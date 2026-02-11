/**
 * 日志系统模块
 * 提供统一的日志记录功能，支持控制台和文件双输出
 * 支持日志文件轮转：按日期命名、大小限制、数量限制、过期清理
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * 日志级别枚举
 */
export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    NONE = 4  // 关闭所有日志
}

/**
 * 日志轮转配置接口
 */
export interface LogRotationConfig {
    /** 单个日志文件最大大小（字节），默认 1GB */
    maxFileSize?: number;
    /** 每天最多保留的日志文件数，默认 10 */
    maxFilesPerDay?: number;
    /** 日志保留天数，默认 7 天 */
    maxRetentionDays?: number;
}

/**
 * 日志配置接口
 */
export interface LoggerConfig {
    /** 日志级别，默认 INFO */
    level?: LogLevel;
    /** 是否启用日志，默认 false */
    enabled?: boolean;
    /** 日志前缀 */
    prefix?: string;
    /** 是否包含时间戳，默认 true */
    timestamp?: boolean;
    /** 是否输出到控制台，默认 true */
    console?: boolean;
    /** 是否写入文件，默认 true */
    file?: boolean;
    /** 日志文件目录，默认 ~/.esign-agent/logs */
    logDir?: string;
    /** 日志文件基础名，默认 sdk */
    logFileName?: string;
    /** 日志轮转配置 */
    rotation?: LogRotationConfig;
    /** 自定义日志输出函数 */
    output?: (message: string) => void;
}

// 默认常量
const DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024; // 1GB
const DEFAULT_MAX_FILES_PER_DAY = 10;
const DEFAULT_MAX_RETENTION_DAYS = 7;

/**
 * 日志记录器类
 * 支持多级别日志输出、控制台彩色输出和文件写入
 * 支持日志文件轮转
 */
export class Logger {
    private static instance: Logger | null = null;
    private config: Required<Omit<LoggerConfig, 'output' | 'rotation'>> & {
        output?: (message: string) => void;
        rotation: Required<LogRotationConfig>;
    };
    private logFilePath: string | null = null;
    private writeStream: fs.WriteStream | null = null;
    private currentFileSize: number = 0;
    private currentDate: string = '';
    private currentFileIndex: number = 0;

    private readonly levelNames: Record<LogLevel, string> = {
        [LogLevel.DEBUG]: 'DEBUG',
        [LogLevel.INFO]: 'INFO',
        [LogLevel.WARN]: 'WARN',
        [LogLevel.ERROR]: 'ERROR',
        [LogLevel.NONE]: 'NONE'
    };

    private readonly levelColors: Record<LogLevel, string> = {
        [LogLevel.DEBUG]: '\x1b[36m',  // cyan
        [LogLevel.INFO]: '\x1b[32m',   // green
        [LogLevel.WARN]: '\x1b[33m',   // yellow
        [LogLevel.ERROR]: '\x1b[31m',  // red
        [LogLevel.NONE]: ''
    };

    private readonly resetColor = '\x1b[0m';

    constructor(config: LoggerConfig = {}) {
        const defaultLogDir = path.join(
            process.env.HOME || process.env.USERPROFILE || '.',
            '.esign-agent',
            'logs'
        );

        this.config = {
            level: config.level ?? LogLevel.INFO,
            enabled: config.enabled ?? false,
            prefix: config.prefix ?? 'esign-agent-trust',
            timestamp: config.timestamp ?? true,
            console: config.console ?? true,
            file: config.file ?? true,
            logDir: config.logDir ?? defaultLogDir,
            logFileName: config.logFileName ?? 'sdk',
            output: config.output,
            rotation: {
                maxFileSize: config.rotation?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
                maxFilesPerDay: config.rotation?.maxFilesPerDay ?? DEFAULT_MAX_FILES_PER_DAY,
                maxRetentionDays: config.rotation?.maxRetentionDays ?? DEFAULT_MAX_RETENTION_DAYS
            }
        };

        // 初始化文件日志
        if (this.config.file && this.config.enabled) {
            this.initFileLogging();
        }
    }

    /**
     * 获取当前日期字符串 (YYYY-MM-DD)
     */
    private getDateString(): string {
        const now = new Date();
        return now.toISOString().split('T')[0];
    }

    /**
     * 生成日志文件名
     * 格式: {baseName}-{date}-{index}.log
     * 例如: sdk-2024-01-15-0.log
     */
    private generateLogFileName(date: string, index: number): string {
        return `${this.config.logFileName}-${date}-${index}.log`;
    }

    /**
     * 解析日志文件名，提取日期和序号
     */
    private parseLogFileName(fileName: string): { date: string; index: number } | null {
        const baseName = this.config.logFileName;
        const regex = new RegExp(`^${baseName}-(\\d{4}-\\d{2}-\\d{2})-(\\d+)\\.log$`);
        const match = fileName.match(regex);
        if (match) {
            return {
                date: match[1],
                index: parseInt(match[2], 10)
            };
        }
        return null;
    }

    /**
     * 查找当天最新的日志文件序号
     */
    private findLatestFileIndex(date: string): number {
        try {
            if (!fs.existsSync(this.config.logDir)) {
                return 0;
            }

            const files = fs.readdirSync(this.config.logDir);
            let maxIndex = -1;

            for (const file of files) {
                const parsed = this.parseLogFileName(file);
                if (parsed && parsed.date === date) {
                    maxIndex = Math.max(maxIndex, parsed.index);
                }
            }

            return maxIndex + 1;
        } catch {
            return 0;
        }
    }

    /**
     * 初始化文件日志
     */
    private initFileLogging(): void {
        try {
            // 确保日志目录存在
            if (!fs.existsSync(this.config.logDir)) {
                fs.mkdirSync(this.config.logDir, { recursive: true, mode: 0o700 });
            }

            // 清理过期日志
            this.cleanExpiredLogs();

            // 设置当前日期和文件序号
            this.currentDate = this.getDateString();
            this.currentFileIndex = this.findLatestFileIndex(this.currentDate);

            // 检查是否超过每日文件数限制
            if (this.currentFileIndex >= this.config.rotation.maxFilesPerDay) {
                console.warn(`已达到每日日志文件数上限 (${this.config.rotation.maxFilesPerDay})，新日志将覆盖最后一个文件`);
                this.currentFileIndex = this.config.rotation.maxFilesPerDay - 1;
            }

            this.openLogFile();
        } catch (error) {
            console.error(`Failed to initialize file logging: ${error}`);
            this.config.file = false;
        }
    }

    /**
     * 打开日志文件
     */
    private openLogFile(): void {
        const fileName = this.generateLogFileName(this.currentDate, this.currentFileIndex);
        this.logFilePath = path.join(this.config.logDir, fileName);

        // 获取现有文件大小
        try {
            if (fs.existsSync(this.logFilePath)) {
                const stats = fs.statSync(this.logFilePath);
                this.currentFileSize = stats.size;
            } else {
                this.currentFileSize = 0;
            }
        } catch {
            this.currentFileSize = 0;
        }

        // 创建写入流（追加模式）
        this.writeStream = fs.createWriteStream(this.logFilePath, {
            flags: 'a',
            encoding: 'utf8'
        });
    }

    /**
     * 关闭当前日志文件
     */
    private closeLogFile(): void {
        if (this.writeStream) {
            this.writeStream.end();
            this.writeStream = null;
        }
    }

    /**
     * 轮转到下一个日志文件
     */
    private rotateLogFile(): void {
        this.closeLogFile();

        const today = this.getDateString();

        // 检查是否跨天
        if (today !== this.currentDate) {
            this.currentDate = today;
            this.currentFileIndex = 0;
            // 跨天时清理过期日志
            this.cleanExpiredLogs();
        } else {
            this.currentFileIndex++;
        }

        // 检查是否超过每日文件数限制
        if (this.currentFileIndex >= this.config.rotation.maxFilesPerDay) {
            console.warn(`已达到每日日志文件数上限 (${this.config.rotation.maxFilesPerDay})，新日志将覆盖最后一个文件`);
            this.currentFileIndex = this.config.rotation.maxFilesPerDay - 1;
            // 删除现有文件以便重新写入
            const fileName = this.generateLogFileName(this.currentDate, this.currentFileIndex);
            const filePath = path.join(this.config.logDir, fileName);
            try {
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            } catch (e) {
                console.error(`Failed to delete log file for rotation: ${e}`);
            }
        }

        this.openLogFile();
    }

    /**
     * 检查是否需要轮转日志文件
     */
    private checkRotation(): void {
        const today = this.getDateString();

        // 跨天轮转
        if (today !== this.currentDate) {
            this.rotateLogFile();
            return;
        }

        // 大小轮转
        if (this.currentFileSize >= this.config.rotation.maxFileSize) {
            this.rotateLogFile();
        }
    }

    /**
     * 清理过期日志文件
     */
    private cleanExpiredLogs(): void {
        try {
            if (!fs.existsSync(this.config.logDir)) {
                return;
            }

            const files = fs.readdirSync(this.config.logDir);
            const now = new Date();
            const cutoffDate = new Date(now.getTime() - this.config.rotation.maxRetentionDays * 24 * 60 * 60 * 1000);
            const cutoffDateStr = cutoffDate.toISOString().split('T')[0];

            for (const file of files) {
                const parsed = this.parseLogFileName(file);
                if (parsed && parsed.date < cutoffDateStr) {
                    const filePath = path.join(this.config.logDir, file);
                    try {
                        fs.unlinkSync(filePath);
                    } catch (e) {
                        console.error(`Failed to delete expired log file ${file}: ${e}`);
                    }
                }
            }
        } catch (error) {
            console.error(`Failed to clean expired logs: ${error}`);
        }
    }

    /**
     * 获取全局单例实例
     */
    public static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    /**
     * 配置全局日志实例
     */
    public static configure(config: LoggerConfig): void {
        Logger.instance = new Logger(config);
    }

    /**
     * 启用日志
     */
    public enable(): void {
        this.config.enabled = true;
        if (this.config.file && !this.writeStream) {
            this.initFileLogging();
        }
    }

    /**
     * 禁用日志
     */
    public disable(): void {
        this.config.enabled = false;
    }

    /**
     * 设置日志级别
     */
    public setLevel(level: LogLevel): void {
        this.config.level = level;
    }

    /**
     * 检查是否启用
     */
    public isEnabled(): boolean {
        return this.config.enabled;
    }

    /**
     * 获取日志文件路径
     */
    public getLogFilePath(): string | null {
        return this.logFilePath;
    }

    /**
     * DEBUG 级别日志
     */
    public debug(message: string, ...args: unknown[]): void {
        this.log(LogLevel.DEBUG, message, ...args);
    }

    /**
     * INFO 级别日志
     */
    public info(message: string, ...args: unknown[]): void {
        this.log(LogLevel.INFO, message, ...args);
    }

    /**
     * WARN 级别日志
     */
    public warn(message: string, ...args: unknown[]): void {
        this.log(LogLevel.WARN, message, ...args);
    }

    /**
     * ERROR 级别日志
     */
    public error(message: string, ...args: unknown[]): void {
        this.log(LogLevel.ERROR, message, ...args);
    }

    /**
     * 核心日志输出方法
     */
    private log(level: LogLevel, message: string, ...args: unknown[]): void {
        if (!this.config.enabled || level < this.config.level) {
            return;
        }

        const formattedMessage = this.formatMessage(level, message, args);

        if (this.config.output) {
            this.config.output(formattedMessage);
        } else {
            // 输出到控制台
            if (this.config.console) {
                this.consoleOutput(level, formattedMessage);
            }

            // 写入文件
            if (this.config.file) {
                this.fileOutput(formattedMessage);
            }
        }
    }

    /**
     * 格式化日志消息
     */
    private formatMessage(level: LogLevel, message: string, args: unknown[]): string {
        const parts: string[] = [];

        // 时间戳
        if (this.config.timestamp) {
            parts.push(`[${new Date().toISOString()}]`);
        }

        // 前缀
        if (this.config.prefix) {
            parts.push(`[${this.config.prefix}]`);
        }

        // 级别
        parts.push(`[${this.levelNames[level]}]`);

        // 消息
        parts.push(message);

        // 附加参数
        if (args.length > 0) {
            const argsStr = args.map(arg => {
                if (typeof arg === 'object') {
                    try {
                        return JSON.stringify(arg);
                    } catch {
                        return String(arg);
                    }
                }
                return String(arg);
            }).join(' ');
            parts.push(argsStr);
        }

        return parts.join(' ');
    }

    /**
     * 控制台输出（带颜色）
     */
    private consoleOutput(level: LogLevel, message: string): void {
        const color = this.levelColors[level];
        const coloredMessage = `${color}${message}${this.resetColor}`;

        switch (level) {
            case LogLevel.ERROR:
                console.error(coloredMessage);
                break;
            case LogLevel.WARN:
                console.warn(coloredMessage);
                break;
            default:
                console.log(coloredMessage);
        }
    }

    /**
     * 文件输出
     */
    private fileOutput(message: string): void {
        if (!this.writeStream) {
            return;
        }

        // 检查是否需要轮转
        this.checkRotation();

        const logLine = message + '\n';
        const lineBytes = Buffer.byteLength(logLine, 'utf8');

        this.writeStream.write(logLine);
        this.currentFileSize += lineBytes;
    }

    /**
     * 关闭日志（清理资源）
     */
    public close(): void {
        if (this.writeStream) {
            this.writeStream.end();
            this.writeStream = null;
        }
    }

    /**
     * 创建带模块名的子日志器
     */
    public createModuleLogger(moduleName: string): ModuleLogger {
        return new ModuleLogger(this, moduleName);
    }
}

/**
 * 模块日志器
 * 为特定模块提供带模块名前缀的日志功能
 */
export class ModuleLogger {
    private readonly logger: Logger;
    private readonly moduleName: string;

    constructor(logger: Logger, moduleName: string) {
        this.logger = logger;
        this.moduleName = moduleName;
    }

    private prefix(message: string): string {
        return `[${this.moduleName}] ${message}`;
    }

    public debug(message: string, ...args: unknown[]): void {
        this.logger.debug(this.prefix(message), ...args);
    }

    public info(message: string, ...args: unknown[]): void {
        this.logger.info(this.prefix(message), ...args);
    }

    public warn(message: string, ...args: unknown[]): void {
        this.logger.warn(this.prefix(message), ...args);
    }

    public error(message: string, ...args: unknown[]): void {
        this.logger.error(this.prefix(message), ...args);
    }
}

