import * as fs from 'fs';
import * as path from 'path';
import {
    EsignAgentConfig,
    CSRSubject,
    SignatureResult,
    AgentCredentials,
    InitResult,
    InitAgentResult,
    ImportAgentResult,
    SignAgentResult,
    AEID,
    LogLevel,
    LogConfig
} from './types';
import { DeviceFingerprint } from './core/DeviceFingerprint';
import { KeyManager } from './core/KeyManager';
import { CSRGenerator } from './core/CSRGenerator';
import { CertificateManager } from './core/CertificateManager';
import { SignatureService } from './core/SignatureService';
import { Logger } from './core/Logger';

/**
 * SDK 配置（包含日志配置）
 */
export interface EsignAgentTrustConfig extends EsignAgentConfig {
    /** 日志配置 */
    log?: LogConfig;
}

/**
 * esignAgentTrust SDK 主类
 * 提供 AI Agent 身份认证和数字签名功能
 */
export class EsignAgentTrust {
    private readonly config: Required<EsignAgentConfig>;
    private readonly fingerprint: DeviceFingerprint;
    private readonly keyManager: KeyManager;
    private readonly csrGenerator: CSRGenerator;
    private readonly certManager: CertificateManager;
    private signatureService: SignatureService | null = null;
    private readonly logger: Logger;

    private currentAgentId: string | null = null;
    private currentAEID: AEID | null = null;
    private initialized: boolean = false;

    constructor(config: EsignAgentTrustConfig = {}) {
        // 初始化日志
        this.logger = new Logger({
            enabled: config.log?.enabled ?? true,
            level: config.log?.level ?? LogLevel.INFO,
            prefix: 'esign-agent-trust'
        });

        const log = this.logger.createModuleLogger('EsignAgentTrust');
        log.info('Initializing SDK...');

        this.config = {
            keystoreService: config.keystoreService || 'esign-agent-trust',
            certStorePath: config.certStorePath ||
                path.join(process.env.HOME || process.env.USERPROFILE || '.', '.esign-agent'),
            keySize: config.keySize || 2048
        };

        // 将 logger 传递给各个模块
        this.fingerprint = new DeviceFingerprint(this.logger);
        this.keyManager = new KeyManager(this.config, this.logger);
        this.csrGenerator = new CSRGenerator(this.logger);
        this.certManager = new CertificateManager(this.config, this.logger);

        log.info('SDK initialized successfully');
    }

    /**
     * 启用日志
     */
    public enableLogging(): void {
        this.logger.enable();
    }

    /**
     * 禁用日志
     */
    public disableLogging(): void {
        this.logger.disable();
    }

    /**
     * 设置日志级别
     */
    public setLogLevel(level: LogLevel): void {
        this.logger.setLevel(level);
    }

    /**
     * 初始化 SDK，生成密钥对和 CSR
     * @param subject CSR 主题信息
     * @param agentId 可选的 Agent ID，如不提供则自动生成
     * @returns 初始化结果，包含 CSR 路径和公钥
     */
    public async initialize(subject: CSRSubject, agentId?: string): Promise<InitResult> {
        // 生成密钥对
        const { publicKey } = this.keyManager.generateKeyPair();

        // 生成 Agent ID（如果未提供）
        this.currentAgentId = agentId || this.generateAgentId(subject.agentId);

        // 保存私钥到 Keystore
        await this.keyManager.savePrivateKey(this.currentAgentId);

        // 生成 CSR
        const { csr, aeid } = this.csrGenerator.createCSR(
            subject,
            this.keyManager.getPublicKey(),
            this.keyManager.getPrivateKey()
        );

        this.currentAEID = aeid;

        // 保存 CSR 文件
        const csrPath = this.saveCSR(csr, this.currentAgentId);

        // 保存公钥文件
        this.savePublicKey(publicKey, this.currentAgentId);

        return {
            csrPath,
            publicKey,
            aeid
        };
    }

    /**
     * 导入平台签发的证书
     * @param certPath 证书文件路径或 PEM 字符串
     */
    public async importCertificate(certPath: string): Promise<void> {
        // 判断是路径还是 PEM 字符串
        if (certPath.includes('-----BEGIN CERTIFICATE-----')) {
            this.certManager.importCertificate(certPath);
        } else {
            this.certManager.loadCertificateFromFile(certPath);
        }

        // 获取 Agent ID
        let agentId = this.certManager.getAgentId();

        // 检查是否存在对应的私钥
        const hasPrivateKey = await this.keyManager.hasPrivateKey(agentId);

        if (!hasPrivateKey) {
            const storedAgents = await this.keyManager.listStoredAgents();
            throw new Error(
                `未找到 Agent "${agentId}" 的私钥。\n` +
                `请先使用 initAgent("${agentId}") 初始化，或检查证书中的 AgentName 是否正确。\n` +
                `当前已存储的 Agent 列表: ${storedAgents.length > 0 ? storedAgents.join(', ') : '(空)'}`
            );
        }

        this.currentAgentId = agentId;

        // 验证设备绑定
        if (!this.certManager.verifyDeviceBinding()) {
            throw new Error('Certificate device binding verification failed.');
        }

        // 加载对应的私钥
        await this.keyManager.loadPrivateKey(this.currentAgentId);
        this.keyManager.derivePublicKey();

        // 保存证书
        this.certManager.saveCertificate(this.currentAgentId);

        // 初始化签名服务
        this.signatureService = new SignatureService(this.keyManager, this.certManager, this.logger);
        this.initialized = true;
    }

    /**
     * 加载已有的凭证
     * @param agentId Agent ID
     */
    public async load(agentId: string): Promise<boolean> {
        // 检查证书是否存在
        if (!this.certManager.loadCertificate(agentId)) {
            this.logger.error(`证书不存在 Certificate not found for Agent "${agentId}"`);
            return false;
        }

        // 检查私钥是否存在
        if (!await this.keyManager.hasPrivateKey(agentId)) {
            this.logger.error(`私钥不存在 Private key not found for Agent "${agentId}"`);
            return false;
        }

        // 验证设备绑定
        if (!this.certManager.verifyDeviceBinding()) {
            throw new Error('Certificate device binding verification failed.');
        }

        // 加载私钥
        await this.keyManager.loadPrivateKey(agentId);
        this.keyManager.derivePublicKey();

        this.currentAgentId = agentId;
        this.signatureService = new SignatureService(this.keyManager, this.certManager, this.logger);
        this.initialized = true;

        return true;
    }

    /**
     * 对数据进行签名
     * @param data 待签名数据
     */
    public sign(data: string | Buffer): SignatureResult {
        this.ensureInitialized();
        return this.signatureService!.sign(data);
    }

    /**
     * 对 JSON 对象进行签名
     */
    public signJSON(obj: object): SignatureResult {
        this.ensureInitialized();
        return this.signatureService!.signJSON(obj);
    }

    /**
     * 创建带签名的响应
     * 适用于 Agent Hook 场景
     */
    public createSignedResponse<T extends object>(content: T): T & { _signature: SignatureResult } {
        this.ensureInitialized();
        return this.signatureService!.createSignedResponse(content);
    }

    /**
     * 验证签名
     */
    public verify(data: string | Buffer, signature: string): boolean {
        this.ensureInitialized();
        return this.signatureService!.verify(data, signature);
    }

    /**
     * 获取 Agent 凭证信息
     */
    public getCredentials(): AgentCredentials {
        this.ensureInitialized();

        return {
            publicKey: this.keyManager.getPublicKeyPem(),
            certificate: this.certManager.getCertificatePem(),
            agentId: this.currentAgentId!
        };
    }

    /**
     * 获取当前 Agent ID
     */
    public getAgentId(): string | null {
        return this.currentAgentId;
    }

    /**
     * 检查 SDK 是否已完成初始化
     */
    public isInitialized(): boolean {
        return this.initialized;
    }

    /**
     * 获取证书信息
     */
    public getCertificateInfo(): {
        subject: Record<string, string>;
        validity: { notBefore: Date; notAfter: Date };
        agentId: string;
    } {
        this.ensureInitialized();

        return {
            subject: this.certManager.getSubject(),
            validity: this.certManager.getValidity(),
            agentId: this.currentAgentId!
        };
    }

    /**
     * 列出所有已存储的 Agent
     */
    public async listAgents(): Promise<string[]> {
        return this.keyManager.listStoredAgents();
    }

    /**
     * 根据 AgentName 获取公钥
     * @param agentName Agent 名称
     * @returns 公钥 PEM 格式字符串，如果不存在则返回 null
     */
    public async getPublicKey(agentName: string): Promise<string | null> {
        const publicKeyPath = path.join(this.config.certStorePath, `${agentName}.pub`);

        if (fs.existsSync(publicKeyPath)) {
            return fs.readFileSync(publicKeyPath, 'utf-8');
        }

        // 尝试从私钥派生公钥
        const hasKey = await this.keyManager.hasPrivateKey(agentName);
        if (hasKey) {
            await this.keyManager.loadPrivateKey(agentName);
            return this.keyManager.getPublicKeyPem();
        }

        return null;
    }

    /**
     * 根据 AgentName 获取证书
     * @param agentName Agent 名称
     * @returns 证书 PEM 格式字符串，如果不存在则返回 null
     */
    public getCertificate(agentName: string): string | null {
        // 尝试多种可能的证书文件名
        const possiblePaths = [
            path.join(this.config.certStorePath, `${agentName}.crt`),
            path.join(this.config.certStorePath, `${agentName}.cer`),
            path.join(this.config.certStorePath, `${agentName}_cert.pem`)
        ];

        for (const certPath of possiblePaths) {
            if (fs.existsSync(certPath)) {
                return fs.readFileSync(certPath, 'utf-8');
            }
        }

        return null;
    }

    /**
     * 根据 AgentName 获取 CSR
     * @param agentName Agent 名称
     * @returns CSR PEM 格式字符串，如果不存在则返回 null
     */
    public getCSR(agentName: string): string | null {
        const csrPath = path.join(this.config.certStorePath, `${agentName}.pem`);

        if (fs.existsSync(csrPath)) {
            return fs.readFileSync(csrPath, 'utf-8');
        }

        return null;
    }

    /**
     * 根据 AgentName 获取凭证信息
     * @param agentName Agent 名称
     */
    public async getCredentialsByName(agentName: string): Promise<{
        publicKey: string | null;
        certificate: string | null;
        csr: string | null;
        agentName: string;
    }> {
        return {
            publicKey: await this.getPublicKey(agentName),
            certificate: this.getCertificate(agentName),
            csr: this.getCSR(agentName),
            agentName: agentName
        };
    }

    // ========== 新增三个 SDK 接口 ==========

    /**
     * 初始化 Agent（接口 1）
     * 生成 CSR 文件，对 AgentName 进行去重管理
     * @param agentName Agent 名称
     * @returns 初始化结果，包含 CSR 文件路径
     */
    public async initAgent(agentName: string): Promise<InitAgentResult> {
        // 检查 AgentName 是否已存在（去重管理）
        const existingAgents = await this.keyManager.listStoredAgents();
        if (existingAgents.includes(agentName)) {
            throw new Error(`Agent "${agentName}" 已存在，请使用其他名称`);
        }

        // 生成密钥对
        const { publicKey } = this.keyManager.generateKeyPair();

        // 保存私钥到 Keystore
        await this.keyManager.savePrivateKey(agentName);

        // 生成 AEID
        const aeid = this.fingerprint.generateAEID();
        const aeidString = this.fingerprint.generateAEIDHash(aeid);

        // 创建 CSR 主题
        const subject: CSRSubject = {
            agentId: agentName,
            guardianId: '',           // 待平台填充
            aeidString: aeidString,
            frameworkType: 'custom',  // 待平台填充
            purpose: 'assistant'      // 待平台填充
        };

        // 生成 CSR
        const { csr } = this.csrGenerator.createCSR(
            subject,
            this.keyManager.getPublicKey(),
            this.keyManager.getPrivateKey()
        );

        // 保存 CSR 文件
        const csrPath = this.saveCSR(csr, agentName);

        // 保存公钥文件
        const publicKeyPath = this.savePublicKey(publicKey, agentName);

        return {
            csrPath,
            publicKeyPath,
            agentName
        };
    }

    /**
     * 导入 Agent 证书（接口 2）
     * 验证 AgentName 与证书中的 AgentName 是否一致，并绑定私钥
     * @param agentName Agent 名称
     * @param certPath 证书文件路径或 PEM 字符串
     * @returns 导入结果
     */
    public async importAgentCertificate(agentName: string, certPath: string): Promise<ImportAgentResult> {
        // 检查是否存在对应的私钥
        const hasPrivateKey = await this.keyManager.hasPrivateKey(agentName);
        if (!hasPrivateKey) {
            throw new Error(`未找到 Agent "${agentName}" 的私钥，请先使用 initAgent 初始化`);
        }

        // 加载证书
        if (certPath.includes('-----BEGIN CERTIFICATE-----')) {
            this.certManager.importCertificate(certPath);
        } else {
            if (!fs.existsSync(certPath)) {
                throw new Error(`证书文件不存在: ${certPath}`);
            }
            this.certManager.loadCertificateFromFile(certPath);
        }

        // 从证书中提取 AgentName 并验证一致性
        const certAgentName = this.certManager.getAgentId();
        if (certAgentName !== agentName) {
            throw new Error(
                `AgentName 不匹配：输入的是 "${agentName}"，证书中的是 "${certAgentName}"`
            );
        }

        // 验证设备绑定
        if (!this.certManager.verifyDeviceBinding()) {
            throw new Error('证书设备绑定验证失败');
        }

        // 加载私钥
        await this.keyManager.loadPrivateKey(agentName);
        this.keyManager.derivePublicKey();

        // 保存证书
        const certificatePath = this.certManager.saveCertificate(agentName);

        // 初始化签名服务
        this.signatureService = new SignatureService(this.keyManager, this.certManager, this.logger);
        this.currentAgentId = agentName;
        this.initialized = true;

        return {
            agentName,
            certificatePath
        };
    }

    /**
     * 使用指定 Agent 签名内容（接口 3）
     * 使用 RSA PKCS1-SHA256 算法签名
     * @param agentName Agent 名称
     * @param content 待签名内容
     * @returns 签名结果
     */
    public async signByAgent(agentName: string, content: string): Promise<SignAgentResult> {
        const log = this.logger.createModuleLogger('signByAgent');
        log.info(`开始签名, agentName: ${agentName}`);

        // 加载 Agent 凭证
        const loaded = await this.load(agentName);
        if (!loaded) {
            log.error(`Agent "${agentName}" 不存在或凭证未找到`);
            throw new Error(`Agent "${agentName}" 不存在或凭证未找到`);
        }
        log.info(`Agent "${agentName}" 凭证加载成功`);

        // 判断 content 是否为文件路径
        let signContent = content;
        if (fs.existsSync(content)) {
            try {
                const stat = fs.statSync(content);
                if (stat.isFile()) {
                    log.info(`检测到输入为文件路径: ${content}`);
                    log.info(`文件大小: ${stat.size} bytes`);
                    signContent = fs.readFileSync(content, 'utf-8');
                    const charCount = signContent.length;
                    log.info(`文件字符数量: ${charCount}`);
                    log.info(`文件内容: ${signContent}`);
                }
            } catch (e) {
                log.warn(`尝试读取文件失败, 将 content 作为普通字符串处理: ${e}`);
            }
        } else {
            log.info(`输入内容长度: ${content.length}`);
            log.debug(`输入内容: ${content}`);
        }

        // 执行签名
        const signResult = this.sign(signContent);
        log.info(`签名完成, agentId: ${signResult.agentId}, timestamp: ${signResult.timestamp}`);

        return {
            signature: signResult.signature,
            agentName: agentName,
            timestamp: signResult.timestamp,
            algorithm: 'RSA-SHA256-PKCS1'
        };
    }

    /**
     * 删除指定 Agent（接口 4）
     * 删除私钥、证书、CSR 和公钥文件
     * @param agentName Agent 名称
     * @returns 删除结果
     */
    public async removeAgent(agentName: string): Promise<{ agentName: string; removed: boolean }> {
        // 检查 Agent 是否存在
        const existingAgents = await this.keyManager.listStoredAgents();
        if (!existingAgents.includes(agentName)) {
            throw new Error(`Agent "${agentName}" 不存在`);
        }

        // 删除私钥
        await this.keyManager.deletePrivateKey(agentName);

        // 删除证书文件
        this.certManager.deleteCertificate(agentName);

        // 删除 CSR 文件
        const csrPath = path.join(this.config.certStorePath, `${agentName}.pem`);
        if (fs.existsSync(csrPath)) {
            fs.unlinkSync(csrPath);
        }

        // 删除公钥文件
        const pubPath = path.join(this.config.certStorePath, `${agentName}.pub`);
        if (fs.existsSync(pubPath)) {
            fs.unlinkSync(pubPath);
        }

        return {
            agentName,
            removed: true
        };
    }

    // ========== 私有方法 ==========

    private ensureInitialized(): void {
        if (!this.initialized || !this.signatureService) {
            throw new Error('SDK not initialized. Call load() or importCertificate() first.');
        }
    }

    private generateAgentId(commonName: string): string {
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 8);
        const name = commonName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 8);
        return `${name}-${timestamp}-${random}`;
    }

    private saveCSR(csr: string, agentId: string): string {
        const storePath = this.config.certStorePath;
        if (!fs.existsSync(storePath)) {
            fs.mkdirSync(storePath, { recursive: true, mode: 0o700 });
        }

        const csrPath = path.join(storePath, `${agentId}.pem`);
        fs.writeFileSync(csrPath, csr, { mode: 0o600 });
        return csrPath;
    }

    private savePublicKey(publicKey: string, agentId: string): string {
        const storePath = this.config.certStorePath;
        const keyPath = path.join(storePath, `${agentId}.pub`);
        fs.writeFileSync(keyPath, publicKey, { mode: 0o644 });
        return keyPath;
    }
}

// 导出所有类型和模块
export * from './types';
export { DeviceFingerprint } from './core/DeviceFingerprint';
export { KeyManager } from './core/KeyManager';
export { CSRGenerator } from './core/CSRGenerator';
export { CertificateManager } from './core/CertificateManager';
export { SignatureService } from './core/SignatureService';
export { Logger, LogLevel as CoreLogLevel } from './core/Logger';
