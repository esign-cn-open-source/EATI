// SDK 核心接口类型定义

/**
 * 设备指纹信息 (Agent Entity ID)
 * 作为私钥使用时的绑定校验因子，所有字段必须在同一设备上保持稳定
 */
export interface AEID {
    /** MAC 地址 */
    macAddress: string;
    /** 设备唯一标识 */
    deviceId: string;
    /** IP 指纹 */
    ipFingerprint: string;
}

/**
 * SDK 配置选项
 */
export interface EsignAgentConfig {
    /** Keystore 服务名称，默认 'esign-agent-trust' */
    keystoreService?: string;
    /** 证书存储目录，默认 ~/.esign-agent/ */
    certStorePath?: string;
    /** RSA 密钥长度，固定 2048 位 */
    keySize?: 2048;
}

/**
 * Agent 框架类型
 */
export type AgentFrameworkType =
    | 'langchain'
    | 'autogen'
    | 'crewai'
    | 'dify'
    | 'coze'
    | 'custom'
    | string;

/**
 * Agent 用途类型
 */
export type AgentPurposeType =
    | 'assistant'      // 通用助手
    | 'coder'          // 编程助手
    | 'data-analyst'   // 数据分析
    | 'customer-service' // 客服
    | 'content-creator'  // 内容创作
    | 'automation'     // 自动化任务
    | string;

/**
 * CSR 主题信息
 * CN 字段格式: AgentID|GuardianID|AEID|FrameworkType|Purpose
 */
export interface CSRSubject {
    /** Agent 唯一标识 */
    agentId: string;
    /** 监护人/所有者 ID */
    guardianId: string;
    /** AEID hash（48 位小写 hex，不使用 base64） */
    aeidString: string;
    /** Agent 框架类型 */
    frameworkType: AgentFrameworkType;
    /** Agent 用途 */
    purpose: AgentPurposeType;
}

/**
 * 签名结果
 */
export interface SignatureResult {
    /** Base64 编码的签名 */
    signature: string;
    /** Agent ID (证书序列号) */
    agentId: string;
    /** 签名时间戳 */
    timestamp: number;
    /** 签名算法 */
    algorithm: string;
}

/**
 * Agent 凭证信息
 */
export interface AgentCredentials {
    /** PEM 格式公钥 */
    publicKey: string;
    /** PEM 格式证书 */
    certificate: string;
    /** Agent ID */
    agentId: string;
}

/**
 * SDK 初始化结果
 */
export interface InitResult {
    /** CSR 文件路径 */
    csrPath: string;
    /** 公钥 PEM */
    publicKey: string;
    /** AEID 信息 */
    aeid: AEID;
}

/**
 * initAgent 接口结果
 */
export interface InitAgentResult {
    /** CSR 文件路径 */
    csrPath: string;
    /** 公钥文件路径 */
    publicKeyPath: string;
    /** Agent 名称 */
    agentName: string;
}

/**
 * importAgentCertificate 接口结果
 */
export interface ImportAgentResult {
    /** Agent 名称 */
    agentName: string;
    /** 证书文件路径 */
    certificatePath: string;
}

/**
 * signByAgent 接口结果
 */
export interface SignAgentResult {
    /** Base64 编码的签名 */
    signature: string;
    /** Agent 名称 */
    agentName: string;
    /** 签名时间戳 */
    timestamp: number;
    /** 签名算法 */
    algorithm: 'RSA-SHA256-PKCS1';
}

/**
 * 日志级别枚举
 */
export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    NONE = 4
}

/**
 * 日志配置选项
 */
export interface LogConfig {
    /** 是否启用日志，默认 false */
    enabled?: boolean;
    /** 日志级别，默认 INFO */
    level?: LogLevel;
}
