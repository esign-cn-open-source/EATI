import * as forge from 'node-forge';
import * as fs from 'fs';
import * as path from 'path';
import { EsignAgentConfig } from '../types';
import { DeviceFingerprint } from './DeviceFingerprint';
import { Logger, ModuleLogger } from './Logger';

/**
 * 证书管理模块
 * 负责证书的导入、存储、验证和信息提取
 */
export class CertificateManager {
    private readonly certStorePath: string;
    private readonly fingerprint: DeviceFingerprint;
    private certificate: forge.pki.Certificate | null = null;
    private readonly log: ModuleLogger;
    private readonly AEID_HASH_REGEX = /^[a-f0-9]{32}$/;

    constructor(config: EsignAgentConfig = {}, logger?: Logger) {
        this.certStorePath = config.certStorePath ||
            path.join(process.env.HOME || process.env.USERPROFILE || '.', '.esign-agent');
        this.log = (logger || Logger.getInstance()).createModuleLogger('CertificateManager');
        this.fingerprint = new DeviceFingerprint(logger);
    }

    /**
     * 确保存储目录存在
     */
    private ensureStorePath(): void {
        if (!fs.existsSync(this.certStorePath)) {
            fs.mkdirSync(this.certStorePath, { recursive: true, mode: 0o700 });
        }
    }

    /**
     * 导入证书
     * @param certPem PEM 格式的证书字符串
     */
    public importCertificate(certPem: string): void {
        this.log.info('Importing certificate from PEM string');
        this.certificate = forge.pki.certificateFromPem(certPem);
        this.log.debug('Certificate imported successfully');
    }

    /**
     * 从文件加载证书
     * @param certPath 证书文件路径
     */
    public loadCertificateFromFile(certPath: string): void {
        this.log.info(`Loading certificate from file: ${certPath}`);
        const certPem = fs.readFileSync(certPath, 'utf-8');
        this.importCertificate(certPem);
    }

    /**
     * 保存证书到文件
     * @param agentId Agent ID
     */
    public saveCertificate(agentId: string): string {
        if (!this.certificate) {
            throw new Error('No certificate to save. Import certificate first.');
        }

        this.ensureStorePath();

        const certPath = path.join(this.certStorePath, `${agentId}.pem`);
        const certPem = forge.pki.certificateToPem(this.certificate);

        this.log.info(`Saving certificate for agent: ${agentId}`);
        try {
            fs.writeFileSync(certPath, certPem, { mode: 0o600 });
            this.log.info(`Certificate saved to: ${certPath}`);
        } catch (error) {
            this.log.error('Failed to save certificate:', error);
            throw new Error(`Failed to save certificate: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }

        return certPath;
    }

    /**
     * 加载已保存的证书
     * @param agentId Agent ID
     */
    public loadCertificate(agentId: string): boolean {
        const certPath = path.join(this.certStorePath, `${agentId}.pem`);

        if (!fs.existsSync(certPath)) {
            this.log.debug(`Certificate not found for agent: ${agentId}`);
            return false;
        }

        this.loadCertificateFromFile(certPath);
        return true;
    }

    /**
     * 获取 Agent ID (从CN字段解析)
     * CN 字段格式: AgentName,GuardianID,AEID,FrameworkType,Purpose
     * 或者直接是 AgentName
     */
    public getAgentId(): string {
        if (!this.certificate) {
            throw new Error('No certificate loaded.');
        }

        // 从CN字段解析Agent信息
        const subject = this.certificate.subject.attributes;
        const cnAttr = subject.find(attr => attr.name === 'commonName' || attr.shortName === 'CN');

        if (cnAttr && cnAttr.value) {
            const cnValue = cnAttr.value as string;
            // 如果CN包含竖线，格式为：AgentName|GuardianID|AEID|FrameworkType|Purpose
            if (cnValue.includes('|')) {
                const parts = cnValue.split('|');
                // 第一部分是 AgentName
                return parts[0].trim();
            }
            // 否则整个 CN 就是 AgentName
            return cnValue.trim();
        }

        throw new Error('证书中未找到 CN (CommonName) 字段');
    }

    /**
     * 从CN字段解析AEID信息
     * CN 字段格式: AgentID,GuardianID,AEID_HASH,FrameworkType,Purpose
     */
    public getAEIDFromCN(): string | null {
        if (!this.certificate) {
            return null;
        }

        const subject = this.certificate.subject.attributes;
        const cnAttr = subject.find(attr => attr.name === 'commonName' || attr.shortName === 'CN');

        if (cnAttr && cnAttr.value) {
            const cnValue = cnAttr.value as string;
            if (cnValue.includes('|')) {
                const parts = cnValue.split('|');
                if (parts.length >= 3) {
                    // 第三部分是 AEID hash (索引2): AgentID,GuardianID,AEID_HASH,...
                    const aeidHash = parts[2].trim().toLowerCase();
                    return aeidHash.length > 0 ? aeidHash : null;
                }
            }
        }

        return null;
    }

    /**
     * 验证证书是否有效（时间范围）
     */
    public isCertificateValid(): boolean {
        if (!this.certificate) {
            return false;
        }

        const now = new Date();
        const valid = now >= this.certificate.validity.notBefore &&
            now <= this.certificate.validity.notAfter;

        this.log.debug(`Certificate validity check: ${valid}`);
        return valid;
    }

    /**
     * 验证 AEID 是否匹配当前设备
     */
    public verifyDeviceBinding(): boolean {
        this.log.debug('Verifying device binding...');
        const aeidHash = this.getAEIDFromCN();
        if (!aeidHash) {
            this.log.warn('Device binding verification failed: AEID hash not found in CN');
            return false;
        }

        if (!this.AEID_HASH_REGEX.test(aeidHash)) {
            this.log.warn('Device binding verification failed: invalid AEID hash format');
            return false;
        }

        const result = this.fingerprint.verifyAEIDHash(aeidHash);
        this.log.debug(`Device binding verification result: ${result}`);
        return result;
    }

    /**
     * 获取证书 PEM 格式
     */
    public getCertificatePem(): string {
        if (!this.certificate) {
            throw new Error('No certificate loaded.');
        }
        return forge.pki.certificateToPem(this.certificate);
    }

    /**
     * 获取证书公钥
     */
    public getPublicKey(): forge.pki.PublicKey {
        if (!this.certificate) {
            throw new Error('No certificate loaded.');
        }
        return this.certificate.publicKey as forge.pki.PublicKey;
    }

    /**
     * 获取证书主题信息
     */
    public getSubject(): Record<string, string> {
        if (!this.certificate) {
            throw new Error('No certificate loaded.');
        }

        const subject: Record<string, string> = {};
        for (const attr of this.certificate.subject.attributes) {
            subject[attr.name || attr.shortName || ''] = attr.value as string;
        }
        return subject;
    }

    /**
     * 获取证书有效期
     */
    public getValidity(): { notBefore: Date; notAfter: Date } {
        if (!this.certificate) {
            throw new Error('No certificate loaded.');
        }
        return {
            notBefore: this.certificate.validity.notBefore,
            notAfter: this.certificate.validity.notAfter
        };
    }

    /**
     * 列出存储目录中的所有证书
     */
    public listCertificates(): string[] {
        this.ensureStorePath();

        const files = fs.readdirSync(this.certStorePath);
        return files
            .filter(f => f.endsWith('.pem'))
            .map(f => f.replace('.pem', ''));
    }

    /**
     * 删除证书
     */
    public deleteCertificate(agentId: string): boolean {
        const certPath = path.join(this.certStorePath, `${agentId}.pem`);

        if (fs.existsSync(certPath)) {
            this.log.info(`Deleting certificate for agent: ${agentId}`);
            fs.unlinkSync(certPath);
            return true;
        }
        this.log.debug(`Certificate not found for agent: ${agentId}`);
        return false;
    }
}
