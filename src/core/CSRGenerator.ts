import * as forge from 'node-forge';
import { AEID, CSRSubject } from '../types';
import { DeviceFingerprint } from './DeviceFingerprint';
import { Logger, ModuleLogger } from './Logger';

/**
 * CSR 生成模块
 * 创建包含 AEID hash 信息的证书签名请求
 */
export class CSRGenerator {
    private readonly fingerprint: DeviceFingerprint;
    private readonly log: ModuleLogger;
    private readonly MAX_CN_LENGTH = 100;

    constructor(logger?: Logger) {
        this.fingerprint = new DeviceFingerprint(logger);
        this.log = (logger || Logger.getInstance()).createModuleLogger('CSRGenerator');
    }

    /**
     * 创建 CSR
     * @param subject CSR 主题信息
     * @param publicKey 公钥
     * @param privateKey 私钥（用于签名 CSR）
     * @param aeid 可选的 AEID，如不提供则自动生成
     */
    public createCSR(
        subject: CSRSubject,
        publicKey: forge.pki.rsa.PublicKey,
        privateKey: forge.pki.rsa.PrivateKey,
        aeid?: AEID
    ): { csr: string; aeid: AEID } {
        this.log.info(`Creating CSR for agent: ${subject.agentId}`);

        // 如果没有提供 AEID，则生成一个
        const deviceAeid = aeid || this.fingerprint.generateAEID();

        // AEID 字段保存 hash（hex），优先使用 subject 传入值，否则自动计算
        const aeidHash = subject.aeidString || this.fingerprint.generateAEIDHash(deviceAeid);
        if (!this.fingerprint.isValidAEIDHashFormat(aeidHash)) {
            throw new Error('Invalid AEID hash format. Expected 32-char hex string.');
        }

        // 创建 CSR
        const csr = forge.pki.createCertificationRequest();

        // 设置公钥
        csr.publicKey = publicKey;

        // 拼接 CN 字段: AgentID,GuardianID,AEID,FrameworkType,Purpose
        const commonName = [
            subject.agentId,
            subject.guardianId,
            aeidHash,
            subject.frameworkType,
            subject.purpose
        ].join('|');

        this.ensureCommonNameLength(commonName, subject, aeidHash);

        this.log.debug('CSR CommonName:', commonName.substring(0, 80) + '...');

        // 设置主题 (只包含 CN)
        const subjectAttrs: forge.pki.CertificateField[] = [
            { name: 'commonName', value: commonName }
        ];

        csr.setSubject(subjectAttrs);

        // 使用私钥签名 CSR
        csr.sign(privateKey, forge.md.sha256.create());
        this.log.info('CSR signed with SHA256');

        // 转换为 PEM 格式
        const csrPem = forge.pki.certificationRequestToPem(csr);

        this.log.info('CSR created successfully');
        return {
            csr: csrPem,
            aeid: deviceAeid
        };
    }

    /**
     * 解析 CSR 并提取 AEID
     * CN 字段格式: AgentID|GuardianID|AEID|FrameworkType|Purpose
     */
    public parseCSR(csrPem: string): { subject: CSRSubject; aeid: AEID | null } {
        this.log.debug('Parsing CSR...');
        const csr = forge.pki.certificationRequestFromPem(csrPem);

        // 提取主题，使用默认值初始化
        const subject: CSRSubject = {
            agentId: '',
            guardianId: '',
            aeidString: '',
            frameworkType: 'custom',
            purpose: 'assistant'
        };

        for (const attr of csr.subject.attributes) {
            switch (attr.name) {
                case 'commonName': {
                    // 解析 CN 字段: AgentID|GuardianID|AEID|FrameworkType|Purpose
                    const cn = attr.value as string;
                    const parts = cn.split('|');
                    if (parts.length >= 5) {
                        subject.agentId = parts[0];
                        subject.guardianId = parts[1];
                        subject.aeidString = parts[2];
                        subject.frameworkType = parts[3];
                        subject.purpose = parts[4];
                    }
                    break;
                }
            }
        }

        this.log.debug(`CSR parsed, agentId: ${subject.agentId}`);
        return { subject, aeid: null };
    }

    /**
     * 验证 CSR 签名
     */
    public verifyCSR(csrPem: string): boolean {
        this.log.debug('Verifying CSR signature...');
        try {
            const csr = forge.pki.certificationRequestFromPem(csrPem);
            const valid = csr.verify();
            this.log.debug(`CSR signature valid: ${valid}`);
            return valid;
        } catch (e) {
            this.log.warn('CSR verification failed:', e);
            return false;
        }
    }

    private ensureCommonNameLength(commonName: string, subject: CSRSubject, aeidHash: string): void {
        if (commonName.length <= this.MAX_CN_LENGTH) {
            return;
        }

        throw new Error(
            `CSR CN length exceeds ${this.MAX_CN_LENGTH}. ` +
            `Current=${commonName.length}, ` +
            `agentId=${subject.agentId.length}, guardianId=${subject.guardianId.length}, ` +
            `aeidHash=${aeidHash.length}, frameworkType=${String(subject.frameworkType).length}, ` +
            `purpose=${String(subject.purpose).length}`
        );
    }
}
