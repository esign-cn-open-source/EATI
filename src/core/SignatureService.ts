import * as forge from 'node-forge';
import { SignatureResult } from '../types';
import { KeyManager } from './KeyManager';
import { CertificateManager } from './CertificateManager';
import { DeviceFingerprint } from './DeviceFingerprint';
import { Logger, ModuleLogger } from './Logger';

/**
 * 签名服务模块
 * 提供数据签名和验签功能
 */
export class SignatureService {
    private readonly keyManager: KeyManager;
    private readonly certManager: CertificateManager;
    private readonly fingerprint: DeviceFingerprint;
    private readonly log: ModuleLogger;

    constructor(
        keyManager: KeyManager,
        certManager: CertificateManager,
        logger?: Logger
    ) {
        this.keyManager = keyManager;
        this.certManager = certManager;
        this.log = (logger || Logger.getInstance()).createModuleLogger('SignatureService');
        this.fingerprint = new DeviceFingerprint(logger);
    }

    /**
     * 对数据进行签名
     * @param data 待签名的数据
     * @param verifyDevice 是否验证设备绑定，默认 true
     */
    public sign(data: string | Buffer, verifyDevice: boolean = true): SignatureResult {
        this.log.info('Signing data...');

        // 验证设备绑定（防止私钥滥用）
        if (verifyDevice && !this.verifyDeviceBinding()) {
            this.log.error('Device binding verification failed');
            throw new Error('Device binding verification failed. The certificate is not bound to this device.');
        }

        const privateKey = this.keyManager.getPrivateKey();
        const agentId = this.certManager.getAgentId();
        const timestamp = Date.now();

        // 创建签名
        const signature = this.createSignature(data, privateKey);

        this.log.info(`Data signed successfully, agentId: ${agentId}`);
        this.log.debug(`Signature length: ${signature.length}`);

        return {
            signature,
            agentId,
            timestamp,
            algorithm: 'RSA-SHA256'
        };
    }

    /**
     * 验证设备绑定
     */
    private verifyDeviceBinding(): boolean {
        return this.certManager.verifyDeviceBinding();
    }

    /**
     * 创建数字签名
     */
    private createSignature(data: string | Buffer, privateKey: forge.pki.rsa.PrivateKey): string {
        const md = forge.md.sha256.create();

        if (typeof data === 'string') {
            md.update(data, 'utf8');
        } else {
            md.update(data.toString('binary'));
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const signature = (privateKey as any).sign(md);
        return forge.util.encode64(signature);
    }

    /**
     * 验证签名
     * @param data 原始数据
     * @param signature Base64 编码的签名
     * @param publicKey 可选的公钥，如不提供则使用证书中的公钥
     */
    public verify(
        data: string | Buffer,
        signature: string,
        publicKey?: forge.pki.rsa.PublicKey
    ): boolean {
        this.log.info('Verifying signature...');
        try {
            const key = publicKey || (this.certManager.getPublicKey() as forge.pki.rsa.PublicKey);
            const signatureBytes = forge.util.decode64(signature);

            const md = forge.md.sha256.create();
            if (typeof data === 'string') {
                md.update(data, 'utf8');
            } else {
                md.update(data.toString('binary'));
            }

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const valid = (key as any).verify(md.digest().bytes(), signatureBytes);
            this.log.info(`Signature verification result: ${valid}`);
            return valid;
        } catch (e) {
            this.log.warn('Signature verification failed:', e);
            return false;
        }
    }

    /**
     * 对 JSON 对象进行签名
     * 将对象序列化为规范化的 JSON 字符串后签名
     */
    public signJSON(obj: object, verifyDevice: boolean = true): SignatureResult {
        this.log.debug('Signing JSON object...');
        // 规范化 JSON（排序 key）以确保一致的签名
        const canonicalJson = JSON.stringify(obj, Object.keys(obj).sort());
        return this.sign(canonicalJson, verifyDevice);
    }

    /**
     * 验证 JSON 对象的签名
     */
    public verifyJSON(obj: object, signature: string, publicKey?: forge.pki.rsa.PublicKey): boolean {
        this.log.debug('Verifying JSON signature...');
        const canonicalJson = JSON.stringify(obj, Object.keys(obj).sort());
        return this.verify(canonicalJson, signature, publicKey);
    }

    /**
     * 创建带签名的完整响应
     * 适用于 Agent Hook 场景
     */
    public createSignedResponse<T extends object>(
        content: T,
        verifyDevice: boolean = true
    ): T & { _signature: SignatureResult } {
        this.log.debug('Creating signed response...');
        const signatureResult = this.signJSON(content, verifyDevice);

        return {
            ...content,
            _signature: signatureResult
        };
    }
}

