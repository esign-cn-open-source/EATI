import * as forge from 'node-forge';
import * as keytar from 'keytar';
import { EsignAgentConfig } from '../types';
import { Logger, ModuleLogger } from './Logger';

/**
 * 密钥管理模块
 * 负责 RSA 密钥对的生成、存储和加载
 * 私钥存储在系统 Keystore 中
 */
export class KeyManager {
    private readonly keystoreService: string;
    private readonly keySize: number;
    private publicKey: forge.pki.rsa.PublicKey | null = null;
    private privateKey: forge.pki.rsa.PrivateKey | null = null;
    private readonly log: ModuleLogger;

    constructor(config: EsignAgentConfig = {}, logger?: Logger) {
        this.keystoreService = config.keystoreService || 'esign-agent-trust';
        this.keySize = config.keySize || 2048;
        this.log = (logger || Logger.getInstance()).createModuleLogger('KeyManager');
    }

    /**
     * 生成 RSA 密钥对
     */
    public generateKeyPair(): { publicKey: string; privateKey: string } {
        this.log.info(`Generating RSA key pair (${this.keySize} bits)...`);
        const keypair = forge.pki.rsa.generateKeyPair({ bits: this.keySize });

        this.publicKey = keypair.publicKey;
        this.privateKey = keypair.privateKey;

        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

        this.log.info('RSA key pair generated successfully');
        this.log.debug('Public key fingerprint:', publicKeyPem.substring(0, 50) + '...');

        return {
            publicKey: publicKeyPem,
            privateKey: privateKeyPem
        };
    }

    /**
     * 保存私钥到系统 Keystore
     * @param agentId Agent 标识，作为 Keystore 账户名
     */
    public async savePrivateKey(agentId: string): Promise<void> {
        if (!this.privateKey) {
            throw new Error('No private key to save. Generate key pair first.');
        }

        this.log.info(`Saving private key to Keystore for agent: ${agentId}`);
        const privateKeyPem = forge.pki.privateKeyToPem(this.privateKey);

        await keytar.setPassword(this.keystoreService, agentId, privateKeyPem);
        this.log.info('Private key saved to Keystore successfully');
    }

    /**
     * 从 Keystore 加载私钥
     * @param agentId Agent 标识
     */
    public async loadPrivateKey(agentId: string): Promise<forge.pki.rsa.PrivateKey> {
        this.log.info(`Loading private key from Keystore for agent: ${agentId}`);
        const privateKeyPem = await keytar.getPassword(this.keystoreService, agentId);

        if (!privateKeyPem) {
            this.log.error(`Private key not found for agent: ${agentId}`);
            throw new Error(`Private key not found for agent: ${agentId}`);
        }

        this.privateKey = forge.pki.privateKeyFromPem(privateKeyPem) as forge.pki.rsa.PrivateKey;
        this.log.info('Private key loaded successfully');
        return this.privateKey;
    }

    /**
     * 检查 Keystore 中是否存在私钥
     */
    public async hasPrivateKey(agentId: string): Promise<boolean> {
        this.log.debug(`Checking if private key exists for agent: ${agentId}`);
        const password = await keytar.getPassword(this.keystoreService, agentId);
        const exists = password !== null;
        this.log.debug(`Private key exists: ${exists}`);
        return exists;
    }

    /**
     * 从 Keystore 删除私钥
     */
    public async deletePrivateKey(agentId: string): Promise<boolean> {
        this.log.info(`Deleting private key for agent: ${agentId}`);
        const result = await keytar.deletePassword(this.keystoreService, agentId);
        this.log.info(`Private key deleted: ${result}`);
        return result;
    }

    /**
     * 获取公钥 PEM
     */
    public getPublicKeyPem(): string {
        if (!this.publicKey) {
            throw new Error('No public key available. Generate or load key pair first.');
        }
        return forge.pki.publicKeyToPem(this.publicKey);
    }

    /**
     * 获取 forge 格式的私钥对象
     */
    public getPrivateKey(): forge.pki.rsa.PrivateKey {
        if (!this.privateKey) {
            throw new Error('No private key available. Generate or load key pair first.');
        }
        return this.privateKey;
    }

    /**
     * 获取 forge 格式的公钥对象
     */
    public getPublicKey(): forge.pki.rsa.PublicKey {
        if (!this.publicKey) {
            throw new Error('No public key available. Generate or load key pair first.');
        }
        return this.publicKey;
    }

    /**
     * 从 PEM 字符串加载公钥
     */
    public loadPublicKeyFromPem(pem: string): void {
        this.log.debug('Loading public key from PEM string');
        this.publicKey = forge.pki.publicKeyFromPem(pem);
    }

    /**
     * 从私钥派生公钥
     */
    public derivePublicKey(): void {
        if (!this.privateKey) {
            throw new Error('No private key available to derive public key.');
        }
        this.log.debug('Deriving public key from private key');
        // 通过私钥的 n 和 e 参数创建公钥
        this.publicKey = forge.pki.rsa.setPublicKey(
            this.privateKey.n,
            this.privateKey.e
        );
    }

    /**
     * 列出该服务下所有已存储的 Agent ID
     */
    public async listStoredAgents(): Promise<string[]> {
        this.log.debug('Listing all stored agents');
        const credentials = await keytar.findCredentials(this.keystoreService);
        const agents = credentials.map(cred => cred.account);
        this.log.debug(`Found ${agents.length} agents`);
        return agents;
    }
}

