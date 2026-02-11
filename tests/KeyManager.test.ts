import { KeyManager } from '../src/core/KeyManager';
import * as keytar from 'keytar';

// Mock keytar for testing without actual Keystore access
jest.mock('keytar', () => ({
    setPassword: jest.fn().mockResolvedValue(undefined),
    getPassword: jest.fn().mockResolvedValue(null),
    deletePassword: jest.fn().mockResolvedValue(true),
    findCredentials: jest.fn().mockResolvedValue([])
}));

describe('KeyManager', () => {
    let keyManager: KeyManager;
    const testAgentId = 'test-agent-001';

    beforeEach(() => {
        keyManager = new KeyManager({
            keystoreService: 'test-esign-agent',
            keySize: 2048
        });
        jest.clearAllMocks();
    });

    describe('generateKeyPair', () => {
        it('should generate a valid RSA key pair', () => {
            const { publicKey, privateKey } = keyManager.generateKeyPair();

            expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
            expect(publicKey).toContain('-----END PUBLIC KEY-----');
            expect(privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(privateKey).toContain('-----END RSA PRIVATE KEY-----');
        });

        it('should generate different keys each time', () => {
            const keyManager2 = new KeyManager({ keySize: 2048 });

            const keys1 = keyManager.generateKeyPair();
            const keys2 = keyManager2.generateKeyPair();

            expect(keys1.publicKey).not.toBe(keys2.publicKey);
        });
    });

    describe('savePrivateKey', () => {
        it('should save private key to keystore', async () => {
            keyManager.generateKeyPair();
            await keyManager.savePrivateKey(testAgentId);

            expect(keytar.setPassword).toHaveBeenCalledWith(
                'test-esign-agent',
                testAgentId,
                expect.stringContaining('-----BEGIN RSA PRIVATE KEY-----')
            );
        });

        it('should throw error if no key generated', async () => {
            await expect(keyManager.savePrivateKey(testAgentId))
                .rejects.toThrow('No private key to save');
        });
    });

    describe('loadPrivateKey', () => {
        it('should load private key from keystore', async () => {
            // First generate and save
            const { privateKey } = keyManager.generateKeyPair();
            (keytar.getPassword as jest.Mock).mockResolvedValueOnce(privateKey);

            const loadedKey = await keyManager.loadPrivateKey(testAgentId);

            expect(loadedKey).toBeDefined();
            expect(keytar.getPassword).toHaveBeenCalledWith(
                'test-esign-agent',
                testAgentId
            );
        });

        it('should throw error if key not found', async () => {
            (keytar.getPassword as jest.Mock).mockResolvedValueOnce(null);

            await expect(keyManager.loadPrivateKey(testAgentId))
                .rejects.toThrow('Private key not found');
        });
    });

    describe('hasPrivateKey', () => {
        it('should return true if key exists', async () => {
            (keytar.getPassword as jest.Mock).mockResolvedValueOnce('some-key-data');

            const exists = await keyManager.hasPrivateKey(testAgentId);
            expect(exists).toBe(true);
        });

        it('should return false if key not exists', async () => {
            (keytar.getPassword as jest.Mock).mockResolvedValueOnce(null);

            const exists = await keyManager.hasPrivateKey(testAgentId);
            expect(exists).toBe(false);
        });
    });

    describe('getPublicKeyPem', () => {
        it('should return public key PEM after generation', () => {
            keyManager.generateKeyPair();
            const pem = keyManager.getPublicKeyPem();

            expect(pem).toContain('-----BEGIN PUBLIC KEY-----');
        });

        it('should throw error if no key available', () => {
            expect(() => keyManager.getPublicKeyPem())
                .toThrow('No public key available');
        });
    });

    describe('derivePublicKey', () => {
        it('should derive public key from private key', async () => {
            const { privateKey, publicKey } = keyManager.generateKeyPair();

            // Reset public key by loading from keystore
            const keyManager2 = new KeyManager();
            (keytar.getPassword as jest.Mock).mockResolvedValueOnce(privateKey);
            await keyManager2.loadPrivateKey(testAgentId);

            keyManager2.derivePublicKey();
            const derivedPem = keyManager2.getPublicKeyPem();

            expect(derivedPem).toContain('-----BEGIN PUBLIC KEY-----');
        });
    });

    describe('listStoredAgents', () => {
        it('should list all stored agents', async () => {
            (keytar.findCredentials as jest.Mock).mockResolvedValueOnce([
                { account: 'agent-1', password: 'key1' },
                { account: 'agent-2', password: 'key2' }
            ]);

            const agents = await keyManager.listStoredAgents();

            expect(agents).toEqual(['agent-1', 'agent-2']);
        });
    });
});
