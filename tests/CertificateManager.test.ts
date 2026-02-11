import { CertificateManager } from '../src/core/CertificateManager';
import { KeyManager } from '../src/core/KeyManager';
import { CSRGenerator } from '../src/core/CSRGenerator';
import { DeviceFingerprint } from '../src/core/DeviceFingerprint';
import * as forge from 'node-forge';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('CertificateManager', () => {
    let certManager: CertificateManager;
    let keyManager: KeyManager;
    let csrGenerator: CSRGenerator;
    let testStorePath: string;

    // 创建自签名测试证书
    const createTestCertificate = (cn: string): string => {
        // 生成密钥对
        const keys = forge.pki.rsa.generateKeyPair(2048);

        // 创建证书
        const cert = forge.pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

        const attrs = [{ name: 'commonName', value: cn }];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        // 自签名
        cert.sign(keys.privateKey, forge.md.sha256.create());

        return forge.pki.certificateToPem(cert);
    };

    beforeEach(() => {
        // 创建临时测试目录
        testStorePath = path.join(os.tmpdir(), `esign-test-${Date.now()}`);
        fs.mkdirSync(testStorePath, { recursive: true });

        certManager = new CertificateManager({ certStorePath: testStorePath });
        keyManager = new KeyManager({ certStorePath: testStorePath, keySize: 2048 });
        csrGenerator = new CSRGenerator();
    });

    afterEach(() => {
        // 清理测试目录
        if (fs.existsSync(testStorePath)) {
            const files = fs.readdirSync(testStorePath);
            for (const file of files) {
                fs.unlinkSync(path.join(testStorePath, file));
            }
            fs.rmdirSync(testStorePath);
        }
    });

    describe('importCertificate', () => {
        it('should import certificate from PEM string', () => {
            const cn = 'test-agent|guardian-001|test-aeid|langchain|assistant';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getCertificatePem()).toBe(certPem);
        });

        it('should load certificate from file', () => {
            const cn = 'test-agent|guardian-001|test-aeid|langchain|assistant';
            const certPem = createTestCertificate(cn);
            const certPath = path.join(testStorePath, 'test.crt');
            fs.writeFileSync(certPath, certPem);

            certManager.loadCertificateFromFile(certPath);

            expect(certManager.getCertificatePem()).toBe(certPem);
        });
    });

    describe('getAgentId', () => {
        it('should extract AgentId from CN with pipe-separated format', () => {
            const cn = 'my-agent|guardian-001|aeid-value|langchain|assistant';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAgentId()).toBe('my-agent');
        });

        it('should return entire CN if no pipe present', () => {
            const cn = 'simple-agent-name';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAgentId()).toBe('simple-agent-name');
        });

        it('should throw error if no certificate loaded', () => {
            expect(() => certManager.getAgentId()).toThrow('No certificate loaded.');
        });
    });

    describe('getAEIDFromCN', () => {
        it('should extract AEID from third segment of CN (index 2)', () => {
            // CN 格式: AgentID|GuardianID|AEID|FrameworkType|Purpose
            const cn = 'agent-001|guardian-001|my-aeid-value|langchain|assistant';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            const aeid = certManager.getAEIDFromCN();
            expect(aeid).toBe('my-aeid-value');
        });

        it('should return correct AEID not GuardianID (regression test)', () => {
            // 这是一个回归测试，确保不会返回第二段 (guardianId) 而是返回第三段 (aeid)
            const cn = 'agent|wrong-guardian|correct-aeid|framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            const aeid = certManager.getAEIDFromCN();
            expect(aeid).not.toBe('wrong-guardian');  // 确保不是返回 GuardianID
            expect(aeid).toBe('correct-aeid');        // 确保返回正确的 AEID
        });

        it('should return null if CN has less than 3 segments', () => {
            const cn = 'agent|guardian';  // 只有2段
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAEIDFromCN()).toBeNull();
        });

        it('should return null if no certificate loaded', () => {
            expect(certManager.getAEIDFromCN()).toBeNull();
        });

        it('should return null if CN has no pipe', () => {
            const cn = 'simple-cn-without-pipe';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAEIDFromCN()).toBeNull();
        });

        it('should handle AEID with special characters', () => {
            const cn = 'agent|guardian|aeid+with/special=chars|framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAEIDFromCN()).toBe('aeid+with/special=chars');
        });

        it('should trim whitespace from AEID', () => {
            const cn = 'agent|guardian|  spaced-aeid  |framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAEIDFromCN()).toBe('spaced-aeid');
        });

        it('should return null when AEID segment is empty', () => {
            const cn = 'agent|guardian||framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.getAEIDFromCN()).toBeNull();
        });
    });

    describe('saveCertificate and loadCertificate', () => {
        it('should save and load certificate', () => {
            const cn = 'test-agent|guardian|aeid|framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);
            const savedPath = certManager.saveCertificate('test-agent');

            expect(fs.existsSync(savedPath)).toBe(true);

            // 创建新的管理器加载证书
            const newManager = new CertificateManager({ certStorePath: testStorePath });
            const loaded = newManager.loadCertificate('test-agent');

            expect(loaded).toBe(true);
            expect(newManager.getAgentId()).toBe('test-agent');
        });

        it('should return false if certificate not found', () => {
            const loaded = certManager.loadCertificate('non-existent-agent');
            expect(loaded).toBe(false);
        });

        it('should throw error if no certificate to save', () => {
            expect(() => certManager.saveCertificate('test')).toThrow('No certificate to save');
        });
    });

    describe('isCertificateValid', () => {
        it('should return true for valid certificate', () => {
            const cn = 'test-agent';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            expect(certManager.isCertificateValid()).toBe(true);
        });

        it('should return false if no certificate loaded', () => {
            expect(certManager.isCertificateValid()).toBe(false);
        });
    });

    describe('getSubject', () => {
        it('should return subject attributes', () => {
            const cn = 'test-agent|guardian|aeid|framework|purpose';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            const subject = certManager.getSubject();
            expect(subject['commonName']).toBe(cn);
        });

        it('should throw error if no certificate loaded', () => {
            expect(() => certManager.getSubject()).toThrow('No certificate loaded.');
        });
    });

    describe('getValidity', () => {
        it('should return certificate validity dates', () => {
            const cn = 'test-agent';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);

            const validity = certManager.getValidity();
            expect(validity.notBefore).toBeInstanceOf(Date);
            expect(validity.notAfter).toBeInstanceOf(Date);
            expect(validity.notAfter.getTime()).toBeGreaterThan(validity.notBefore.getTime());
        });
    });

    describe('listCertificates', () => {
        it('should list saved certificates', () => {
            const cn1 = 'agent-1|guardian|aeid|framework|purpose';
            const cn2 = 'agent-2|guardian|aeid|framework|purpose';

            certManager.importCertificate(createTestCertificate(cn1));
            certManager.saveCertificate('agent-1');

            certManager.importCertificate(createTestCertificate(cn2));
            certManager.saveCertificate('agent-2');

            const certs = certManager.listCertificates();
            expect(certs).toContain('agent-1');
            expect(certs).toContain('agent-2');
        });
    });

    describe('deleteCertificate', () => {
        it('should delete saved certificate', () => {
            const cn = 'test-agent';
            const certPem = createTestCertificate(cn);

            certManager.importCertificate(certPem);
            certManager.saveCertificate('test-agent');

            const deleted = certManager.deleteCertificate('test-agent');
            expect(deleted).toBe(true);

            const loaded = certManager.loadCertificate('test-agent');
            expect(loaded).toBe(false);
        });

        it('should return false if certificate not found', () => {
            const deleted = certManager.deleteCertificate('non-existent');
            expect(deleted).toBe(false);
        });
    });

    describe('verifyDeviceBinding', () => {
        it('should verify when AEID hash in CN matches current device', () => {
            const fingerprint = new DeviceFingerprint();
            const aeidHash = fingerprint.generateAEIDHash();
            const cn = `agent-001|guardian-001|${aeidHash}|custom|assistant`;

            certManager.importCertificate(createTestCertificate(cn));

            expect(certManager.verifyDeviceBinding()).toBe(true);
        });

        it('should fail when AEID hash format is invalid', () => {
            const cn = 'agent-001|guardian-001|invalid-hash|custom|assistant';

            certManager.importCertificate(createTestCertificate(cn));

            expect(certManager.verifyDeviceBinding()).toBe(false);
        });

        it('should fail when AEID hash in CN does not match current device', () => {
            const fingerprint = new DeviceFingerprint();
            const fakeHash = fingerprint.computeAEIDHash({
                macAddress: 'ff:ff:ff:ff:ff:ff',
                deviceId: 'fake-device-id',
                ipFingerprint: 'fake-ip'
            });
            const cn = `agent-001,guardian-001,${fakeHash},custom,assistant`;

            certManager.importCertificate(createTestCertificate(cn));

            expect(certManager.verifyDeviceBinding()).toBe(false);
        });
    });
});
