import { CSRGenerator } from '../src/core/CSRGenerator';
import { KeyManager } from '../src/core/KeyManager';
import { DeviceFingerprint } from '../src/core/DeviceFingerprint';
import { CSRSubject } from '../src/types';
import * as forge from 'node-forge';

describe('CSRGenerator', () => {
    let csrGenerator: CSRGenerator;
    let keyManager: KeyManager;

    // 创建测试用 CSRSubject 的辅助函数
    const createTestSubject = (overrides: Partial<CSRSubject> = {}): CSRSubject => ({
        agentId: 'test-agent-001',
        guardianId: 'guardian-001',
        aeidString: '0123456789abcdef0123456789abcdef',
        frameworkType: 'langchain',
        purpose: 'assistant',
        ...overrides
    });

    beforeEach(() => {
        csrGenerator = new CSRGenerator();
        keyManager = new KeyManager({ keySize: 2048 });
        keyManager.generateKeyPair();
    });

    describe('createCSR', () => {
        it('should create a valid CSR with required subject fields', () => {
            const subject = createTestSubject();

            const { csr, aeid } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            expect(csr).toContain('-----BEGIN CERTIFICATE REQUEST-----');
            expect(csr).toContain('-----END CERTIFICATE REQUEST-----');
            expect(aeid).toBeDefined();
        });

        it('should include all subject fields in CSR CN', () => {
            const subject = createTestSubject();

            const { csr } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            // Parse the CSR
            const parsedCsr = forge.pki.certificationRequestFromPem(csr);
            const attrs = parsedCsr.subject.attributes;

            // CN 应该是拼接的格式: AgentID,GuardianID,AEID,FrameworkType,Purpose
            const cn = attrs.find(a => a.name === 'commonName')?.value as string;
            expect(cn).toContain('test-agent-001');
            expect(cn).toContain('guardian-001');
            expect(cn).toContain('langchain');
            expect(cn).toContain('assistant');
        });

        it('should put AEID hash in CN third field', () => {
            const subject = createTestSubject();

            const { csr } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            const parsed = csrGenerator.parseCSR(csr);
            expect(parsed.subject.aeidString).toMatch(/^[a-f0-9]{32}$/);
            expect(parsed.aeid).toBeNull();
        });

        it('should use provided AEID hash', () => {
            const subject = createTestSubject();
            const customHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

            const { csr } = csrGenerator.createCSR(
                { ...subject, aeidString: customHash },
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            const parsed = csrGenerator.parseCSR(csr);
            expect(parsed.subject.aeidString).toBe(customHash);
        });

        it('should auto-generate AEID hash when subject hash is empty', () => {
            const subject = createTestSubject({ aeidString: '' });

            const { csr } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            const parsed = csrGenerator.parseCSR(csr);
            expect(parsed.subject.aeidString).toMatch(/^[a-f0-9]{32}$/);
        });

        it('should reject invalid AEID hash format', () => {
            const subject = createTestSubject({ aeidString: 'not-hex-hash' });

            expect(() => csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            )).toThrow('Invalid AEID hash format');
        });

        it('should reject CSR when CN length exceeds 100', () => {
            const fp = new DeviceFingerprint();
            const longSubject = createTestSubject({
                agentId: 'agent-name-very-very-long-1234567890',
                guardianId: 'guardian-id-very-very-long-1234567890',
                aeidString: fp.generateAEIDHash(),
                frameworkType: 'custom',
                purpose: 'assistant'
            });

            expect(() => csrGenerator.createCSR(
                longSubject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            )).toThrow('CSR CN length exceeds 100');
        });
    });

    describe('verifyCSR', () => {
        it('should verify valid CSR signature', () => {
            const subject = createTestSubject();

            const { csr } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            const isValid = csrGenerator.verifyCSR(csr);
            expect(isValid).toBe(true);
        });

        it('should fail verification for invalid CSR', () => {
            const invalidCsr = '-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----';

            const isValid = csrGenerator.verifyCSR(invalidCsr);
            expect(isValid).toBe(false);
        });
    });

    describe('parseCSR', () => {
        it('should parse CSR and extract subject', () => {
            const subject = createTestSubject();

            const { csr } = csrGenerator.createCSR(
                subject,
                keyManager.getPublicKey(),
                keyManager.getPrivateKey()
            );

            const parsed = csrGenerator.parseCSR(csr);

            // 验证解析的字段
            expect(parsed.subject.agentId).toBe('test-agent-001');
            expect(parsed.subject.guardianId).toBe('guardian-001');
            expect(parsed.subject.frameworkType).toBe('langchain');
            expect(parsed.subject.purpose).toBe('assistant');
        });
    });
});
