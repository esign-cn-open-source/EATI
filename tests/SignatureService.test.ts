import { SignatureService } from '../src/core/SignatureService';
import { KeyManager } from '../src/core/KeyManager';
import { CertificateManager } from '../src/core/CertificateManager';
import { DeviceFingerprint } from '../src/core/DeviceFingerprint';
import * as forge from 'node-forge';

// Create a self-signed certificate for testing
function createTestCertificate(keyManager: KeyManager): string {
    keyManager.generateKeyPair();
    const fingerprint = new DeviceFingerprint();
    const aeidHash = fingerprint.generateAEIDHash();

    const cert = forge.pki.createCertificate();
    cert.publicKey = keyManager.getPublicKey();
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{ name: 'commonName', value: `Test Agent|guardian|${aeidHash}|custom|assistant` }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.sign(keyManager.getPrivateKey(), forge.md.sha256.create());

    return forge.pki.certificateToPem(cert);
}

describe('SignatureService', () => {
    let signatureService: SignatureService;
    let keyManager: KeyManager;
    let certManager: CertificateManager;

    beforeEach(() => {
        keyManager = new KeyManager({ keySize: 2048 });
        certManager = new CertificateManager();

        // Create and import test certificate
        const certPem = createTestCertificate(keyManager);
        certManager.importCertificate(certPem);

        signatureService = new SignatureService(keyManager, certManager);
    });

    describe('sign', () => {
        it('should sign with device verification enabled by default', () => {
            const data = 'Hello, secure world!';
            const result = signatureService.sign(data);

            expect(result.signature).toBeDefined();
            expect(result.agentId).toBe('Test Agent');
        });

        it('should sign string data', () => {
            const data = 'Hello, World!';
            const result = signatureService.sign(data, false);

            expect(result.signature).toBeDefined();
            expect(result.signature.length).toBeGreaterThan(0);
            expect(result.agentId).toBe('Test Agent');
            expect(result.algorithm).toBe('RSA-SHA256');
            expect(result.timestamp).toBeGreaterThan(0);
        });

        it('should sign Buffer data', () => {
            const data = Buffer.from('Binary data');
            const result = signatureService.sign(data, false);

            expect(result.signature).toBeDefined();
        });

        it('should produce different signatures for different data', () => {
            const result1 = signatureService.sign('data1', false);
            const result2 = signatureService.sign('data2', false);

            expect(result1.signature).not.toBe(result2.signature);
        });

        it('should produce same signature for same data', () => {
            const data = 'Same data';
            const result1 = signatureService.sign(data, false);
            const result2 = signatureService.sign(data, false);

            expect(result1.signature).toBe(result2.signature);
        });
    });

    describe('verify', () => {
        it('should verify valid signature', () => {
            const data = 'Test data for signing';
            const result = signatureService.sign(data, false);

            const isValid = signatureService.verify(data, result.signature);
            expect(isValid).toBe(true);
        });

        it('should fail verification for modified data', () => {
            const data = 'Original data';
            const result = signatureService.sign(data, false);

            const isValid = signatureService.verify('Modified data', result.signature);
            expect(isValid).toBe(false);
        });

        it('should fail verification for invalid signature', () => {
            const data = 'Test data';
            const invalidSignature = 'aW52YWxpZA=='; // "invalid" in base64

            const isValid = signatureService.verify(data, invalidSignature);
            expect(isValid).toBe(false);
        });
    });

    describe('signJSON', () => {
        it('should sign JSON object', () => {
            const obj = { key: 'value', number: 123 };
            const result = signatureService.signJSON(obj, false);

            expect(result.signature).toBeDefined();
        });

        it('should produce consistent signature regardless of key order', () => {
            const obj1 = { b: 2, a: 1 };
            const obj2 = { a: 1, b: 2 };

            const result1 = signatureService.signJSON(obj1, false);
            const result2 = signatureService.signJSON(obj2, false);

            expect(result1.signature).toBe(result2.signature);
        });
    });

    describe('verifyJSON', () => {
        it('should verify JSON signature', () => {
            const obj = { message: 'Hello', count: 42 };
            const result = signatureService.signJSON(obj, false);

            const isValid = signatureService.verifyJSON(obj, result.signature);
            expect(isValid).toBe(true);
        });

        it('should fail for modified JSON', () => {
            const obj = { message: 'Hello' };
            const result = signatureService.signJSON(obj, false);

            const modifiedObj = { message: 'Modified' };
            const isValid = signatureService.verifyJSON(modifiedObj, result.signature);
            expect(isValid).toBe(false);
        });
    });

    describe('createSignedResponse', () => {
        it('should create response with embedded signature', () => {
            const content = { title: 'Post', body: 'Content' };
            const response = signatureService.createSignedResponse(content, false);

            expect(response.title).toBe('Post');
            expect(response.body).toBe('Content');
            expect(response._signature).toBeDefined();
            expect(response._signature.signature).toBeDefined();
            expect(response._signature.agentId).toBe('Test Agent');
        });

        it('should allow verification of signed response', () => {
            const content = { action: 'submit', data: 123 };
            const response = signatureService.createSignedResponse(content, false);

            // Extract original content and verify
            const { _signature, ...originalContent } = response;
            const isValid = signatureService.verifyJSON(originalContent, _signature.signature);
            expect(isValid).toBe(true);
        });
    });
});
