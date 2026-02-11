import { DeviceFingerprint } from '../src/core/DeviceFingerprint';
import { AEID } from '../src/types';

describe('DeviceFingerprint', () => {
    let fingerprint: DeviceFingerprint;

    beforeEach(() => {
        fingerprint = new DeviceFingerprint();
    });

    describe('generateAEID', () => {
        it('should generate a valid AEID', () => {
            const aeid = fingerprint.generateAEID();

            expect(aeid).toBeDefined();
            expect(aeid.macAddress).toBeDefined();
            expect(aeid.deviceId).toBeDefined();
            expect(aeid.ipFingerprint).toBeDefined();
        });

        it('should generate consistent MAC address', () => {
            const aeid1 = fingerprint.generateAEID();
            const aeid2 = fingerprint.generateAEID();

            expect(aeid1.macAddress).toBe(aeid2.macAddress);
        });

        it('should generate consistent device ID', () => {
            const aeid1 = fingerprint.generateAEID();
            const aeid2 = fingerprint.generateAEID();

            expect(aeid1.deviceId).toBe(aeid2.deviceId);
        });
    });

    describe('generateAEIDHash / verifyAEIDHash', () => {
        it('should generate 32-char hex hash (MD5)', () => {
            const hash = fingerprint.generateAEIDHash();
            expect(hash).toMatch(/^[a-f0-9]{32}$/);
            expect(hash.length).toBe(32);
        });

        it('should generate same hash for same AEID', () => {
            const aeid = fingerprint.generateAEID();
            const hash1 = fingerprint.generateAEIDHash(aeid);
            const hash2 = fingerprint.generateAEIDHash(aeid);

            expect(hash1).toBe(hash2);
        });

        it('should verify hash from current device', () => {
            const hash = fingerprint.generateAEIDHash();
            expect(fingerprint.verifyAEIDHash(hash)).toBe(true);
        });

        it('should fail verification for invalid hash format', () => {
            expect(fingerprint.verifyAEIDHash('invalid-hash')).toBe(false);
        });
    });

    describe('verifyAEID', () => {
        it('should verify AEID from same device', () => {
            const aeid = fingerprint.generateAEID();
            const isValid = fingerprint.verifyAEID(aeid);

            expect(isValid).toBe(true);
        });

        it('should fail verification for different MAC address', () => {
            const aeid: AEID = {
                macAddress: 'ff:ff:ff:ff:ff:ff',
                deviceId: 'fake-device-id',
                ipFingerprint: 'fake-ip'
            };

            const isValid = fingerprint.verifyAEID(aeid);
            expect(isValid).toBe(false);
        });

        it('should pass non-strict mode with matching MAC', () => {
            const aeid = fingerprint.generateAEID();
            aeid.deviceId = 'modified-device-id'; // Modify device ID

            const isValid = fingerprint.verifyAEID(aeid, false);
            expect(isValid).toBe(true);
        });

        it('should fail strict mode with different device ID', () => {
            const aeid = fingerprint.generateAEID();
            aeid.deviceId = 'modified-device-id';

            const isValid = fingerprint.verifyAEID(aeid, true);
            expect(isValid).toBe(false);
        });
    });
});
