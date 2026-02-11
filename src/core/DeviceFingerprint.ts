import * as os from 'os';
import * as crypto from 'crypto';
import { AEID } from '../types';
import { Logger, ModuleLogger } from './Logger';

/**
 * 设备指纹采集模块
 * 生成和验证 AEID (Agent Entity ID)
 */
export class DeviceFingerprint {
    private readonly log: ModuleLogger;
    private readonly AEID_HASH_REGEX = /^[a-f0-9]{32}$/;

    constructor(logger?: Logger) {
        this.log = (logger || Logger.getInstance()).createModuleLogger('DeviceFingerprint');
    }

    /**
     * 获取主网络接口的 MAC 地址
     */
    private getMacAddress(): string {
        const interfaces = os.networkInterfaces();

        for (const [name, nets] of Object.entries(interfaces)) {
            // 跳过虚拟接口
            if (name.startsWith('lo') || name.startsWith('docker') || name.startsWith('veth')) {
                continue;
            }

            if (nets) {
                for (const net of nets) {
                    // 跳过内部接口和无 MAC 地址的接口
                    if (!net.internal && net.mac && net.mac !== '00:00:00:00:00:00') {
                        return net.mac;
                    }
                }
            }
        }

        // 如果没有找到有效的 MAC 地址，返回一个基于 hostname 的 hash
        return crypto.createHash('sha256')
            .update(os.hostname())
            .digest('hex')
            .substring(0, 17)
            .replace(/(.{2})(?=.)/g, '$1:');
    }

    /**
     * 获取设备唯一标识
     * 基于 hostname、platform、arch 和 CPU 信息生成
     */
    private getDeviceId(): string {
        const info = [
            os.hostname(),
            os.platform(),
            os.arch(),
            os.cpus()[0]?.model || 'unknown-cpu',
            os.totalmem().toString()
        ].join('|');

        return crypto.createHash('sha256')
            .update(info)
            .digest('hex')
            .substring(0, 32);
    }

    /**
     * 生成 IP 指纹
     * 基于所有网络接口的 IP 地址生成
     */
    private getIpFingerprint(): string {
        const interfaces = os.networkInterfaces();
        const ips: string[] = [];

        for (const nets of Object.values(interfaces)) {
            if (nets) {
                for (const net of nets) {
                    if (!net.internal) {
                        ips.push(net.address);
                    }
                }
            }
        }

        // 对 IP 排序后生成 hash，确保一致性
        ips.sort();
        return crypto.createHash('sha256')
            .update(ips.join(','))
            .digest('hex')
            .substring(0, 16);
    }

    /**
     * 生成完整的 AEID
     * 返回的 AEID 在同一设备上是确定性的，用于私钥使用时的绑定校验
     */
    public generateAEID(): AEID {
        this.log.info('Generating device fingerprint (AEID)...');

        const aeid = {
            macAddress: this.getMacAddress(),
            deviceId: this.getDeviceId(),
            ipFingerprint: this.getIpFingerprint()
        };

        this.log.debug('AEID generated:', {
            macAddress: aeid.macAddress.substring(0, 8) + '...',
            deviceId: aeid.deviceId.substring(0, 8) + '...'
        });

        return aeid;
    }

    /**
     * 验证 AEID 是否匹配当前设备
     * @param aeid 待验证的 AEID
     * @param strictMode 严格模式，要求 MAC 和设备 ID 都匹配
     */
    public verifyAEID(aeid: AEID, strictMode: boolean = false): boolean {
        this.log.debug('Verifying AEID...', { strictMode });

        const currentMac = this.getMacAddress();
        const currentDeviceId = this.getDeviceId();

        // 必须验证 MAC 地址
        if (aeid.macAddress !== currentMac) {
            this.log.warn('AEID verification failed: MAC address mismatch');
            return false;
        }

        // 严格模式下还要验证设备 ID
        if (strictMode && aeid.deviceId !== currentDeviceId) {
            this.log.warn('AEID verification failed: Device ID mismatch');
            return false;
        }

        this.log.debug('AEID verification passed');
        return true;
    }

    /**
     * 计算 AEID 哈希（hex，不使用 base64）
     * - 使用 MD5 算法，输出 16 字节（32 个十六进制字符，128 bit）
     * - 无需截取，完整输出
     */
    public computeAEIDHash(aeid: AEID): string {
        const normalizedMac = aeid.macAddress.trim().toLowerCase().replace(/[:-]/g, '');
        const normalizedDeviceId = aeid.deviceId.trim().toLowerCase();
        const canonical = `v1|mac=${normalizedMac}|did=${normalizedDeviceId}`;

        return crypto.createHash('md5')
            .update(canonical, 'utf8')
            .digest('hex');
    }

    /**
     * 生成当前设备 AEID 的哈希
     */
    public generateAEIDHash(aeid?: AEID): string {
        const source = aeid || this.generateAEID();
        const hash = this.computeAEIDHash(source);
        this.log.debug('AEID hash generated:', `${hash.slice(0, 8)}...`);
        return hash;
    }

    /**
     * 验证 AEID 哈希是否匹配当前设备
     */
    public verifyAEIDHash(expectedHash: string): boolean {
        if (!this.AEID_HASH_REGEX.test(expectedHash)) {
            this.log.warn('AEID hash format invalid');
            return false;
        }

        const currentHash = this.generateAEIDHash();
        const expectedBuffer = Buffer.from(expectedHash, 'utf8');
        const currentBuffer = Buffer.from(currentHash, 'utf8');

        if (expectedBuffer.length !== currentBuffer.length) {
            return false;
        }

        const matched = crypto.timingSafeEqual(expectedBuffer, currentBuffer);
        this.log.debug(`AEID hash verification result: ${matched}`);
        return matched;
    }

    /**
     * 判断字符串是否为合法 AEID hash
     */
    public isValidAEIDHashFormat(value: string): boolean {
        return this.AEID_HASH_REGEX.test(value);
    }
}
