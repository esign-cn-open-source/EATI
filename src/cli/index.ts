#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import { EsignAgentTrust } from '../index';

const program = new Command();

program
    .name('esign-agent-trust')
    .description('AI Agent 身份认证与数字签名 SDK')
    .version('1.0.0');

/**
 * 初始化命令 - 生成密钥对和 CSR
 */
program
    .command('init <agentName>')
    .description('初始化 Agent，生成密钥对和 CSR')
    .action(async (agentName) => {
        try {
            console.log(chalk.blue('🔐 正在初始化 Agent...'));

            const sdk = new EsignAgentTrust();

            // 使用 initAgent 方法（包含去重检查）
            const result = await sdk.initAgent(agentName);

            console.log(chalk.green('✅ 初始化成功！'));
            console.log('');
            console.log(chalk.yellow('🆔 Agent Name:'), result.agentName);
            console.log(chalk.yellow('📄 CSR 文件路径:'), result.csrPath);
            console.log(chalk.yellow('🔑 公钥文件路径:'), result.publicKeyPath);
            console.log('');
            console.log(chalk.cyan('📝 下一步:'));
            console.log('   1. 将 CSR 文件提交到平台获取证书');
            console.log('   2. 收到证书后运行: esign-agent-trust import <agentName> <证书路径>');
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
            console.error(chalk.red('❌ 初始化失败:'), errorMessage);
            process.exit(1);
        }
    });

/**
 * 导入证书命令
 */
program
    .command('import <agentName> <certPath>')
    .description('导入平台签发的证书，验证 AgentName 一致性')
    .action(async (agentName, certPath) => {
        try {
            console.log(chalk.blue('📥 正在导入证书...'));

            if (!fs.existsSync(certPath)) {
                throw new Error(`证书文件不存在: ${certPath}`);
            }

            const sdk = new EsignAgentTrust();
            const result = await sdk.importAgentCertificate(agentName, certPath);

            console.log(chalk.green('✅ 证书导入成功！'));
            console.log('');
            console.log(chalk.yellow('🆔 Agent Name:'), result.agentName);
            console.log(chalk.yellow('📄 证书路径:'), result.certificatePath);
        } catch (error) {
            console.error(chalk.red('❌ 导入失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 签名命令
 */
program
    .command('sign <agentId>')
    .description('对数据进行签名')
    .option('-d, --data <data>', '待签名的数据')
    .option('-f, --file <file>', '待签名的文件')
    .action(async (agentId, options) => {
        try {
            if (!options.data && !options.file) {
                throw new Error('请指定 --data 或 --file 参数');
            }

            const sdk = new EsignAgentTrust();
            const loaded = await sdk.load(agentId);

            if (!loaded) {
                throw new Error(`Agent 不存在或凭证未找到: ${agentId}`);
            }

            let data: string;
            if (options.file) {
                console.log(chalk.blue(`📄 读取文件: ${options.file}`));
                data = fs.readFileSync(options.file, 'utf-8');
                console.log(chalk.blue(`📏 文件字符数量: ${data.length}`));
                console.log(chalk.blue(`📝 文件内容:`));
                console.log(data);
            } else {
                data = options.data;
            }

            const result = sdk.sign(data);

            console.log(chalk.green('✅ 签名成功！'));
            console.log('');
            console.log(JSON.stringify(result, null, 2));
        } catch (error) {
            console.error(chalk.red('❌ 签名失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 查看信息命令
 */
program
    .command('info <agentId>')
    .description('查看 Agent 信息')
    .action(async (agentId) => {
        try {
            const sdk = new EsignAgentTrust();
            const loaded = await sdk.load(agentId);

            if (!loaded) {
                throw new Error(`Agent 不存在或凭证未找到: ${agentId}`);
            }

            const credentials = sdk.getCredentials();
            const info = sdk.getCertificateInfo();

            console.log(chalk.blue('📋 Agent 信息'));
            console.log('');
            console.log(chalk.yellow('🆔 Agent ID:'), info.agentId);
            console.log(chalk.yellow('📋 主题:'), JSON.stringify(info.subject));
            console.log(chalk.yellow('📅 有效期:'),
                `${info.validity.notBefore.toISOString()} - ${info.validity.notAfter.toISOString()}`);
            console.log('');
            console.log(chalk.yellow('🔑 公钥:'));
            console.log(credentials.publicKey);
            console.log(chalk.yellow('📜 证书:'));
            console.log(credentials.certificate);
        } catch (error) {
            console.error(chalk.red('❌ 获取信息失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 列出所有 Agent
 */
program
    .command('list')
    .description('列出所有已注册的 Agent')
    .action(async () => {
        try {
            const sdk = new EsignAgentTrust();
            const agents = await sdk.listAgents();

            if (agents.length === 0) {
                console.log(chalk.yellow('📭 暂无已注册的 Agent'));
                console.log('运行 esign-agent-trust init 来初始化一个新的 Agent');
                return;
            }

            console.log(chalk.blue('📋 已注册的 Agent 列表:'));
            console.log('');
            agents.forEach((agentId, index) => {
                console.log(`  ${index + 1}. ${agentId}`);
            });
        } catch (error) {
            console.error(chalk.red('❌ 获取列表失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 导出凭证命令
 */
program
    .command('export <agentId>')
    .description('导出 Agent 凭证（公钥 + 证书 + AgentID）')
    .option('-o, --output <file>', '输出文件路径')
    .action(async (agentId, options) => {
        try {
            const sdk = new EsignAgentTrust();
            const loaded = await sdk.load(agentId);

            if (!loaded) {
                throw new Error(`Agent 不存在或凭证未找到: ${agentId}`);
            }

            const credentials = sdk.getCredentials();
            const output = JSON.stringify(credentials, null, 2);

            if (options.output) {
                fs.writeFileSync(options.output, output);
                console.log(chalk.green('✅ 凭证已导出到:'), options.output);
            } else {
                console.log(output);
            }
        } catch (error) {
            console.error(chalk.red('❌ 导出失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 删除 Agent 命令
 */
program
    .command('remove <agentName>')
    .description('删除指定的 Agent（包括私钥、证书和相关文件）')
    .action(async (agentName) => {
        try {
            console.log(chalk.blue('🗑️ 正在删除 Agent...'));

            const sdk = new EsignAgentTrust();
            const result = await sdk.removeAgent(agentName);

            console.log(chalk.green('✅ 删除成功！'));
            console.log('');
            console.log(chalk.yellow('🆔 已删除 Agent:'), result.agentName);
        } catch (error) {
            console.error(chalk.red('❌ 删除失败:'), (error as Error).message);
            process.exit(1);
        }
    });

/**
 * 验签命令
 */
program
    .command('verify <agentName> <content> <signature>')
    .description('验证签名，验证指定 Agent 对内容的签名是否有效')
    .action(async (agentName, content, signature) => {
        try {
            console.log(chalk.blue('🔍 正在验证签名...'));

            const sdk = new EsignAgentTrust();
            const loaded = await sdk.load(agentName);

            if (!loaded) {
                throw new Error(`Agent "${agentName}" 不存在或凭证未找到`);
            }

            const isValid = sdk.verify(content, signature);

            console.log('');
            if (isValid) {
                console.log(chalk.green('✅ 签名验证通过！'));
                console.log('');
                console.log(chalk.yellow('🆔 Agent Name:'), agentName);
                console.log(chalk.yellow('📝 原文:'), content.length > 50 ? content.substring(0, 50) + '...' : content);
                console.log(chalk.yellow('🔏 签名:'), signature.substring(0, 50) + '...');
            } else {
                console.log(chalk.red('❌ 签名验证失败！'));
                console.log('');
                console.log(chalk.yellow('可能的原因:'));
                console.log('  1. 原文内容与签名时不一致');
                console.log('  2. 签名已被篡改');
                console.log('  3. Agent 不匹配');
            }

            process.exit(isValid ? 0 : 1);
        } catch (error) {
            console.error(chalk.red('❌ 验签失败:'), (error as Error).message);
            process.exit(1);
        }
    });

program.parse();
