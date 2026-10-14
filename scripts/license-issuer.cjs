const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline/promises');
const { licensePayload, verifyLicense } = require('../src/license');
const root = path.resolve(__dirname, '..');
const privatePath = path.join(root, '.local', 'license-issuer', 'private-key.pem');
const publicPath = path.join(root, 'src', 'license-public-key.pem');

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--init') {
    if (fs.existsSync(privatePath) || fs.existsSync(publicPath)) throw new Error('密钥已存在，拒绝覆盖；更换密钥会使原授权失效。');
    const pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.mkdirSync(path.dirname(privatePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(privatePath, pair.privateKey, { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(publicPath, pair.publicKey, { flag: 'wx' });
    console.log('签发密钥已初始化。私钥仅位于 .local/license-issuer/private-key.pem，请单独备份。');
    return;
  }
  let machine;
  if (args.length === 2 && args[0] === '--machine') machine = args[1];
  else if (args.length === 0) {
    const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
    try { machine = await terminal.question('请输入用户机器码：'); }
    finally { terminal.close(); }
  } else throw new Error('用法：npm run license:issue -- --machine 用户机器码');
  machine = machine.trim().toUpperCase();
  const payload = licensePayload(machine);
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privatePath));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('签发密钥类型错误');
  const signature = crypto.sign(null, payload, privateKey);
  const code = 'TK1.' + payload.toString('base64url') + '.' + signature.toString('base64url');
  // 发放前用客户端公钥自检，避免备份恢复了不匹配的私钥。
  if (!verifyLicense(code, machine, fs.readFileSync(publicPath)).ok) throw new Error('私钥与客户端公钥不匹配，停止签发。');
  const directory = path.join(root, '.local', 'issued-licenses');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const output = path.join(directory, machine + '.txt');
  fs.writeFileSync(output, code + '\n', { mode: 0o600 });
  console.log('永久授权，绑定机器码：' + machine);
  console.log('授权文件：' + output);
  console.log('发送给用户的授权码：\n' + code);
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
