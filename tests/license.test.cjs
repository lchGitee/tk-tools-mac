const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { licensePayload, verifyLicense, createLicenseStore } = require('../src/license');
const A = 'A'.repeat(32);
const B = 'B'.repeat(32);
const pair = crypto.generateKeyPairSync('ed25519');
function sign(machine, key = pair.privateKey) {
  const data = licensePayload(machine);
  return 'TK1.' + data.toString('base64url') + '.' + crypto.sign(null, data, key).toString('base64url');
}

test('授权只允许签发的机器，保存后重启和复制文件仍验证签名与机器', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tk-license-'));
  try {
    const filePath = path.join(directory, 'activation.lic');
    const storeA = createLicenseStore({ filePath, getMachineCode: () => A, publicKey: pair.publicKey });
    const storeB = createLicenseStore({ filePath, getMachineCode: () => B, publicKey: pair.publicKey });
    assert.equal(storeA.state().reason, 'not_activated');
    const code = sign(A);
    assert.equal(storeB.activate(code).reason, 'machine_mismatch');
    assert.equal(fs.existsSync(filePath), false);
    assert.equal(storeA.activate(code).ok, true);
    const restarted = createLicenseStore({ filePath, getMachineCode: () => A, publicKey: pair.publicKey });
    assert.equal(restarted.state().ok, true);
    assert.equal(storeB.state().reason, 'machine_mismatch');
    assert.equal(storeB.activate(code).reason, 'machine_mismatch');
    assert.equal(fs.readFileSync(filePath, 'utf8'), code);
    const parts = code.split('.');
    parts[1] = licensePayload(B).toString('base64url');
    fs.writeFileSync(filePath, parts.join('.'));
    assert.equal(storeB.state().reason, 'invalid');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('篡改内容、签名或使用其他私钥，均不能激活', () => {
  const code = sign(A);
  const [prefix, data, signature] = code.split('.');
  assert.equal(verifyLicense([prefix, licensePayload(B).toString('base64url'), signature].join('.'), B, pair.publicKey).reason, 'invalid');
  const badSignature = Buffer.from(signature, 'base64url'); badSignature[0] ^= 1;
  assert.equal(verifyLicense([prefix, data, badSignature.toString('base64url')].join('.'), A, pair.publicKey).reason, 'invalid');
  const other = crypto.generateKeyPairSync('ed25519');
  assert.equal(verifyLicense(sign(A, other.privateKey), A, pair.publicKey).reason, 'invalid');
});

test('旧卡密、旧激活文件和不支持的产品被拒绝', () => {
  assert.equal(verifyLicense('TK-A1B2-C3D4-E5F6', A, pair.publicKey).reason, 'format');
  assert.equal(verifyLicense('TK1.a.b', A, pair.publicKey).reason, 'format');
  const data = Buffer.from(JSON.stringify({ version: 1, product: 'other', machineCode: A }));
  const code = 'TK1.' + data.toString('base64url') + '.' + crypto.sign(null, data, pair.privateKey).toString('base64url');
  assert.equal(verifyLicense(code, A, pair.publicKey).reason, 'invalid');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tk-license-old-'));
  try {
    const filePath = path.join(directory, 'activation.lic'); fs.writeFileSync(filePath, crypto.randomBytes(100));
    assert.equal(createLicenseStore({ filePath, getMachineCode: () => A, publicKey: pair.publicKey }).state().ok, false);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('写入失败显式返回错误，不报告激活成功', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tk-license-write-'));
  try {
    const store = createLicenseStore({ filePath: path.join(directory, 'missing', 'activation.lic'), getMachineCode: () => A, publicKey: pair.publicKey });
    assert.equal(store.activate(sign(A)).reason, 'storage_error');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
