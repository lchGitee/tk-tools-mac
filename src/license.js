const crypto = require('crypto');
const fs = require('fs');

const PRODUCT = 'tk-tools';
const MAX_CODE_LENGTH = 4096;
const MACHINE_PATTERN = /^[A-F0-9]{32}$/;

function licensePayload(machineCode) {
  if (!MACHINE_PATTERN.test(machineCode)) throw new Error('机器码应为 32 位十六进制字符');
  return Buffer.from(JSON.stringify({ version: 1, product: PRODUCT, machineCode }), 'utf8');
}

function verifyLicense(code, machineCode, publicKey) {
  if (typeof code !== 'string' || code.length > MAX_CODE_LENGTH) return { ok: false, reason: 'format' };
  const parts = code.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'TK1' || !parts.slice(1).every(p => /^[A-Za-z0-9_-]+$/.test(p))) {
    return { ok: false, reason: 'format' };
  }
  const payload = Buffer.from(parts[1], 'base64url');
  const signature = Buffer.from(parts[2], 'base64url');
  if (payload.toString('base64url') !== parts[1] || signature.toString('base64url') !== parts[2] || signature.length !== 64) {
    return { ok: false, reason: 'format' };
  }
  // 先验证签名，再信任授权内容；机器码不能由客户端重新绑定。
  if (!crypto.verify(null, payload, publicKey, signature)) return { ok: false, reason: 'invalid' };
  let data;
  try { data = JSON.parse(payload.toString('utf8')); }
  catch { return { ok: false, reason: 'invalid' }; }
  if (!data || data.version !== 1 || data.product !== PRODUCT || !MACHINE_PATTERN.test(data.machineCode)
    || Object.keys(data).sort().join(',') !== 'machineCode,product,version') {
    return { ok: false, reason: 'invalid' };
  }
  if (data.machineCode !== machineCode) return { ok: false, reason: 'machine_mismatch' };
  return { ok: true, reason: 'ok' };
}

function createLicenseStore({ filePath, getMachineCode, publicKey }) {
  return {
    state() {
      const machine = getMachineCode();
      let code;
      try {
        if (fs.statSync(filePath).size > MAX_CODE_LENGTH) return { ok: false, reason: 'invalid', machine };
        code = fs.readFileSync(filePath, 'utf8');
      } catch (error) {
        return { ok: false, reason: error.code === 'ENOENT' ? 'not_activated' : 'storage_error', machine };
      }
      return { ...verifyLicense(code, machine, publicKey), machine };
    },
    activate(code) {
      const result = verifyLicense(code, getMachineCode(), publicKey);
      if (!result.ok) return result;
      const temporary = filePath + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
      try {
        // 原样保存已签名的授权码，替换文件前先完成写入。
        fs.writeFileSync(temporary, code.trim(), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        fs.renameSync(temporary, filePath);
      } catch (error) {
        if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
        return { ok: false, reason: 'storage_error' };
      }
      return result;
    },
  };
}

module.exports = { licensePayload, verifyLicense, createLicenseStore };
