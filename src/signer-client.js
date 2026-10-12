// signer-client.js - 签名服务客户端（移植自抖歪 SignerClient，用户已买断授权）
// 抖歪通道：RapidAPI 签名服务生成 X-Bogus/X-Argus/X-Ladon → Node 直连 webcast API 带签名头不被风控
'use strict';
const https = require('https');
// v1.12.38 优先用 Electron net（走 app.commandLine 设置的 socks5 代理），墙内直连 RapidAPI 被墙导致签名失败
let electronNet = null;
try { electronNet = require('electron').net; } catch (e) { electronNet = null; }
const DEFAULT_URL = 'https://tiktok-live-studio-api-signer1.p.rapidapi.com/';

function normalizeBaseUrl(url) {
  if (typeof url !== 'string' || url.length > 2048 || /[\s\\]/.test(url)) throw new Error('签名服务地址无效');
  const u = new URL(url);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname))) throw new Error('签名服务地址无效');
  if (u.username || u.password || u.search || u.hash) throw new Error('签名服务地址无效');
  let p = u.pathname;
  if (!p.endsWith('/')) p += '/';
  return u.protocol + '//' + u.host + p;
}

function postJson(url, body, opts, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = Buffer.from(JSON.stringify(body));
    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Content-Length': payload.length };
    if (opts.authMode === 'header' && opts.apiKey) { headers['X-RapidAPI-Key'] = opts.apiKey; headers['X-RapidAPI-Host'] = u.host; }
    if (opts.authMode === 'bearer' && opts.apiKey) headers['Authorization'] = 'Bearer ' + opts.apiKey;
    // v1.12.38 Electron net 优先（走 socks5 10808 代理）；非 Electron 环境回退 Node https
    if (electronNet && electronNet.request) {
      try {
        const req = electronNet.request({ method: 'POST', url, headers });
        let size = 0;
        req.on('response', (res) => {
          const chunks = [];
          res.on('data', c => { size += c.length; if (size > 1048576) { req.destroy(); reject(new Error('签名服务响应过大')); } else chunks.push(c); });
          res.on('end', () => {
            const status = res.statusCode;
            if (status < 200 || status >= 300) { reject(new Error('签名服务 HTTP ' + status)); return; }
            try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (e) { reject(new Error('签名服务响应格式错误')); }
          });
        });
        req.on('error', reject);
        req.setTimeout(timeoutMs, () => { try { req.abort(); } catch (e) {} });
        req.end(payload);
        return;
      } catch (eNet) { /* 回退 Node https */ }
    }
    const lib = u.protocol === 'https:' ? https : require('http');
    const req = lib.request(u, { method: 'POST', headers }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', c => { size += c.length; if (size > 1048576) { req.destroy(); reject(new Error('签名服务响应过大')); } else chunks.push(c); });
      res.on('end', () => {
        const status = res.statusCode;
        if (status < 200 || status >= 300) { reject(new Error('签名服务 HTTP ' + status)); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (e) { reject(new Error('签名服务响应格式错误')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('签名服务超时')); });
    req.end(payload);
  });
}

// 拿签名头（抖歪同款：RapidAPI /signatures 返回 headers 里的 x-khronos/x-argus/x-ladon）
async function getSignatures({ baseUrl = DEFAULT_URL, apiKey, authMode = 'header', params = '', stub = '', device_id = '', timestamp = Math.floor(Date.now() / 1000), license_id = 0x6fefffe9 }, timeoutMs = 20000) {
  if (!apiKey) throw new Error('未配置签名服务 Key');
  const url = normalizeBaseUrl(baseUrl) + 'signatures';
  const resp = await postJson(url, { timestamp, aid: '8311', device_id: String(device_id), license_id, params: String(params), stub: String(stub) }, { apiKey, authMode }, timeoutMs);
  const data = (resp && resp.signResult) || resp || {};
  const hdrs = data.headers || {};
  const get = (names) => { for (const n of names) { const v = hdrs[n]; if (v !== undefined && v !== null) return String(v); } return ''; };
  const bogus = get(['X-Bogus', 'x-bogus', 'x-khronos', 'X-Khronos']);
  const argus = get(['X-Argus', 'x-argus']);
  const ladon = get(['X-Ladon', 'x-ladon']);
  if (!argus || !ladon) throw new Error('签名服务返回缺少签名头');
  const out = { 'X-Bogus': bogus, 'X-Argus': argus, 'X-Ladon': ladon };
  const khronos = get(['x-khronos', 'X-Khronos']);
  if (khronos) out['X-Khronos'] = khronos;
  return out;
}

// 自检：签名服务连通性（抖歪同款 detect 逻辑）
async function checkSigner({ baseUrl = DEFAULT_URL, apiKey, authMode = 'header' }) {
  const t = Math.floor(Date.now() / 1000);
  const sig = await getSignatures({ baseUrl, apiKey, authMode, timestamp: t });
  return { ok: true, checkedAt: Date.now(), message: '签名服务连接成功（X-Bogus ' + sig['X-Bogus'].length + ' 字符）' };
}

// 帧签名规范化（照搬抖歪 signer-client.cjs normalizeFrame）：
// 强制 frametype='2'/lid='1879048169'/signversion='3'，缺字段补默认、非法即抛
function normalizeFrame(frame) {
  const src = (frame && frame.signResult) || frame;
  if (!src || !['signinfo', 'signvalue'].every(k => typeof src[k] === 'string' && src[k].length > 0 && src[k].length <= 16384)) {
    throw new Error('帧签名格式无效');
  }
  const out = {
    frametype: String(src.frametype || '2'),
    lid: String(src.lid || '1879048169'),
    signinfo: src.signinfo,
    signvalue: src.signvalue,
    signversion: String(src.signversion || '3'),
  };
  if (out.frametype !== '2' || !/^\d{1,64}$/.test(out.lid) || !/^[\x21-\x7e]{1,32}$/.test(out.signversion)) {
    throw new Error('帧签名格式无效');
  }
  return out;
}

// 帧签名批次（抖歪同款 /framesign/batch）：
// 绑定 uid/did/roomid/frametype=2，服务端按 timestamp 生成 30s 粒度签名
// 返回 { success, signatures: [{timestamp, signResult:{frametype,lid,signinfo,signvalue,signversion}}] }
async function getFrameSignatures({ baseUrl = DEFAULT_URL, apiKey, authMode = 'header', uid = '', did = '', roomid = '', frametype = '2', timestamp = Math.floor(Date.now() / 1000), duration = 300, step = 1 }, timeoutMs = 30000) {
  if (!apiKey) throw new Error('未配置签名服务 Key');
  const url = normalizeBaseUrl(baseUrl) + 'framesign/batch';
  const body = {
    aid: '8311',
    uid: String(uid || ''),
    did: String(did || ''),
    roomid: String(roomid || ''),
    frametype: String(frametype || '2'),
    timestamp: Math.floor(Number(timestamp) || Math.floor(Date.now() / 1000)),
    duration: Number(duration) || 300,
    step: Number(step) || 1,
  };
  const resp = await postJson(url, body, { apiKey, authMode }, timeoutMs);
  if (!resp || resp.success !== true) throw new Error('帧签名服务返回失败: ' + JSON.stringify(resp || {}).slice(0, 200));
  if (!Array.isArray(resp.signatures) || !resp.signatures.length) throw new Error('帧签名服务返回空批次');
  // 照搬抖歪：逐条 normalize + 校验 timestamp 范围
  const norm = [];
  for (const item of resp.signatures) {
    const ts = Number(item && item.timestamp);
    if (!Number.isFinite(ts) || ts < body.timestamp - 1 || ts > body.timestamp + body.duration) throw new Error('帧签名批次时间戳异常');
    norm.push({ timestamp: ts, signResult: normalizeFrame(item) });
  }
  return { success: true, signatures: norm };
}

module.exports = { getSignatures, getFrameSignatures, checkSigner, normalizeBaseUrl, DEFAULT_URL };
