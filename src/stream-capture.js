// v1.12.0 移植自抖歪 stream-info.js（用户已买断版权并授权）：
// 从直播页网络响应里递归提取 rtmp 推流码（评分排序 + 解析 serverUrl/streamKey）
'use strict';

// v1.12.33 扩大匹配：+inspect/data/stream（手机直播间 room/inspect 响应含推流码，之前漏匹配导致捕获率低）
const STREAM_RESPONSE_RE = /(webcast\/room\/(enter|create|start|start_live|info|inspect|data|stream|finish|close))|(webcast\/im\/fetch)|(\/live\/[a-z_\/]*?(room|start|create|info))|(start_live)|(rtmp_push)|(push_url)/i;

function isStreamResponseUrl(url) {
  return STREAM_RESPONSE_RE.test(String(url || ''));
}

function normalizeUrlValue(v) {
  return String(v || '')
    .replace(/\\u0026/gi, '&')
    .replace(/\\u003d/gi, '=')
    .replace(/\\u00252f/gi, '/')
    .replace(/\\\//g, '/')
    .replace(/^[\s"'`]+|[\s"'`]+$/g, '')
    .trim();
}

function scorePushUrlCandidate(cand) {
  const sourcePath = String((cand && cand.sourcePath) || '').toLowerCase();
  const url = String((cand && cand.url) || '').toLowerCase();
  let score = 0;
  if (sourcePath.includes('complete_push_urls')) score += 0x82;
  if (sourcePath.includes('stream_url')) score += 0x78;
  if (sourcePath.includes('rtmp_push_url')) score += 0x6e;
  if (sourcePath.includes('start_live') || sourcePath.includes('start_stream')) score += 0x50;
  if (sourcePath === 'push_url' || sourcePath.endsWith('.push_url')) score += 0x5a;
  if (sourcePath.includes('room_id')) score += 0x3c;
  if (sourcePath.includes('stream_id')) score += 0x32;
  if (url.startsWith('rtmps://')) score += 0x14;
  if (url.includes('rtmp://')) score += 0xa;
  return score;
}

function collectPushUrlCandidates(obj, sourcePath = 'root', seen = new Set()) {
  const out = [];
  const push = (v, sp) => {
    const norm = normalizeUrlValue(v);
    if (!/^rtmps?:\/\//i.test(norm)) return;
    const dedup = sp + '::' + norm;
    if (seen.has(dedup)) return;
    seen.add(dedup);
    out.push({ url: norm, sourcePath: sp, score: scorePushUrlCandidate({ url: norm, sourcePath: sp }) });
  };
  if (!obj || typeof obj !== 'object') {
    if (typeof obj === 'string') push(obj, sourcePath);
    return out;
  }
  for (const k of ['stream_url']) {
    if (Array.isArray(obj[k])) obj[k].forEach((v, i) => push(v, sourcePath + '.' + k + '[' + i + ']'));
  }
  for (const k of ['rtmp_push_url', 'push_url']) {
    if (typeof obj[k] === 'string') push(obj[k], sourcePath + '.' + k);
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) out.push(...collectPushUrlCandidates(obj[i], sourcePath + '[' + i + ']', seen));
    return out;
  }
  for (const [k, v] of Object.entries(obj)) out.push(...collectPushUrlCandidates(v, sourcePath + '.' + k, seen));
  return out;
}

function parsePushUrl(raw) {
  const url = normalizeUrlValue(raw);
  if (!/^rtmps?:\/\//i.test(url)) return null;
  try {
    const u = new URL(url);
    const segs = (u.pathname || '/').split('/').filter(Boolean);
    if (segs.length > 0) {
      const last = segs[segs.length - 1];
      if (/^stream-[^/?#]+/i.test(last)) {
        const serverPath = segs.slice(0, -1).join('/');
        return { rawUrl: url, serverUrl: u.protocol + '//' + u.host + (serverPath ? '/' + serverPath : ''), streamKey: '' + last + u.search };
      }
    }
    if (u.search) {
      return { rawUrl: url, serverUrl: u.protocol + '//' + u.host + u.pathname, streamKey: u.search.replace(/^\?/, '') };
    }
  } catch (e) { /* fall through */ }
  const idx = url.indexOf('stream-');
  if (idx !== -1) {
    const key = url.slice(idx);
    if (!/^stream-[^/?#]+(?:[?#].*)?$/i.test(key)) return null;
    return { rawUrl: url, serverUrl: url.slice(0, idx), streamKey: key };
  }
  return null;
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}

function extractStreamInfoFromBody(body) {
  const obj = safeJsonParse(body);
  if (!obj) return null;
  const candidates = collectPushUrlCandidates(obj).sort((a, b) => b.score - a.score);
  if (candidates.length === 0) return null;
  for (const cand of candidates) {
    const parsed = parsePushUrl(cand.url);
    if (parsed) return { ...parsed, sourcePath: cand.sourcePath };
  }
  return null;
}

module.exports = { isStreamResponseUrl, extractStreamInfoFromBody, parsePushUrl, collectPushUrlCandidates };
