// ============================================================
// flv-sei.js —— 抖歪精确版（逐行对照 _decrypted/companion-stream/flv-sei.cjs）
// 作用：在 FLV 视频流的 H.264 NALU 里注入「帧签名 SEI」
//       TikTok 服务器校验视频流中的签名 SEI 才接受推流（invalid_sign/not_allowed 的根治）
// 关键差异（对照抖歪修正）：
//   1. SEI 长度用 varint（0xff 前缀）；payload 做 H.264 emulation prevention（0x03 转义）
//   2. 节奏由 FLV tag 时间戳驱动（pacer），每个视频 NALU tag 注入 0..N 个 SEI
//   3. SEI 注入位置：整个 NALU body 最前（slice(0,5) + SEIs + slice(5)）
//   4. payload JSON 字段精确照抄（fresh/small/signed 三型）
//   5. 签名取「当前墙钟秒」的签名（cache 预取 300s，逐秒一条）
// ============================================================
'use strict';
const { Transform } = require('stream');

// ---------- H.264 varint（0xff 前缀编码，照搬抖歪 variable） ----------
function variable(n) {
  const out = [];
  while (n >= 0xff) { out.push(0xff); n -= 0xff; }
  return Buffer.from([...out, n]);
}

// ---------- sei100：SEI NALU（type=6）生成，含 emulation prevention（照搬抖歪） ----------
function sei100(payload) {
  const rbsp = Buffer.concat([variable(0x64), variable(payload.length), payload, Buffer.from([0x80])]);
  const out = [0x06];
  let zeros = 0;
  for (const b of rbsp) {
    if (zeros >= 2 && b <= 0x03) { out.push(0x03); zeros = 0; }
    out.push(b);
    zeros = (b === 0x00) ? zeros + 1 : 0;
  }
  return Buffer.from(out);
}

// ---------- FrameSigner：批量预取帧签名（照搬抖歪：fetch 300s、逐秒 Map、sign 取当前秒） ----------
class FrameSigner {
  constructor({ getBatch, binding, now = Date.now }) {
    if (typeof getBatch !== 'function') throw new Error('FrameSigner: getBatch 必须是函数');
    this.getBatch = getBatch;
    this.binding = binding || { aid: '8311', uid: '', did: '', roomid: '', frametype: '2' };
    this.now = now;
    this.cache = new Map();   // timestamp(秒) -> signResult
    this.batchStart = 0;
    this.batchEnd = 0;
    this.prefetchAt = 0;      // 接近末尾阈值
    this.prefetching = null;
    this.lastError = '';
  }

  async fetch(startTs) {
    const t0 = Math.floor(Number(startTs) || Math.floor(this.now() / 1000));
    const resp = await this.getBatch({ ...this.binding, timestamp: t0 }, 300, 1);
    const map = new Map();
    const list = (resp && resp.signatures) || [];
    for (const item of list) {
      const k = Number(item && item.timestamp);
      if (Number.isFinite(k) && item.signResult) map.set(k, item.signResult);
    }
    if (!map.size) throw new Error('帧签名批次为空');
    this.cache = map;
    this.batchStart = t0;
    this.batchEnd = t0 + 300;
    this.prefetchAt = t0 + 240; // 抖歪 0xf0
    this.lastError = '';
    return map;
  }

  prefetch(startTs) {
    if (this.prefetching) return this.prefetching;
    this.prefetching = this.fetch(startTs)
      .catch(e => { this.lastError = e.message || String(e); })
      .finally(() => { this.prefetching = null; });
    return this.prefetching;
  }

  // sign()：取 ≤当前墙钟秒的最近签名（RapidAPI 30s 粒度；抖歪服务 1s 粒度）
  // 返回 { result, nowMs }，nowMs=签名时间戳毫秒（SEI ts/timestamp 与签名 slot 精确对齐）
  async sign() {
    const pick = (sec) => {
      let best = null, bestTs = -1;
      for (const [k, v] of this.cache) {
        if (k <= sec && k > bestTs) { bestTs = k; best = v; }
      }
      return best ? { result: best, signTs: bestTs } : null;
    };
    let nowSec = Math.floor(this.now() / 1000);
    let hit = pick(nowSec);
    if (!hit) {
      if (!this.prefetching) this.prefetch(nowSec);
      try { await this.prefetching; } catch (e) {}
      nowSec = Math.floor(this.now() / 1000);
      hit = pick(nowSec);
    }
    if (!hit) throw new Error('帧签名当前秒缺失: ' + nowSec + ' lastError=' + this.lastError);
    // 接近批次末尾 → 后台预取下一批
    if (nowSec >= this.prefetchAt && nowSec < this.batchEnd) this.prefetch(nowSec);
    // nowMs = 签名槽位毫秒（30s 粒度下 SEI ts 必须与签名 slot 精确对齐；抖歪 1s 粒度时等价于当前墙钟）
    return { result: hit.result, nowMs: hit.signTs * 1000 };
  }

  destroy() {}
}

// ---------- SeiPacer：FLV tag 时间戳驱动的注入节奏（照搬抖歪） ----------
class SeiPacer {
  constructor() {
    this.base = null;
    this.slot = 0;
    this.last = null;
  }
  next(ts) {
    if (this.base === null) this.base = ts;
    if (this.last !== null && (ts < this.last || ts - this.last > 30000)) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
    this.last = ts;
    const out = [];
    const delays = [0, 0, 16, 700, 1000];
    const kinds = ['signed', 'small', 'signed', 'signed', 'signed'];
    while (ts - this.base >= Math.floor(this.slot / 5) * 2000 + delays[this.slot % 5]) {
      out.push(this.slot === 0 ? 'startup' : kinds[this.slot % 5]);
      this.slot++;
      if (out.length > 80) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
    }
    return out;
  }
}

// ---------- FlvSeiTransform（照搬抖歪） ----------
class FlvSeiTransform extends Transform {
  constructor({ signer, width, height, now = Date.now }) {
    super();
    if (![width, height].every(v => Number.isFinite(v) && v >= 16 && v <= 16384)) {
      throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
    }
    this.signer = signer;
    this.width = width;
    this.height = height;
    this.now = now;
    this.buffer = Buffer.alloc(0);
    this.header = false;
    this.lengthSize = null;
    this.pacer = new SeiPacer();
    this.index = -1;   // 抖歪 index 初始 -1 → 首个 sei_index=0
    this.metrics = { videoTags: 0, audioTags: 0, sei: 0, signed: 0, bytes: 0 };
  }

  _transform(chunk, enc, cb) {
    this._drain(chunk).then(() => cb(), cb);
  }

  async _drain(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (!this.header) {
      if (this.buffer.length < 9) return;
      if (this.buffer.slice(0, 3).toString() !== 'FLV' || this.buffer[3] !== 1) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
      const headerSize = this.buffer.readUInt32BE(5);
      if (headerSize < 9 || headerSize > 0x1000) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
      if (this.buffer.length < headerSize + 4) return;
      if (this.buffer.readUInt32BE(headerSize) !== 0) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
      this.push(this.buffer.subarray(0, headerSize + 4));
      this.buffer = this.buffer.slice(headerSize + 4);
      this.header = true;
    }
    while (this.buffer.length >= 11) {
      const dataSize = this.buffer.readUIntBE(1, 3);
      if (dataSize > 8 * 0x400 * 0x400 || ![0x8, 0x9, 0x12].includes(this.buffer[0]) || this.buffer.readUIntBE(8, 3) !== 0) {
        throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
      }
      if (this.buffer.length < dataSize + 15) return;
      const tag = this.buffer.subarray(0, dataSize + 15);
      this.buffer = this.buffer.slice(dataSize + 15);
      if (tag.readUInt32BE(11 + dataSize) !== dataSize + 11) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');

      let body = tag.subarray(11, 11 + dataSize);
      if (tag[0] === 0x09) {
        // 视频 tag
        if (body.length < 5 || (body[0] & 0x0f) !== 7) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
        this.metrics.videoTags++;
        if (body[1] === 0x00) {
          // AVCDecoderConfigurationRecord：tagData[9]=0xFC|lengthSizeMinusOne
          if (body.length < 10) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
          this.lengthSize = (body[9] & 0x03) + 1;
          if (this.lengthSize === 3) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
        } else if (body[1] === 0x01) {
          // NALU 数据
          if (!this.lengthSize) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
          // 校验 NALU 结构完整性
          for (let i = 5; i < body.length; ) {
            if (i + this.lengthSize > body.length) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
            const len = body.readUIntBE(i, this.lengthSize);
            i += this.lengthSize;
            if (!len || i + len > body.length) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
            i += len;
          }
          // FLV tag 时间戳（3 字节 + 高位扩展位）
          const ts = tag.readUIntBE(4, 3) + tag[7] * 0x1000000;
          const seis = [];
          for (const kind of this.pacer.next(ts)) {
            let seiObj;
            if (kind === 'small') {
              // small 型 = 无签名（抖歪原样：sei_index + video_e2e_delay）
              const nowMs = this.now();
              seiObj = {
                sei_index: ++this.index,
                video_e2e_delay: { capture_window: nowMs, encode: nowMs + 0x6e },
              };
            } else {
              // startup/signed 型 = 带 signResult
              const { result, nowMs } = await this.signer.sign();
              seiObj = {
                live_sei_mute_mic: { is_mute_mic: 0 },
                push_video_height: this.height,
                push_video_width: this.width,
                sei_index: ++this.index,
                signResult: result,
                ttls_live_scene: 'live_studio',
              };
              // startup 型不加时间戳；signed 型加 live_sei_game_moment.timestamp + ts
              if (kind !== 'startup') {
                seiObj.live_sei_game_moment = { timestamp: nowMs };
                seiObj.ts = String(nowMs);
              }
              this.metrics.signed++;
            }
            const sei = sei100(Buffer.concat([Buffer.from('JSON'), Buffer.from(JSON.stringify(seiObj))]));
            const lenBuf = Buffer.alloc(this.lengthSize);
            if (sei.length >= 2 ** (8 * this.lengthSize)) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
            lenBuf.writeUIntBE(sei.length, 0, this.lengthSize);
            seis.push(lenBuf, sei);
            this.metrics.sei++;
          }
          if (seis.length) {
            body = Buffer.concat([body.slice(0, 5), ...seis, body.slice(5)]);
          }
        } else if (body[1] !== 0x02) {
          throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
        }
      } else if (tag[0] === 0x08) {
        this.metrics.audioTags++;
      }
      if (body.length > 0xffffff) throw new Error('伴侣流媒体数据无效或暂不支持该编码格式');
      const header = Buffer.from(tag.subarray(0, 11));
      header.writeUIntBE(body.length, 1, 3);
      const prev = Buffer.alloc(4);
      prev.writeUInt32BE(body.length + 11, 0);
      const out = Buffer.concat([header, body, prev]);
      this.metrics.bytes += out.length;
      this.push(out);
    }
  }

  _flush(cb) {
    cb(this.buffer.length || !this.header ? new Error('伴侣流媒体数据无效或暂不支持该编码格式') : undefined);
  }
}

module.exports = { FlvSeiTransform, FrameSigner, SeiPacer, sei100 };
