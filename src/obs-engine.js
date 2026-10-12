// obs-engine.js - OBS 推流引擎（抖歪同款思路：OBSWebSocket 控制 OBS 推流）
// v1.13.0 手写 OBS 5.x WebSocket 协议（ws + crypto），兼容 OBS 32.x/5.7.4 强制认证握手
// 内置便携 OBS（obs-portable/，隐藏运行不占桌面）；默认不启用（推流引擎选 FFmpeg），acc.useOBS=true 时启用
// 链路：软件拿当场推流码 → 连接内置 OBS(WebSocket 4455) → 配置媒体源(所选视频 循环) → 设置推流地址 → StartStream
'use strict';
const WebSocket = require('ws');
const crypto = require('crypto');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const OBS_WS_URL = 'ws://127.0.0.1:4455';
// v1.14.6 asar 安装版修复：spawn 是原生调用，不能走 app.asar 内路径（磁盘上不存在）→ 重定向到 app.asar.unpacked
function unpackedPath(p) {
  const i = p.indexOf('app.asar');
  if (i !== -1 && p.indexOf('app.asar.unpacked') === -1) {
    return p.slice(0, i) + 'app.asar.unpacked' + p.slice(i + 8);
  }
  return p;
}
// v1.13.0 内置便携 OBS 优先；回退本机常见安装路径（v1.14.10 改为候选列表，不再只认 D:\OBS）
const PORTABLE_OBS = unpackedPath(path.join(__dirname, 'obs-portable', 'bin', '64bit', 'obs64.exe'));
const OBS_CANDIDATES = [
  PORTABLE_OBS,
  'D:\\OBS\\obs-studio\\bin\\64bit\\obs64.exe',
  'C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe',
  'C:\\Program Files (x86)\\obs-studio\\bin\\64bit\\obs64.exe',
];
const OBS_EXE = OBS_CANDIDATES.find(p => p && fs.existsSync(p)) || PORTABLE_OBS;
// 默认场景媒体源名（与画面编辑器所选视频对应；找不到时自动创建）
const SCENE_NAME = '直播场景';
const SOURCE_NAME = '画面源';

// v1.13.0 内置 OBS 配置：走 %APPDATA% 标准配置（便携模式在 OBS 32.x 启动即崩，实测不用）
// 已验证：内置 OBS 首次运行自动生成配置且 WebSocket(4455) 默认开启；此处仅兜底确保 config.json 存在
function ensureOBSConfig() {
  try {
    const wsCfgPath = path.join(process.env.APPDATA || '', 'obs-studio', 'plugin_config', 'obs-websocket', 'config.json');
    if (fs.existsSync(wsCfgPath)) return;
    fs.mkdirSync(path.dirname(wsCfgPath), { recursive: true });
    fs.writeFileSync(wsCfgPath, JSON.stringify({
      alerts_enabled: false,
      auth_required: false,
      first_load: false,
      server_auth_required: false,
      server_enabled: true,
      server_password: '',
      server_port: 4455,
    }, null, 2));
  } catch (e) { console.log('[OBS引擎] WebSocket 配置兜底写入失败:', e.message); }
}
ensureOBSConfig();

// OBS 5.7+ 认证算法（实测确认，2024 后变更）：secret = base64(sha256(password + salt))；auth = base64(sha256(secret_b64str + challenge))
// 注意：password 在前、salt/challenge 均为原字符串（不 base64 解码）——与旧版(解码salt)不同
function makeAuth(challenge, salt, password) {
  const sha = (d) => crypto.createHash('sha256').update(d).digest();
  const secret = sha(Buffer.concat([Buffer.from(password, 'utf8'), Buffer.from(salt, 'utf8')])).toString('base64');
  return sha(Buffer.concat([Buffer.from(secret, 'utf8'), Buffer.from(challenge, 'utf8')])).toString('base64');
}

class OBSEngine {
  constructor() {
    this.ws = null;
    this.proc = null;
    this.sceneName = null;
    this._pending = null;
    this._id = 0;
    this._ready = false;
  }

  // 1) 确保 OBS 进程在跑（v1.13.0：先探测 4455 WebSocket，没监听才启动内置 OBS，隐藏窗口）
  ensureRunning() {
    return new Promise(async (resolve) => {
      const probe = () => new Promise(r => { const s = require('net').connect({ port: 4455, host: '127.0.0.1' }); s.on('connect', () => { s.destroy(); r(true); }); s.on('error', () => { s.destroy(); r(false); }); });
      try { if (await probe()) { resolve(true); return; } } catch (e) {}
      try {
        // v1.13.0 必须 cwd=exe 目录启动：OBS 靠 CWD 找 data\locale（否则报 Failed to find locale/en-US.ini）
        // 同时清理 OBS 崩溃痕迹（上次强杀/异常退出会弹"检测到崩溃"恢复框，阻塞 4455 就绪）
        try {
          const cp = process.env.APPDATA || '';
          for (const d of [path.join(cp, 'obs-studio', 'logs'), path.join(cp, 'obs-studio', 'crash')]) {
            if (!fs.existsSync(d)) continue;
            for (const f of fs.readdirSync(d)) { try { fs.unlinkSync(path.join(d, f)); } catch (e) {} }
          }
        } catch (e) {}
        this.proc = spawn(OBS_EXE, ['--minimize-tray'], { detached: false, windowsHide: true, cwd: path.dirname(OBS_EXE) });
        const deadline = Date.now() + 25000;
        while (Date.now() < deadline) {
          await new Promise(r => setTimeout(r, 1500));
          if (await probe()) { resolve(true); return; }
        }
        resolve(false);
      } catch (e) { resolve(false); }
    });
  }

  // 2) 连接 WebSocket（OBS 5.x 协议：Hello(op0) → 认证 → Identify(op1) → 就绪）
  connect(timeoutMs = 30000) {
    return new Promise((resolve) => {
      const deadline = Date.now() + timeoutMs;
      const tryConnect = () => {
        if (this._ready) { resolve(true); return; }
        const ws = new WebSocket(OBS_WS_URL);
        const timer = setTimeout(() => { try { ws.terminate(); } catch (e) {} retry(); }, 5000);
        ws.on('open', () => {
          this.ws = ws;
          this._pending = new Map();
          this._id = 0;
          // 不发 Identify（等 Hello 后再按认证发）——OBS 5.7 收到提前 Identify 直接 4009
        });
        ws.on('message', (d) => {
          let m; try { m = JSON.parse(d); } catch (e) { return; }
          clearTimeout(timer);
          if (m.op === 0) { // Hello
            const authData = (m.d && m.d.authentication) || null;
            const authentication = authData ? makeAuth(authData.challenge, authData.salt, '') : null;
            try {
              ws.send(JSON.stringify({ op: 1, d: { rpcVersion: 1, authentication, eventSubscriptions: 0 } }));
            } catch (e) { this.ws = null; retry(); }
          } else if (m.op === 2) { // IdentifyResponse → 就绪
            this._ready = true;
            resolve(true);
          } else if (m.op === 7) { // RequestResponse
            const rid = m.d && m.d.requestId;
            const p = this._pending && this._pending.get(rid);
            if (p) { p(m.d); this._pending.delete(rid); }
          } else if (m.op === 5) { // Event 忽略
          }
        });
        ws.on('error', () => { this.ws = null; retry(); });
        ws.on('close', () => { this.ws = null; this._ready = false; });
      };
      const retry = () => {
        if (Date.now() < deadline) tryConnect();
        else resolve(false);
      };
      tryConnect();
    });
  }

  // 3) OBS 请求（op6 request → op7 response）
  call(requestType, requestData) {
    return new Promise((resolve) => {
      if (!this.ws || !this._ready) { resolve(null); return; }
      const requestId = 'r' + (++this._id);
      this._pending.set(requestId, (d) => resolve(d));
      try {
        this.ws.send(JSON.stringify({ op: 6, d: { requestType, requestId, requestData: requestData || {} } }));
      } catch (e) { resolve(null); }
    });
  }

  async identify() {
    if (!this.ws) return null;
    try {
      const sc = await this.call('GetSceneList');
      const scenes = (sc && sc.requestStatus && !!sc.requestStatus.result && sc.responseData && sc.responseData.scenes) || [];
      const target = scenes.find(s => s.sceneName === SCENE_NAME);
      if (target) {
        this.sceneName = SCENE_NAME;
        await this.call('SetCurrentProgramScene', { sceneName: this.sceneName });
        return this.sceneName;
      }
    } catch (e) {}
    try {
      const cr = await this.call('CreateScene', { sceneName: SCENE_NAME });
      if (cr && cr.requestStatus && !!cr.requestStatus.result) { this.sceneName = SCENE_NAME; return this.sceneName; }
      return null;
    } catch (e) { return null; }
  }

  // 4) 确保媒体源存在（本地视频循环播放，代替摄像头）
  async ensureMediaSource(videoPath) {
    if (!this.ws) return false;
    const scene = this.sceneName || (await this.identify());
    if (!scene) return false;
    try {
      const list = await this.call('GetInputList');
      const inputs = (list && list.responseData && list.responseData.inputs) || [];
      const exist = inputs.find(i => i.inputName === SOURCE_NAME);
      const settings = { local_file: videoPath, looping: true, restart_on_activate: true, is_local_file: true };
      if (exist) {
        await this.call('SetInputSettings', { inputName: SOURCE_NAME, inputSettings: settings });
      } else {
        await this.call('CreateInput', { sceneName: scene, inputName: SOURCE_NAME, inputKind: 'ffmpeg_source', inputSettings: settings });
      }
      try {
        const items = await this.call('GetSceneItemList', { sceneName: scene });
        const sceneItems = (items && items.responseData && items.responseData.sceneItems) || [];
        const has = sceneItems.some(it => it.sourceName === SOURCE_NAME);
        if (!has) await this.call('CreateSceneItem', { sceneName: scene, sourceName: SOURCE_NAME });
      } catch (e) { try { await this.call('CreateSceneItem', { sceneName: scene, sourceName: SOURCE_NAME }); } catch (e2) {} }
      return true;
    } catch (e) {
      console.log('[OBS引擎] 媒体源配置失败:', e.message);
      return false;
    }
  }

  // 5) 设置推流地址（当场推流码）
  async setStream(rtmpUrl, streamKey) {
    if (!this.ws) return false;
    let server = rtmpUrl, key = streamKey || '';
    try {
      const u = new URL(rtmpUrl);
      server = u.protocol + '//' + u.host;
      const p = (u.pathname || '').replace(/^\//, '');
      if (p) key = p + (u.search || '');
      if (!key && streamKey) key = streamKey;
      if (key && streamKey && !key.includes(streamKey)) key = key + '/' + streamKey;
    } catch (e) {}
    try {
      const r = await this.call('SetStreamServiceSettings', { streamServiceType: 'rtmp_common', streamServiceSettings: { server, key, use_auth: false } });
      console.log('[OBS引擎] 推流地址已设置 server=' + server + ' key=' + String(key).slice(0, 40) + ' result=' + (r && r.requestStatus ? r.requestStatus.result : 'null'));
      return !!(r && r.requestStatus && r.requestStatus.result);
    } catch (e) {
      console.log('[OBS引擎] SetStreamServiceSettings 失败:', e.message);
      return false;
    }
  }

  // 6) 开始推流（启动后验证是否真正推流，4 秒内无输出则失败）
  async startStream() {
    if (!this.ws) return false;
    try {
      await this.call('StartStream');
      await new Promise(r => setTimeout(r, 4000));
      const st = await this.status();
      if (st && st.outputActive) return true;
      console.log('[OBS引擎] StartStream 后 outputActive=false，推流未真正启动');
      return false;
    } catch (e) { console.log('[OBS引擎] StartStream:', e.message); return false; }
  }

  async stopStream() {
    if (!this.ws) return false;
    try { const r = await this.call('StopStream'); return !!(r && r.requestStatus && r.requestStatus.result); } catch (e) { return false; }
  }

  async status() {
    if (!this.ws) return null;
    try { const r = await this.call('GetStreamStatus'); return (r && r.responseData) || null; } catch (e) { return null; }
  }

  async disconnect() {
    this._ready = false;
    if (this.ws) { try { this.ws.close(); } catch (e) {} this.ws = null; }
    // 不主动杀 OBS 进程（保留内置 OBS 运行，下次推流复用；软件退出时由主进程统一处理）
  }

  // v1.13.0 优雅关闭内置 OBS（Shutdown API）：干净退出 → 下次启动不弹崩溃恢复框
  async shutdown() {
    if (!this.ws || !this._ready) return false;
    try { const r = await this.call('Shutdown'); return !!(r && r.requestStatus && r.requestStatus.result); } catch (e) { return false; }
  }
}

module.exports = { OBSEngine, OBS_WS_URL, OBS_EXE, SCENE_NAME, SOURCE_NAME };
