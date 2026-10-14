// xray-runtime.js — 内置 xray 代理运行时（v1.13.11 照搬抖歪 network 层机制）
// 目标：软件内置 xray.exe，用保存的节点（vless/vmess/socks5）起本地 SOCKS5 代理（专用端口 10888）
//      页面/API 全部走内置代理 → 换电脑无需桌面 v2（v2rayN）也能正常工作
const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_PORT = 10888; // 内置代理专用端口（避开桌面 v2 的 10808/10809）

// v1.14.6 asar 安装版修复：child_process.spawn 是原生调用，不能使用 app.asar 内路径（磁盘上不存在），
// 必须重定向到 app.asar.unpacked（electron-builder asarUnpack 输出目录），否则安装版 xray 永远起不来
function unpackedPath(p) {
  const i = p.indexOf('app.asar');
  if (i !== -1 && p.indexOf('app.asar.unpacked') === -1) {
    return p.slice(0, i) + 'app.asar.unpacked' + p.slice(i + 8);
  }
  return p;
}

// ---------- 节点链接解析（vless/vmess/socks5 → xray outbound）----------
function fail(msg) { throw new Error(msg); }
function text(s, label, max = 400) {
  if (typeof s !== 'string' || s.length > max || /[\x00-\x1f\x7f]/.test(s)) fail(label + '格式无效');
  return s;
}
function host(h) {
  h = text(h, '服务器地址', 253).replace(/^\[|\]$/g, '');
  if (!h || /[\s/@?#\\]/.test(h)) fail('服务器地址无效');
  if (!/^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(h) && !net.isIP(h)) fail('服务器地址无效');
  return h;
}
function port(p) {
  if (!/^\d{1,5}$/.test(String(p)) || Number(p) < 1 || Number(p) > 65535) fail('端口必须为 1–65535');
  return Number(p);
}
function userId(u) {
  u = text(u, '用户ID', 36);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(u)) fail('用户ID格式无效');
  return u;
}
function b64decode(s) {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s) || s.length % 4 === 1) fail('节点 Base64 格式无效');
  const buf = Buffer.from(s, 'base64');
  return new TextDecoder('utf-8', { fatal: true }).decode(buf);
}
function stream(params) {
  const netMap = { tcp: 'tcp', raw: 'tcp', ws: 'ws', websocket: 'ws', grpc: 'grpc', xhttp: 'xhttp', httpupgrade: 'httpupgrade' };
  const network = netMap[params.type || 'tcp'];
  if (!network) fail('传输协议无效');
  const security = params.security || 'none';
  if (!['none', 'tls', 'reality'].includes(security)) fail('加密方式无效');
  const flow = params.flow || '';
  if (flow && (flow !== 'xtls-rprx-vision' || network !== 'tcp' || security === 'none')) fail('flow 仅支持 tcp+vision');
  if (security === 'reality' && !['tcp', 'grpc', 'xhttp'].includes(network)) fail('reality 仅支持 tcp/grpc/xhttp');
  const headerType = params.headerType || 'none';
  if (!['none', 'http'].includes(headerType)) fail('headerType 无效');
  if (headerType === 'http' && (network !== 'tcp' || security === 'reality' || flow)) fail('http 伪装与当前配置冲突');
  const out = { network, security };
  if (security !== 'none') {
    const tlsObj = {
      serverName: text(params.sni || '', 'TLS 参数', 253),
      fingerprint: text(params.fp || 'chrome', 'TLS 参数', 32),
    };
    if (!['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'qq', 'random', 'randomized'].includes(tlsObj.fingerprint)) fail('指纹参数无效');
    if (security === 'reality') {
      if (!/^[a-zA-Z0-9_-]{43}$/.test(params.pbk || '')) fail('reality 公钥无效');
      if (!/^(?:[a-f0-9]{2}){0,8}$/i.test(params.sid || '')) fail('reality shortId 无效');
      out.realitySettings = {
        serverName: tlsObj.serverName, fingerprint: tlsObj.fingerprint, allowInsecure: false,
        publicKey: params.pbk, shortId: params.sid || '', spiderX: text(params.spx || '/', 'spiderX', 64),
      };
    } else {
      tlsObj.allowInsecure = false;
      if (params.alpn) {
        const list = String(params.alpn).split(',');
        if (list.some(x => !['h2', 'http/1.1'].includes(x))) fail('alpn 参数无效');
        tlsObj.alpn = list;
      }
      out.tlsSettings = tlsObj;
    }
  }
  if (network === 'ws') out.wsSettings = { path: text(params.path || '/', '路径', 256), headers: params.host ? { Host: text(params.host, 'Host', 253) } : {} };
  if (network === 'grpc') out.grpcSettings = { serviceName: text(params.serviceName || '', 'serviceName', 256), multiMode: params.mode === 'multi' };
  if (network === 'xhttp') out.xhttpSettings = { path: text(params.path || '/', '路径', 256), host: text(params.host || '', 'host', 253), mode: params.mode || 'auto' };
  if (network === 'tcp' && headerType === 'http') {
    const paths = text(params.path || '/', 'HTTP 伪装路径', 256).split(',');
    const hosts = params.host ? text(params.host, 'HTTP 伪装 Host', 253).split(',') : [];
    out.tcpSettings = { header: { type: 'http', request: { path: paths, ...(hosts.length ? { headers: { Host: hosts } } : {}) } } };
  }
  return { streamSettings: out, flow };
}

function parseNodeLink(link) {
  if (typeof link !== 'string' || link.length > 4000) fail('节点链接过长或格式无效');
  const raw = link.trim();
  if (!raw || /[\r\n]/.test(raw)) fail('每次请输入一个完整节点链接');
  let protocol, server, portNum, name, outbound;
  if (raw.startsWith('vmess://')) {
    let obj;
    try { obj = JSON.parse(b64decode(raw.slice(8))); } catch (e) { fail('VMess 内容无效'); }
    if (!obj || Array.isArray(obj) || typeof obj !== 'object') fail('VMess 内容无效');
    if (obj.aid && String(obj.aid) !== '0') fail('暂不支持旧版 VMess alterId，请导出 AEAD 节点链接');
    if (obj.type && !['none', 'http', 'gun', 'multi'].includes(obj.type)) fail('VMess 传输协议无效');
    protocol = 'vmess';
    server = host(obj.add);
    portNum = port(obj.port);
    name = text(obj.ps || 'VMess 节点', '节点名称', 120);
    const security = obj.scy || 'auto';
    if (!['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'].includes(security)) fail('VMess 加密方式无效');
    const st = stream({ type: obj.type, security: obj.tls || 'none', sni: obj.sni || obj.host, host: obj.host, path: obj.path, serviceName: obj.path, fp: obj.fp, alpn: obj.alpn, headerType: obj.type === 'http' ? 'http' : 'none', mode: obj.type === 'multi' ? 'multi' : undefined });
    outbound = {
      protocol: 'vmess',
      settings: { vnext: [{ address: server, port: portNum, users: [{ id: userId(obj.id), security, alterId: 0 }] }] },
      streamSettings: st.streamSettings,
    };
  } else if (raw.startsWith('vless://')) {
    let u;
    try { u = new URL(raw); } catch (e) { fail('VLESS 地址格式无效'); }
    if (u.pathname && u.pathname !== '/') fail('VLESS 地址格式无效');
    const params = u.searchParams;
    const encryption = params.get('encryption') || 'none';
    if (encryption && encryption !== 'none') fail('当前仅支持 encryption=none 的 VLESS 节点');
    protocol = 'vless';
    server = host(u.hostname);
    portNum = port(u.port);
    name = text(decodeURIComponent(u.hash.slice(1)) || 'VLESS 节点', '节点名称', 120);
    const st = stream({
      type: params.get('type'), security: params.get('security'), sni: params.get('sni'),
      fp: params.get('fp'), flow: params.get('flow'), pbk: params.get('pbk'), sid: params.get('sid'),
      spx: params.get('spx'), path: params.get('path'), host: params.get('host'),
      serviceName: params.get('serviceName'), alpn: params.get('alpn'), headerType: params.get('headerType'),
      mode: params.get('mode'), authority: params.get('authority'),
    });
    if (st.streamSettings.security === 'none') fail('VLESS 节点必须启用 tls 或 reality');
    outbound = {
      protocol: 'vless',
      settings: { vnext: [{ address: server, port: portNum, users: [{ id: userId(decodeURIComponent(u.username)), encryption: 'none', ...(st.flow ? { flow: st.flow } : {}) }] }] },
      streamSettings: st.streamSettings,
    };
  } else if (/^socks5?:\/\//i.test(raw)) {
    let u;
    try { u = new URL(raw); } catch (e) { fail('SOCKS 地址格式无效'); }
    if (u.search || (u.hash && u.hash !== '/')) fail('SOCKS 地址格式无效');
    protocol = 'socks';
    server = host(u.hostname);
    portNum = port(u.port);
    name = text(decodeURIComponent(u.hash.slice(1)) || 'SOCKS 节点', '节点名称', 120);
    let username = decodeURIComponent(u.username), password = decodeURIComponent(u.password);
    if (username && !u.password && !raw.split('@')[0].slice(raw.indexOf('//') + 2).includes(':')) {
      const dec = b64decode(username);
      const idx = dec.indexOf(':');
      if (idx < 1) fail('SOCKS 认证信息无效');
      username = dec.slice(0, idx); password = dec.slice(idx + 1);
    }
    outbound = {
      protocol: 'socks',
      settings: { servers: [{ address: server, port: portNum, ...(username ? { users: [{ user: username, pass: password }] } : {}) }] },
    };
  } else {
    fail('暂不支持的节点格式（支持 vless://、vmess://、socks5://）');
  }
  return { protocol, server, port: portNum, name, outbound };
}

// ---------- xray 配置生成（照搬抖歪 xray-config）----------
function buildXrayConfig(nodeOutbound, listenPort) {
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535 || !nodeOutbound || !nodeOutbound.outbound) fail('配置参数无效');
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'matrix-local', listen: '127.0.0.1', port: listenPort, protocol: 'socks', settings: { udp: true } }],
    outbounds: [
      { tag: 'matrix-direct', protocol: 'freedom', settings: {} },
      { ...JSON.parse(JSON.stringify(nodeOutbound.outbound)), tag: 'matrix-node' },
    ],
    routing: { domainStrategy: 'AsIs', rules: [{ type: 'field', inboundTag: ['matrix-local'], outboundTag: 'matrix-node' }] },
  };
}

// ---------- xray 进程（照搬抖歪 xray-process）----------
function reservePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(e => e ? reject(e) : resolve(p)); });
  });
}

class XrayProcess {
  constructor({ executable, logDir }) { this.executable = executable; this.logDir = logDir || path.join(process.env.APPDATA || require('os').tmpdir(), 'TikTok直播工作台'); this.logPath = ''; this.child = null; this.cancelled = false; this.endpoint = null; this.exitTask = null; }

  async launch(configJson, testMode) {
    if (this.cancelled) throw new Error('节点启动已取消');
    // xray 26.x 不支持 -config -（stdin），写临时配置文件
    const tmpPath = path.join(require('os').tmpdir(), 'xraycfg-' + crypto.randomBytes(4).toString('hex') + '.json');
    fs.writeFileSync(tmpPath, JSON.stringify(configJson));
    const args = ['run', ...(testMode ? ['-test'] : []), '-config', tmpPath, '-format', 'json'];
    // v1.14.16 xray 日志落盘：stdio 不再全 ignore（节点失效/握手失败时无日志可查），
    // 写 %APPDATA%\TikTok直播工作台\xray_*.log（每次启动清理旧日志，只留最新）
    // 注意：createWriteStream 是异步打开（fd:null），spawn 不接受未就绪的 stream → 必须等 open 事件后再 spawn
    let stdioArr = ['ignore', 'ignore', 'ignore'];
    try {
      const logDir = this.logDir;
      fs.mkdirSync(logDir, { recursive: true });
      // 测速和常驻进程各留自己的日志，不删除仍被其他进程打开的文件。
      this.logPath = path.join(logDir, 'xray_' + (testMode ? 'test_' : '') + Date.now() + '_' + crypto.randomBytes(4).toString('hex') + '.log');
      const xlog = fs.createWriteStream(this.logPath, { flags: 'w' });
      await new Promise((res, rej) => { xlog.once('open', () => res()); xlog.once('error', (e) => rej(e)); });
      stdioArr = ['ignore', xlog, xlog];
      this.logStream = xlog;
    } catch (e) { console.error('[内置代理] 日志文件创建失败:', e.message); }
    const child = spawn(this.executable, args, { windowsHide: true, stdio: stdioArr });
    setTimeout(() => { try { fs.unlinkSync(tmpPath); } catch (e) {} }, 8000);
    this.child = child;
    const exitTask = new Promise(resolve => { child.once('error', () => resolve(-1)); child.once('close', code => { if (this.logStream) this.logStream.end(); resolve(code); }); });
    this.exitTask = exitTask;
    return { child, exited: exitTask };
  }

  // 先 -test 校验配置，通过后正式启动，轮询本地端口就绪
  async startWithNode(nodeLink, listenPort) {
    const parsed = parseNodeLink(nodeLink);
    const config = buildXrayConfig(parsed, listenPort);
    const testRun = await this.launch(config, true);
    let timer;
    try {
      const code = await Promise.race([testRun.exited, new Promise(r => { timer = setTimeout(() => r(-2), 12000); })]);
      if (code !== 0) { try { testRun.child.kill(); } catch (e) {} await testRun.exited; throw new Error('节点配置未通过内核校验'); }
    } finally { clearTimeout(timer); }
    const real = await this.launch(config, false);
    this.endpoint = { host: '127.0.0.1', port: listenPort };
    let failed = false;
    real.exited.then(code => { failed = true; if (this.onExit) this.onExit(code); });
    const deadline = Date.now() + 12000;
    while (Date.now() < deadline && !this.cancelled && !failed) {
      if (await new Promise(res => {
        const c = net.connect({ host: this.endpoint.host, port: listenPort });
        c.once('connect', () => { c.destroy(); res(true); });
        c.once('error', () => res(false));
        c.setTimeout(250, () => { c.destroy(); res(false); });
      })) return this.endpoint;
      await new Promise(r => setTimeout(r, 40));
    }
    await this.stop();
    throw new Error(failed ? '节点内核未能启动' : '节点内核启动超时');
  }

  async stop() {
    this.cancelled = true;
    if (this.child && this.child.exitCode === null) { try { this.child.kill(); } catch (e) {} }
    if (this.exitTask) await this.exitTask;
  }
}

// ---------- 运行时管理器（单节点：软件全局代理）----------
class XrayRuntime {
  constructor({ logDir } = {}) {
    this.logDir = logDir;
    this.proc = null;
    this.port = DEFAULT_PORT;
    this.activeLink = '';
  }
  async start(nodeLink) {
    await this.stop();
    const xrayPath = process.platform === 'darwin' ? require('./mac-platform').runtimePath('xray') : unpackedPath(path.join(__dirname, 'xray-portable', 'xray.exe'));
    if (!fs.existsSync(xrayPath)) throw new Error('内置 Xray 内核缺失，请准备当前平台运行工具');
    // 10888 被占用 → 探测一个空闲端口（尽量贴近）
    if (!await isPortFree(this.port)) {
      const alt = await reservePort();
      this.port = alt;
    } else { this.port = DEFAULT_PORT; }
    const proc = new XrayProcess({ executable: xrayPath, logDir: this.logDir });
    proc.onExit = (code) => {
      if (this.proc === proc) {
        console.log('[内置代理] Xray 已退出 PID=' + proc.child.pid + ' code=' + code);
        this.proc = null;
      }
    };
    const ep = await proc.startWithNode(nodeLink, this.port);
    this.proc = proc;
    this.activeLink = nodeLink;
    return ep;
  }
  async stop() { if (this.proc) { const p = this.proc; this.proc = null; await p.stop(); } }
  isRunning() { return !!(this.proc && this.proc.child && this.proc.child.exitCode === null); }
  endpoint() { return this.proc ? this.proc.endpoint : null; }
}

function isPortFree(p) {
  return new Promise(res => {
    const c = net.connect({ host: '127.0.0.1', port: p });
    c.once('connect', () => { c.destroy(); res(false); });
    c.once('error', () => res(true));
    c.setTimeout(500, () => { c.destroy(); res(true); });
  });
}

module.exports = { XrayRuntime, XrayProcess, parseNodeLink, buildXrayConfig, DEFAULT_PORT };
