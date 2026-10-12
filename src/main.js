// TikTok直播工作台 - Electron主进程
// v1.12.1：修复 CDP 捕获流程挂起（loadURL 超时 + 总超时 + 自动关窗）（CDP 监听直播页网络响应提取 rtmp）+ 捕获 watchDog 自动刷新重试
const { app, BrowserWindow, ipcMain, dialog, session, screen, net: electronNet, Notification } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto'); // v1.14.0 卡密授权：机器码哈希 / lic 加密
const os = require('os'); // v1.14.0 机器码 fallback
const fs = require('fs');
// 开发数据独立存放，避免覆盖正式安装版的账号与节点配置。
if (!app.isPackaged) {
  const devData = path.join(__dirname, '..', '.local');
  fs.mkdirSync(devData, { recursive: true });
  app.setPath('userData', devData);
}
const net = require('net');
const tls = require('tls');
const https = require('https'); // v1.12.37 补上（此前缺失导致 httpsJson 一直抛错被吞）
const zlib = require('zlib');
// ==================== v1.14.12 EPIPE 崩溃弹窗修复 ====================
// 现象：exe 从命令行/管道启动（或父进程拉起、调试工具包裹）时，stdout 是管道；管道另一端关闭后，
// console.log 的异步写错误（EPIPE broken pipe）会变成 uncaughtException（try/catch 抓不住异步写错误）
// → Electron 弹 "A JavaScript error occurred in the main process" 报错窗（用户实测遇到）
// 修复两层：
//  ① 非 TTY（管道）输出直接丢弃：stdout/stderr 不再真实写入，EPIPE 从根上消失（日志仍完整写 run.log 文件）
//  ② 全局 uncaughtException：EPIPE 类错误静默记录；其他未捕获异常写入日志而不弹窗（直播场景不被弹窗打断）
if (process.stdout && !process.stdout.isTTY) { try { process.stdout.write = () => false; } catch (e) {} }
if (process.stderr && !process.stderr.isTTY) { try { process.stderr.write = () => false; } catch (e) {} }
process.on('uncaughtException', (err) => {
  const _m = String((err && err.message) || err || '');
  try {
    if (/EPIPE|broken pipe|write after end/i.test(_m)) {
      fs.appendFileSync(path.join(app.getPath('userData'), 'run.log'), '[' + new Date().toISOString() + '] [EPIPE静默] ' + _m + '\n');
      return; // 管道断开：静默，不弹窗不退出
    }
    fs.appendFileSync(path.join(app.getPath('userData'), 'run.log'), '[' + new Date().toISOString() + '] [FATAL] ' + ((err && err.stack) || _m) + '\n');
  } catch (e) {}
});
// ==================== 卡密授权系统 v1.14.0（本地验证 / 一卡一机 / 永久有效）====================
// 卡密库：只存 SHA-256 哈希（明文卡密不在软件里，防提取）；激活文件绑定机器码，复制到别的电脑无法使用
const LICENSE_HASHES = [
  '57961038c232ef42a768c53ca1f8b15e25cf41e37af2b7f4537907d2973d8238',
  '711a5d6d5e5a0ae056815179fa3f1a83a7978902d240b87caa57efb3c92f8926',
  '2f4a9a5e969e235b70d76e814321dd54f6116ec34dde890df1b53431471d05e5',
  '74a01d694b95e3efa1074e0907ec18b17f7db4a80766887c9c952c7250902b12',
  '741b0ddc6dc1d5977907e35a2513ee62caa6ccd24f6eb54ac09c8cb9909a321c',
  '8b3e7bfa462cd95ed40d89909cfdd7edbd4546e7e6f8abbaa7e0a2d0de7a8b96',
  '979adcd9e814a37947533d7e4f98ded89ad61b6fbf75005d3a951c6a4925e1e9',
  '17a3bcb9a39b3683927964e26e2f4bd6e574c0436d2aa188577da633cdfd52eb',
  '56de25084b7f314c991ea81bb9f8388553c8ca0b82a8f9a1f894f9d5021169f1',
  'c9e8aa46afb5c8f4d72d622f698965c970247bb02d7797705f4eadceacdef487',
  '29367eb7683bf6c49c5a9a243ab586102298bccd62eac6228004f2307fe559a9',
  '1e5f7a03635cbc5d8c7125f750828110cf4a271f9f84b5dcdf2114ed39548fb9',
  '175aaad43f77a64fe8d55a089514c92bcf59732b25f6ca65e5f56830621fe305',
  '2097a8239eb798b8bb2fa4d60c271f8ac0cc1c82aca643e80aa102c73fd9dda2',
  'cc1a4f2e2f4cd6304b1134934a2b030565c03af86b18328d985ad97392779a6f',
  'cb1dde4329e2d4c70cce38440bbb90f0d4e712a77872c5ae66def72329fd230b',
  'fed991e015a57fac01221009bc94758d7c87c7374729b0d275a99d69d8d38ff1',
  '92647dad4aa6eefc16e2866628634952d05bfba606f9588077b9487613c2472b',
  '9017bd6e7a121fd0b1cc8d8130e79d487166b62b9d160b13f785b2bf2043f5ae',
  '26327c2a6a4a6a1843da1e02dd7abcc0ef06f092deae1ce8b4becf1147331dd7'
];
const LIC_KEY = crypto.createHash('sha256').update('TK-Live-Workbench|2026|auth|v1').digest(); // 32 字节 AES 密钥
let _machineCache = '';
function getMachineCode() {
  if (_machineCache) return _machineCache;
  let raw = '';
  try {
    const cpu = execSync('wmic cpu get ProcessorId /value', { timeout: 6000, windowsHide: true }).toString().match(/ProcessorId=(\S+)/i);
    const mb = execSync('wmic baseboard get SerialNumber /value', { timeout: 6000, windowsHide: true }).toString().match(/SerialNumber=(\S+)/i);
    const disk = execSync('wmic diskdrive get SerialNumber /value', { timeout: 6000, windowsHide: true }).toString().match(/SerialNumber=(\S+)/i);
    raw = (cpu ? cpu[1] : '') + '|' + (mb ? mb[1] : '') + '|' + (disk ? disk[1] : '');
  } catch (e) {}
  if (!raw || raw === '||') {
    // v1.14.7 Win11 24H2+ 已移除 wmic → 用 PowerShell CIM 拿 CPU/主板/磁盘序列号（无需管理员可拿 CPU+主板）
    try {
      const psOut = execSync('powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).ProcessorId + \'|\' + (Get-CimInstance Win32_BaseBoard).SerialNumber + \'|\' + (Get-CimInstance Win32_DiskDrive | Select-Object -First 1).SerialNumber"', { timeout: 12000, windowsHide: true }).toString().trim();
      if (psOut && psOut.split('|').filter(s => s && s.trim()).length >= 1) raw = psOut;
    } catch (e) {}
  }
  if (!raw || raw === '||') {
    try {
      const vol = execSync('vol C:', { timeout: 6000, windowsHide: true }).toString().match(/Volume Serial Number is ([0-9A-F-]+)/i);
      raw = os.hostname() + '|' + os.platform() + '|' + os.release() + '|' + (vol ? vol[1] : '');
    } catch (e2) {
      raw = os.hostname() + '|' + os.platform() + '|' + os.release();
    }
  }
  _machineCache = crypto.createHash('sha256').update('TK' + raw).digest('hex').slice(0, 32).toUpperCase();
  return _machineCache;
}
function licPath() {
  return path.join(app.isPackaged ? path.dirname(app.getPath('exe')) : app.getPath('userData'), 'activation.lic');
}
function licRead() {
  try {
    const data = fs.readFileSync(licPath());
    if (data.length < 29) return null;
    const iv = data.slice(0, 12), tag = data.slice(12, 28), ct = data.slice(28);
    const d = crypto.createDecipheriv('aes-256-gcm', LIC_KEY, iv);
    d.setAuthTag(tag);
    return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
  } catch (e) { return null; }
}
function licWrite(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', LIC_KEY, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj), 'utf8')), c.final()]);
  fs.writeFileSync(licPath(), Buffer.concat([iv, c.getAuthTag(), ct]));
}
function licenseState() {
  const m = getMachineCode();
  const lic = licRead();
  if (!lic) return { ok: false, reason: 'not_activated', machine: m };
  if (lic.m !== m) return { ok: false, reason: 'machine_mismatch', machine: m };
  return { ok: true, reason: 'ok', machine: m };
}
function activateLicense(code) {
  const c = String(code || '').trim().toUpperCase();
  if (!/^TK-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(c)) return { ok: false, reason: 'format' };
  const h = crypto.createHash('sha256').update(c).digest('hex');
  if (!LICENSE_HASHES.includes(h)) return { ok: false, reason: 'invalid' };
  licWrite({ m: getMachineCode(), c: h.slice(0, 16), t: Date.now() });
  return { ok: true, reason: 'ok' };
}
ipcMain.handle('license:check', async () => licenseState());
ipcMain.handle('license:activate', async (event, { code }) => activateLicense(code));
// ==================== 卡密授权系统结束 ====================
const { isStreamResponseUrl, extractStreamInfoFromBody } = require('./stream-capture'); // v1.12.0 抖歪移植
const { getSignatures, getFrameSignatures, checkSigner } = require('./signer-client'); // v1.12.34/1.12.50 抖歪同款：RapidAPI 签名服务（含 /framesign/batch 帧签名）
const { OBSEngine } = require('./obs-engine'); // v1.12.47 抖歪同款：OBS 引擎推流（OBSWebSocket 控制本机 OBS，替换 FFmpeg）
const { MediaEgress } = require('./media-egress'); // v1.12.49/1.12.50 抖歪同款：本机隧道转发推流（FFmpeg 推本机 → TCP 透传 TikTok，支持代理隧道）
const { FrameSigner, FlvSeiTransform } = require('./flv-sei'); // v1.12.50 抖歪同款：帧签名 SEI 注入（not_allowed 根治）
const { XrayRuntime, XrayProcess } = require('./xray-runtime'); // v1.13.11 抖歪同款：内置 xray 代理内核（不依赖桌面 v2/v2rayN）

// v1.12.47 运行日志落盘（远程诊断用）
// v1.14.6 修复：安装包版(asar)无法写入 __dirname/run.log（app.asar 只读）→ 改写到 userData（AppData\Roaming\TikTok直播工作台\run.log）
const RUN_LOG = path.join(app.getPath('userData'), 'run.log');
// v1.14.9 修复：ffmpeg stderr 原写死 D:/tk4k屏 本机路径（新电脑不存在→报错被吞，诊断看不到具体原因）→ 改写到 userData，随诊断包导出
const FF_STDERR = path.join(app.getPath('userData'), '_ffmpeg_stderr.txt');
function logToFile(...args) {
  try {
    const line = '[' + new Date().toISOString() + '] ' + args.map(a => (typeof a === 'string' ? a : (a instanceof Error ? a.message : JSON.stringify(a)))).join(' ') + '\n';
    fs.appendFileSync(RUN_LOG, line);
  } catch (e) {}
}
// v1.14.6 asar 安装版修复：spawn 是原生调用，不能使用 app.asar 内路径（磁盘上不存在）→ 重定向到 app.asar.unpacked
function unpackedPath(p) {
  const i = p.indexOf('app.asar');
  if (i !== -1 && p.indexOf('app.asar.unpacked') === -1) {
    return p.slice(0, i) + 'app.asar.unpacked' + p.slice(i + 8);
  }
  return p;
}
const _origLog = console.log;
console.log = (...args) => { try { _origLog(...args); } catch (e) {} logToFile(...args); };
const _origErr = console.error;
console.error = (...args) => { try { _origErr(...args); } catch (e) {} logToFile('ERR', ...args); };

// v1.13.11 内置 xray 代理（10888 专用端口，不依赖桌面 v2/v2rayN）：软件保存了节点 → 页面/API 走内置代理；无节点 → 直连（推流本就直连）
// 换电脑无需安装 v2：节点链接保存后，内置 xray.exe 直接起本地 SOCKS5 代理
const NODES_FILE = path.join(app.getPath('userData'), 'nodes.json');
const XRAY_PROXY_PORT = 10888;
function readNodesFile() {
  try {
    const d = JSON.parse(fs.readFileSync(NODES_FILE, 'utf8') || '[]');
    return Array.isArray(d) ? d.filter(n => n && typeof n.link === 'string' && n.link.trim()) : [];
  } catch (e) { return []; }
}
function writeNodesFile(nodes) {
  try { fs.writeFileSync(NODES_FILE, JSON.stringify(Array.isArray(nodes) ? nodes : [], null, 1)); } catch (e) {}
}
let _builtinProxyOn = false;
try { _builtinProxyOn = readNodesFile().length > 0; } catch (e) {}
// v1.14.5 页面窗口不再设全局代理（appendSwitch）：全局 10888 在 xray 启动失败时会让所有页面加载失败（登录黑屏）。
// 页面窗口一律按 applyProxyToWindow 探测结果走（内置 xray 10888 → 桌面 v2 10808 → 直连）。
// 仅保留主进程 API 的环境变量代理（有内置节点时走 10888，无节点时直连）。
let _proxyServer = _builtinProxyOn ? ('socks5://127.0.0.1:' + XRAY_PROXY_PORT) : null;
if (_proxyServer) {
  process.env.HTTPS_PROXY = _proxyServer;
  process.env.HTTP_PROXY = _proxyServer;
}

// v1.14.4 代理可用性探测：内置 xray(10888) → 桌面 v2(10808) → 直连（都没有代理就直连，避免黑屏）
let _effectiveProxy = _proxyServer; // 初始：有内置节点时默认 10888
function isPortOpen(port, ms) {
  return new Promise((res) => {
    const c = net.connect({ host: '127.0.0.1', port });
    c.once('connect', () => { c.destroy(); res(true); });
    c.once('error', () => res(false));
    c.setTimeout(ms || 500, () => { c.destroy(); res(false); });
  });
}
async function refreshEffectiveProxy() {
  try {
    if (await isPortOpen(XRAY_PROXY_PORT)) { _effectiveProxy = 'socks5://127.0.0.1:' + XRAY_PROXY_PORT; return; }
    if (await isPortOpen(10808)) { _effectiveProxy = 'socks5://127.0.0.1:10808'; return; }
    _effectiveProxy = null;
  } catch (e) { _effectiveProxy = null; }
}
// v1.14.17 代理出口实测（强化版）：socks5 CONNECT 成功 ≠ 数据链路通（节点 Reality 层失效时 CONNECT 被接受但 TLS 数据转发超时）
// → 改为真实 HTTPS 请求 generate_204（完整 TLS 握手 + 数据往返），5 秒超时，拿到 204 才算可用。
function testProxyEgress(port, timeoutMs) {
  return new Promise((resolve) => {
    import('socks-proxy-agent').then(({ SocksProxyAgent }) => {
      try {
        const agent = new SocksProxyAgent('socks5://127.0.0.1:' + port);
        const req = https.request({ hostname: 'www.google.com', path: '/generate_204', method: 'HEAD', agent }, (res) => {
          try { agent.destroy(); } catch (e) {}
          resolve(res.statusCode === 204);
        });
        req.on('error', () => { try { agent.destroy(); } catch (e) {} resolve(false); });
        req.setTimeout(timeoutMs || 5000, () => { try { req.destroy(new Error('timeout')); } catch (e) {} });
        req.end();
      } catch (e) { resolve(false); }
    }).catch(() => resolve(false));
  });
}
// v1.14.7 修复获取推流码慢/失败：v1.14.5 移除 appendSwitch 全局代理后，
// electronNet（httpsJson 查询房间号/推流码用的 Chromium 网络栈）走 defaultSession 且不读环境变量 → 直连 TikTok 被墙（ERR_CONNECTION_RESET/TIMED_OUT）。
// 这里把探测结果同步到 defaultSession：electronNet 走可用代理；无代理 → 直连（不会黑屏，行为与页面窗口 applyProxyToWindow 一致）。
function applyProxyToDefaultSession() {
  try {
    const ses = session.defaultSession;
    if (ses && ses.setProxy) {
      const p = _effectiveProxy;
      ses.setProxy(p ? { proxyRules: p, proxyBypassRules: '<local>;localhost;127.0.0.1;10.*;192.168.*' } : { mode: 'direct' }).catch(() => {});
    }
  } catch (e) {}
}
// 把探测结果应用到某个窗口的 session（页面加载走可用代理；无代理 → 直连）
function applyProxyToWindow(win) {
  try {
    const ses = win.webContents.session;
    if (ses && ses.setProxy) {
      const p = _effectiveProxy;
      ses.setProxy(p ? { proxyRules: p, proxyBypassRules: '<local>;localhost;127.0.0.1;10.*;192.168.*' } : { mode: 'direct' }).catch(() => {});
    }
  } catch (e) {}
}

// v1.14.5 一键导出诊断包：日志 + 代理状态 + 节点格式（uuid/pbk 打码）+ 账号摘要（不含 cookie 值）→ 桌面 txt
function maskNodeLink(link) {
  try {
    const s = String(link || '');
    if (/^vless:\/\//i.test(s) || /^vmess:\/\//i.test(s)) {
      const u = new URL(s);
      let out = s;
      if (u.username) out = out.replace(u.username, (u.username.slice(0, 6) || '') + '…uuid已打码');
      const pbk = u.searchParams.get('pbk');
      if (pbk) out = out.replace(pbk, 'PBK…已打码');
      const sid = u.searchParams.get('sid');
      if (sid) out = out.replace(sid, 'SID…已打码');
      const spx = u.searchParams.get('spx');
      if (spx) out = out.replace(spx, 'SPX…已打码');
      return out;
    }
    if (/^socks5?:\/\//i.test(s)) {
      const u = new URL(s);
      if (u.username) return s.replace(u.username + ':' + u.password, 'USER:PASS…已打码');
    }
    return s.length > 120 ? s.slice(0, 120) + '…' : s;
  } catch (e) { return String(link || '').slice(0, 120); }
}
ipcMain.handle('diagnostics:export', async () => {
  try {
    const lines = [];
    lines.push('=== TikTok直播工作台 诊断包 v' + app.getVersion() + ' ===');
    lines.push('导出时间: ' + new Date().toString());
    lines.push('系统: ' + process.platform + ' ' + process.arch + ' / Electron ' + process.versions.electron + ' / Node ' + process.versions.node);
    lines.push('软件目录: ' + __dirname);
    lines.push('用户数据: ' + app.getPath('userData'));
    lines.push('');
    lines.push('--- 代理状态 ---');
    lines.push('全局代理: ' + (_proxyServer || '未设置(直连)'));
    lines.push('生效探测代理: ' + (_effectiveProxy || '直连'));
    lines.push('端口探测: 10888=' + (await isPortOpen(XRAY_PROXY_PORT)) + ' 10808=' + (await isPortOpen(10808)));
    lines.push('xray 运行: ' + (xrayRuntime ? (xrayRuntime.isRunning() ? '运行中 ' + JSON.stringify(xrayRuntime.endpoint()) : '已初始化但未运行') : '未初始化'));
    lines.push('');
    lines.push('--- 节点（敏感参数已打码） ---');
    const nodes = readNodesFile();
    lines.push('节点数: ' + nodes.length);
    nodes.forEach((n, i) => lines.push('节点' + (i + 1) + ': ' + (n.name || '') + ' | ' + maskNodeLink(n.link)));
    lines.push('');
    lines.push('--- 账号摘要（不含 Cookie 值） ---');
    const accs = loadAccounts();
    const ids = Object.keys(accs);
    lines.push('账号数: ' + ids.length);
    ids.forEach(id => {
      const a = accs[id] || {};
      lines.push('账号' + id + ': name=' + (a.name || '') + ' loggedIn=' + !!a.loggedIn + ' cookies=' + (a.cookies ? a.cookies.length : 0) + ' signer=' + (a.signer && a.signer.apiKey ? '已配置' : '未配置') + ' useOBS=' + (a.useOBS === true ? '是' : '否') + ' autoReply=' + (a.autoReply === true ? '开' : '关'));
    });
    lines.push('');
    lines.push('--- FFmpeg 内置引擎检测 ---');
    (function ffDiag() {
      const cands = [
        path.join(process.resourcesPath, 'app', 'ffmpeg', 'bin', 'ffmpeg.exe'),
        path.join(process.resourcesPath, 'app.asar.unpacked', 'ffmpeg', 'bin', 'ffmpeg.exe'),
        path.join(__dirname, 'ffmpeg', 'bin', 'ffmpeg.exe'),
        path.join(app.getAppPath(), 'ffmpeg', 'bin', 'ffmpeg.exe'),
        'C:\\ffmpeg\\bin\\ffmpeg.exe',
        'C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe',
      ];
      const seen = {};
      cands.forEach(c => {
        try {
          if (!c || seen[c]) return;
          seen[c] = true;
          const ex = fs.existsSync(c);
          let info = '不存在';
          if (ex) {
            const sz = Math.round(fs.statSync(c).size / 1048576);
            try { execSync('"' + c + '" -version', { stdio: ['ignore', 'ignore', 'ignore'], timeout: 5000 }); info = '存在 ' + sz + 'MB 可执行'; }
            catch (e) { info = '存在 ' + sz + 'MB 不可执行(' + (e.code || e.message || '?') + ')'; }
          }
          lines.push('FFmpeg候选: ' + c + ' => ' + info);
        } catch (e) { lines.push('FFmpeg候选: ' + c + ' => 检测异常 ' + e.message); }
      });
      try {
        const { spawnSync } = require('child_process');
        const t = spawnSync('ffmpeg', ['-version'], { stdio: 'ignore', timeout: 5000 });
        lines.push('系统PATH ffmpeg: ' + (t && !t.error ? '可用' : '不可用'));
      } catch (e) { lines.push('系统PATH ffmpeg: 检测异常'); }
      try { lines.push('findFFmpeg() 结果: ' + (findFFmpeg() || 'null(未找到)')); }
      catch (e) { lines.push('findFFmpeg() 结果: 检测异常 ' + e.message); }
    })();
    lines.push('');
    lines.push('--- run.log 完整内容 ---');
    if (fs.existsSync(RUN_LOG)) {
      lines.push(fs.readFileSync(RUN_LOG, 'utf8'));
    } else {
      lines.push('(run.log 不存在)');
    }
    lines.push('');
    lines.push('--- FFmpeg stderr 最近记录（_ffmpeg_stderr.txt，截取最后 30KB） ---');
    if (fs.existsSync(FF_STDERR)) {
      const _st = fs.readFileSync(FF_STDERR, 'utf8');
      lines.push(_st.slice(-30000) || '(空)');
    } else {
      lines.push('(_ffmpeg_stderr.txt 不存在：推流失败时无 stderr 记录)');
    }
    lines.push('');
    lines.push('--- 诊断记录文件（风险告警/监控轮询/互动明细/xray 日志，各截取最后 8KB） ---');
    ['_risk_alerts.txt', '_poll_diag.txt', '_diag_chatitems.txt'].forEach(fn => {
      const _fp = path.join(app.getPath('userData'), fn);
      if (fs.existsSync(_fp)) {
        const _c = fs.readFileSync(_fp, 'utf8');
        lines.push('[' + fn + ']');
        lines.push(_c.slice(-8000) || '(空)');
      } else {
        lines.push('[' + fn + '] (不存在)');
      }
    });
    // v1.14.16 xray 内核日志（节点失效/握手失败定位用）：取最新一个 xray_*.log 尾部 8KB
    try {
      const _xdir = app.getPath('userData');
      const _xf = fs.readdirSync(_xdir).filter(f => /^xray_.*\.log$/.test(f)).sort().pop();
      if (_xf) {
        const _xc = fs.readFileSync(path.join(_xdir, _xf), 'utf8');
        lines.push('[xray 内核日志: ' + _xf + ']');
        lines.push(_xc.slice(-8000) || '(空)');
      } else {
        lines.push('[xray 内核日志] (不存在)');
      }
    } catch (e) { lines.push('[xray 内核日志] 读取失败: ' + e.message); }
    const outPath = path.join(app.getPath('desktop'), 'TK诊断包_v' + app.getVersion() + '_' + Date.now() + '.txt');
    fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
    console.log('[诊断包] 已导出:', outPath);
    return { success: true, path: outPath };
  } catch (e) {
    console.error('[诊断包] 导出失败:', e.message);
    return { success: false, error: e.message };
  }
});

let mainWindow = null;
const streamProcesses = {};    // accountId -> ffmpeg process
const streamEncoderFallback = {}; // v1.14.9 accountId -> true（nvenc 实际编码失败后本会话强制 libx264）
const mediaEgresses = {};      // v1.12.49 accountId -> MediaEgress（抖歪式本机隧道）
const frameSigners = {};       // v1.12.50 accountId -> FrameSigner（抖歪式帧签名）
const frameSignerTransforms = {}; // v1.12.50 accountId -> FlvSeiTransform
const streamRooms = {};        // v1.12.10 accountId -> 软件推流的直播间 roomId（监控跟随观众互动所在直播间）
const streamKeys = {};         // v1.12.11 accountId -> 推流 streamKey（停止推流时关房间用）
const streamUids = {};         // v1.12.50 accountId -> 主播 uid（帧签名 binding 用）
const lastSignerInfo = {};     // v1.12.36 accountId -> 签名服务最近自动生成信息（软件内可见）
const signerCache = {};        // v1.12.37 accountId -> { headers, at } 签名缓存 60s（RapidAPI 免费额度限流，短时复用）
const accountWindows = {};     // accountId -> [BrowserWindow]
const loginPollers = {};       // accountId -> interval 登录态/推流码检测
const loginCookieSaved = {};   // v1.12.32 accountId -> bool Cookie 已保存过（避免重复抓取，且保存后不退出轮询器继续扫描）
const scanRetry = {};          // accountId -> { stall, phase, refreshCount, entryCount } 推流码扫描自动重试状态
const autoGoLiveFlags = {};    // accountId -> bool 是否允许自动点击「手机直播」入口
const autoCloseFlags = {};     // accountId -> bool 抓到推流码后自动关闭直播中心窗口
let xrayRuntime = null;        // v1.13.11 内置 xray 代理运行时（XrayRuntime 实例）
const autoStreamTimers = {};   // v1.13.11 accountId -> 自动推流倒计时 timer（等待平台释放手机推流权后自动推流）
const streamStartPayloads = {}; // v1.13.12 accountId -> 最近一次推流参数（duplicate 自动重试复用）
const streamRetries = {};     // v1.13.12 accountId -> { left } duplicate 自动重试剩余次数
const streamStopIntent = {};  // v1.14.11 accountId -> bool 主动停止意图（区分"kill 旧进程"与"被动退出"，避免旧进程 close 误清重试链/误发 stopped）
const streamStarting = {};    // v1.14.13 accountId -> bool 推流启动互斥（防按钮连点/手动+自动重试叠加 → 多 FFmpeg 并发互相杀 → not_allowed 风暴）

// TikTok 登录态 Cookie 关键名
const AUTH_COOKIE_NAMES = ['sessionid', 'sessionid_ss', 'sid_tt', 'sid_tt_ss', 'uid_tt', 'uid_tt_ss', 'sessionid_legacy'];
const COOKIE_DOMAINS = ['.tiktok.com', 'tiktok.com', 'www.tiktok.com', '.livecenter.tiktok.com'];

// TikTok LIVE Studio 官方客户端真实 UA（从用户本机官方客户端 1.36.6 提取逻辑：默认 UA + "TikTokLIVEStudio/{版本}" 追加）。
// 实测：普通浏览器 UA 访问 livecenter 会被重定向回首页引导下载客户端；带 TikTokLIVEStudio 标记后 producer/直播中心完整放行进入登录流程。
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) TikTokLIVEStudio/1.36.6 Chrome/126.0.0.0 Electron/30.0.0 Safari/537.36';

// 运行进度上报：抓推流码/登录流程阶段进度 → 主窗口日志区显示百分比
function sendProgress(accountId, pct, message) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('tiktok:progress', {
      accountId, pct: Math.max(0, Math.min(100, pct)), message: message || '',
      ts: Date.now(),
    });
  }
  console.log(`[进度] 房间${accountId} ${pct}% ${message || ''}`);
}

// ============================================================
// 每账号独立会话分区
// ============================================================
function accountPartition(accountId) { return 'persist:room-' + accountId; }
function accountSession(accountId) { return session.fromPartition(accountPartition(accountId)); }

// ============================================================
// 账号数据落盘
// ============================================================
function accountsFile() { return path.join(app.getPath('userData'), 'accounts.json'); }
function loadAccounts() {
  try { return JSON.parse(fs.readFileSync(accountsFile(), 'utf8')); } catch (e) { return {}; }
}
function saveAccounts(data) {
  try {
    fs.mkdirSync(path.dirname(accountsFile()), { recursive: true });
    fs.writeFileSync(accountsFile(), JSON.stringify(data, null, 2));
  } catch (e) { console.error('[账号数据] 保存失败:', e.message); }
}

// ============================================================
// 窗口跟踪
// ============================================================
function trackWindow(accountId, win) {
  if (!accountWindows[accountId]) accountWindows[accountId] = [];
  accountWindows[accountId].push(win);
  win.on('closed', () => {
    accountWindows[accountId] = (accountWindows[accountId] || []).filter(w => w !== win && !w.isDestroyed());
    if (accountWindows[accountId].length === 0) delete accountWindows[accountId];
  });
}
function closeAccountWindows(accountId) {
  (accountWindows[accountId] || []).slice().forEach(w => {
    try { if (!w.isDestroyed()) w.close(); } catch (e) {}
  });
  delete accountWindows[accountId];
}

// 每个账号的窗口一律新建，绝不复用；不设父窗口，完全独立
function createAccountWindow(accountId, opts) {
  const win = new BrowserWindow({
    width: opts.width || 1200,
    height: opts.height || 820,
    title: opts.title || 'TikTok直播工作台',
    modal: false,
    backgroundColor: '#16182d',
    // v1.11.0 支持 show:false（监控数据窗口后台隐藏扫描，不弹给用户看）
    show: opts.show !== undefined ? !!opts.show : true,
    webPreferences: {
      partition: accountPartition(accountId),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      // v1.13.15 监控数据窗口用 preload 注入采集（页面加载即运行，绕过 executeJavaScript 失败）
      ...(opts.preload ? { preload: opts.preload } : {}),
      // v1.12.40 后台不节流（隐藏监控窗口 DOM 实时更新，点赞/评论/进场不漏抓）
      backgroundThrottling: false,
    },
  });
  win.setMenuBarVisibility(false);
  trackWindow(accountId, win);
  // v1.14.4 页面窗口按探测结果应用代理（无可用代理 → 直连，避免登录页黑屏）
  applyProxyToWindow(win);
  return win;
}

// ============================================================
// 主窗口
// ============================================================
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1180,
    minHeight: 680,
    title: 'TikTok直播工作台',
    backgroundColor: '#16182d',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile('index.html');
  if (process.argv.includes('--dev')) mainWindow.webContents.openDevTools();
  mainWindow.on('closed', () => {
    Object.keys(streamProcesses).forEach(id => stopStream(id));
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  // v1.14.11 run.log 轮转：每次启动把旧日志归档为 run.log.old，新会话从空开始
  // （修复：旧版本运行期间写入的"风险扫描/风险告警"等历史日志残留，用户误以为当前版本仍开启风险功能）
  try {
    if (fs.existsSync(RUN_LOG)) {
      const _old = path.join(app.getPath('userData'), 'run.log.old');
      try { if (fs.existsSync(_old)) fs.unlinkSync(_old); } catch (e) {}
      fs.renameSync(RUN_LOG, _old);
    }
  } catch (e) {}
  // v1.13.11 内置 xray 代理启动（有节点时）：页面/API 全部走内置代理，无需桌面 v2
  // v1.14.18 按用户要求恢复：固定使用第一个节点（不做启动出口验证），换节点时用户手动在软件里调整/测试
  try {
    const _savedNodes = readNodesFile();
    if (_savedNodes.length) {
      const _nodeLink = _savedNodes[0].link;
      if (!xrayRuntime) xrayRuntime = new XrayRuntime();
      const ep = await xrayRuntime.start(_nodeLink);
      console.log('[内置代理] 已启动', ep.host + ':' + ep.port, '节点', (_savedNodes[0].name || _nodeLink.slice(0, 40)));
    } else {
      console.log('[内置代理] 无保存节点，走直连（推流直连正常；页面直连 TikTok 实测可用）');
    }
  } catch (e) {
    console.error('[内置代理] 启动失败:', e.message, '（若页面无法访问 TikTok，请更换节点或删除节点后重启软件改直连）');
  }
  // v1.14.4 探测最终可用代理（内置 xray → 桌面 v2 → 直连），登录/监控等页面窗口按此走代理
  await refreshEffectiveProxy();
  applyProxyToDefaultSession(); // v1.14.7 修复：electronNet（获取推流码/查询房间号）走 defaultSession 代理
  console.log('[代理] 生效代理: ' + (_effectiveProxy ? _effectiveProxy : '直连（无可用代理）'));
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on('window-all-closed', () => {
  Object.keys(streamProcesses).forEach(id => stopStream(id));
  if (process.platform !== 'darwin') app.quit();
});

// ============================================================
// Cookie 提取 / 检测 / 保存
// ============================================================
function pickCookie(c) {
  return { name: c.name, value: c.value, domain: c.domain, path: c.path || '/', secure: !!c.secure, httpOnly: !!c.httpOnly, expirationDate: c.expirationDate };
}

async function captureCookies(accountId, accountName, win) {
  try {
    const cookies = await win.webContents.session.cookies.get({});
    if (!cookies || cookies.length === 0) return null;
    const data = loadAccounts();
    const prev = data[accountId] || {};
    const savedCookies = cookies
      .filter(c => c.value && COOKIE_DOMAINS.some(d => (c.domain || '').endsWith(d.replace(/^\./, '')) || d === c.domain))
      .map(pickCookie);
    data[accountId] = {
      // v1.14.3 保留原有配置字段（签名服务/自动互动/使用OBS等），登录只更新登录态与 Cookie
      ...(prev && typeof prev === 'object' ? prev : {}),
      name: accountName || prev.name || '',
      cookies: savedCookies,
      cookieCount: savedCookies.length,
      capturedAt: Date.now(),
      loggedIn: true,
    };
    saveAccounts(data);
    sendLoginState(accountId, data[accountId]);
    return data[accountId];
  } catch (e) {
    console.error('[Cookie] 抓取失败:', e.message);
    return null;
  }
}

function sendLoginState(accountId, info) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('tiktok:loginStateChanged', {
      accountId,
      loggedIn: !!(info && info.loggedIn),
      cookieCount: info ? (info.cookieCount || 0) : 0,
      capturedAt: info ? info.capturedAt : null,
      name: info ? (info.name || '') : '',
    });
  }
}

// ============================================================
// 登录检测 + 自动抓推流码（每账号独立窗口）
// ============================================================
// 深度页面扫描脚本：递归 iframe / shadow DOM，提取推流码并自动点击「获取推流码」等按钮
const SCAN_STREAM_SCRIPT = `(function(){
  var foundRtmp = null, foundStreamKey = null, clicked = null, hint = '';
  var visited = new Set();
  function scanDoc(doc, depth) {
    if (!doc || visited.has(doc)) return;
    visited.add(doc);
    try {
      var root = doc.documentElement || doc;
      if (!root) return;
      var bodyText = (doc.body ? doc.body.innerText : '') || '';
      // 1) 所有 input 的 value（推流地址/推流密钥/推流码）
      var inputs = root.querySelectorAll ? root.querySelectorAll('input') : [];
      for (var i = 0; i < inputs.length; i++) {
        var v = (inputs[i].value || '').trim();
        if (!v) continue;
        if (!foundRtmp && /^rtmps?:\\/\\//.test(v)) foundRtmp = v;
        if (!foundStreamKey && /^stream-[a-zA-Z0-9_\\-?&=.%]{10,}/.test(v)) foundStreamKey = v;
        if (!foundStreamKey && /^[a-zA-Z0-9_\\-?&=.%]{40,}$/.test(v) && v.indexOf('://') < 0 && bodyText.indexOf('stream') > -1) {
          // 纯推流密钥输入框（页面含 stream 字样时兜底）
          var lbl = (inputs[i].closest && inputs[i].closest('label, div')) ? (inputs[i].closest('label, div').innerText || '') : '';
          if (/key|密钥|推流/i.test(lbl)) foundStreamKey = v;
        }
      }
      // 2) 标签邻近抓取（Server URL / Stream Key 等）
      if (!foundRtmp || !foundStreamKey) {
        var els = root.querySelectorAll ? root.querySelectorAll('label, div, span, p, h1, h2, h3, h4, dt, dd') : [];
        for (var j = 0; j < els.length; j++) {
          var t = (els[j].innerText || '').trim();
          if (!t || t.length > 200) continue;
          if (!foundRtmp && /Server URL|推流地址|推流服务器|RTMP|server url/i.test(t)) {
            var box = els[j].closest ? (els[j].closest('div, td, li') || els[j].parentElement) : els[j].parentElement;
            if (box) {
              var inp = box.querySelector('input');
              if (inp && inp.value && /^rtmps?:\\/\\//.test(inp.value.trim())) foundRtmp = inp.value.trim();
              else {
                var t2 = box.innerText || '';
                var m = t2.match(/rtmps?:\\/\\/[^\\s"'<>]+/);
                if (m) foundRtmp = m[0];
              }
            }
          }
          if (!foundStreamKey && /Stream ?Key|推流密钥|推流码|stream key/i.test(t)) {
            var box2 = els[j].closest ? (els[j].closest('div, td, li') || els[j].parentElement) : els[j].parentElement;
            if (box2) {
              var inp2 = box2.querySelector('input');
              if (inp2 && inp2.value && /^stream-/.test(inp2.value.trim())) foundStreamKey = inp2.value.trim();
              else {
                var t3 = box2.innerText || '';
                var m2 = t3.match(/stream-[a-zA-Z0-9_\\-?&=.%]{20,}/);
                if (m2) foundStreamKey = m2[0];
              }
            }
          }
          if (foundRtmp && foundStreamKey) break;
        }
      }
      // 3) 正文正则兜底
      if (!foundRtmp) {
        var mm = bodyText.match(/rtmps?:\\/\\/[^\\s"'<>]+/g);
        if (mm && mm.length) foundRtmp = mm[0];
      }
      if (!foundStreamKey) {
        var m2 = bodyText.match(/stream-[a-zA-Z0-9_\\-?&=.%]{20,}/);
        if (m2) foundStreamKey = m2[0];
      }
      // 4) 页面未显示推流码时自动点击入口（推进队列：获取推流码 → 手机直播 → Stream to PC → 第三方/OBS → Go LIVE/开始直播 → 直播管理）
      if (!foundStreamKey && depth < 3) {
        try {
          var btns = root.querySelectorAll ? Array.prototype.slice.call(root.querySelectorAll('button, [role="button"], [data-e2e], a, [data-testid], [class*="button"], [class*="btn"], [class*="cta"], [aria-label], [title]')) : [];
          var clickQueue = [
            ['获取推流码', /获取推流码|get stream key|生成推流码|取得推流碼|show stream key|stream key/i],
            ['手机直播', /手机直播|手機直播|Go LIVE from [Pp]hone|LIVE from [Pp]hone|Start Live.*[Pp]hone|^[Pp]hone[\\s:]|直播至手机|直播至手機/i],
            ['Stream to PC', /stream to pc|cast to pc|stream to computer|連接到? ?(?:PC|電腦)|連接至? ?(?:PC|電腦)|connect to (?:pc|computer)|投屏|串流到|stream to device/i],
            ['第三方软件', /第三方軟?件|third[- ]party|external encoder|obs[\\s]|使用第三方/i],
            ['开始直播', /^Go LIVE$|^Go live$|^LIVE$|^開始直播$|^开始直播$|^开始$|^開始$|开始直播|開始直播|Start Live|開播|开播/i],
            ['直播管理', /直播设置|直播設定|直播管理|直播中心|Live Setup|Streaming Setup|Broadcast|LIVE Setup/i]
          ];
          var proceed = true;
          for (var qi = 0; qi < clickQueue.length && proceed; qi++) {
            var q = clickQueue[qi];
            var key = 'tkc_click_' + qi;
            if (sessionStorage.getItem(key)) continue;
            var hit = null;
            for (var bi = 0; bi < btns.length; bi++) {
              var b = btns[bi];
              var tx = ((b.innerText || b.textContent || '').trim() || '').replace(/\s+/g, ' ');
              var attrText = ((b.getAttribute && (b.getAttribute('aria-label') || b.getAttribute('title') || b.getAttribute('data-e2e') || '')) || '').replace(/\s+/g, ' ');
              if (tx.length === 0 && attrText.length === 0) continue;
              if (tx.length > 80) continue;
              var hay = (tx + ' ' + attrText).trim();
              if (hay.length === 0) continue;
              if (q[1].test(hay)) { hit = b; break; }
            }
            if (hit) {
              try { hit.click(); } catch(e) {}
              sessionStorage.setItem(key, '1');
              clicked = q[0];
              proceed = false; // 每次轮询只点一步，防页面连锁跳转
            }
          }
          if (!clicked) { sessionStorage.clear(); }
        } catch(e) {}
      }
      // 5) 递归 iframe（同源）与 open shadow root
      try {
        var frames = root.querySelectorAll ? root.querySelectorAll('iframe') : [];
        for (var k = 0; k < frames.length; k++) {
          try { if (frames[k].contentDocument) scanDoc(frames[k].contentDocument, depth + 1); } catch(e) {}
        }
      } catch(e) {}
      try {
        var shadows = root.querySelectorAll ? root.querySelectorAll('*') : [];
        for (var s = 0; s < shadows.length; s++) {
          try { if (shadows[s].shadowRoot) scanDoc(shadows[s].shadowRoot, depth + 1); } catch(e) {}
        }
      } catch(e) {}
    } catch(e) {}
  }
  scanDoc(document, 0);
  return { rtmp: foundRtmp, streamKey: foundStreamKey, url: window.location.href, clicked: clicked, hint: hint };
})()`;

// 检测 livecenter 页面内的真实登录状态（比 URL 判断可靠：失效 Cookie 也可能停在 /producer）
const PAGE_LOGIN_SCRIPT = `(function(){
  var state = 'unknown';
  try {
    var all = document.querySelectorAll('button, a, [role="button"], [data-testid]');
    for (var i = 0; i < all.length; i++) {
      var t = ((all[i].innerText || all[i].textContent || '').trim() || '').replace(/\\s+/g, ' ');
      if (t.length > 0 && t.length < 24 && /^(Log ?in|Sign ?in|登录|Log In|Sign In)$/i.test(t)) { state = 'logged_out'; break; }
      if (t.length > 0 && t.length < 40 && /^(Create account|Sign up|注册)$/i.test(t)) { state = 'logged_out'; }
    }
  } catch(e) {}
  if (state === 'unknown') {
    try {
      var bt = (document.body ? document.body.innerText : '') || '';
      var hasUser = /@[a-zA-Z0-9_.]{2,}/.test(bt) || !!document.querySelector('[data-e2e="producer-header-account"], [data-e2e="user-avatar"], [data-e2e="account-avatar"], [class*="avatar"], [class*="user-menu"]');
      if (hasUser) state = 'logged_in';
    } catch(e) {}
  }
  return state;
})()`;

function startLoginMonitor(accountId, accountName, win, opts) {
  const mode = (opts && opts.mode) || 'mobile';
  const autoCloseLogin = !!(opts && opts.autoCloseLogin);
  const autoCloseOnKey = !!(opts && opts.autoCloseOnKey);
  if (loginPollers[accountId]) { clearInterval(loginPollers[accountId]); delete loginPollers[accountId]; }

  loginPollers[accountId] = setInterval(async () => {
    if (!win || win.isDestroyed()) {
      clearInterval(loginPollers[accountId]);
      delete loginPollers[accountId];
      return;
    }
    try {
      const urlNow = win.webContents.getURL() || '';
      if (urlNow.includes('livecenter.tiktok.com') || urlNow.includes('tiktok.com/login') || urlNow.includes('www.tiktok.com')) {
        sendProgress(accountId, 40, '页面加载中，检测登录状态...');
      }
      const cookies = await win.webContents.session.cookies.get({});
      const now = Date.now() / 1000;
      // 只认未过期的登录 Cookie（过期 Cookie 会导致登录窗口被误关）
      const auth = cookies.filter(c => c.value && AUTH_COOKIE_NAMES.includes(c.name) && (!c.expirationDate || c.expirationDate > now));
      if (auth.length > 0) {
        const url = win.webContents.getURL() || '';
        const loaded = url.startsWith('http') && !win.webContents.isLoading();
        if (loaded && url.includes('tiktok.com')) {
          // 登录页 / 认证页 = 未登录，绝不能自动关窗
          if (/\/login\b|\/auth\/|enter_from=live_center/.test(url)) {
            sendProgress(accountId, 30, '等待登录：请在窗口内登录 TikTok（成功后自动保存并关闭）');
          } else {
            // 用页面内真实登录态判断（失效 Cookie 也可能停在 /producer，URL 判断不可靠）
            let pageLogin = 'unknown';
            try { pageLogin = await Promise.race([win.webContents.executeJavaScript(PAGE_LOGIN_SCRIPT), new Promise(r => setTimeout(() => r('timeout'), 5000))]); } catch (e) {}
            if (pageLogin === 'logged_in') {
              // v1.12.32 Cookie 只抓一次；保存后不退出轮询器（扫描通道需要窗口持续扫描推流码，之前 return 导致扫描永远不跑卡 60%）
              if (!loginCookieSaved[accountId]) {
                sendProgress(accountId, 55, '检测到已登录，自动抓取 Cookie...');
                const info = await captureCookies(accountId, accountName, win);
                if (info) {
                  console.log('[登录] 房间', accountId, 'Cookie 已自动抓取，共', info.cookieCount, '条');
                  sendProgress(accountId, 60, 'Cookie 已自动保存（' + info.cookieCount + ' 条）');
                  loginCookieSaved[accountId] = true;
                }
              }
              if (autoCloseLogin && loginCookieSaved[accountId]) {
                console.log('[登录] 房间', accountId, '登录成功，自动关闭登录窗口');
                sendProgress(accountId, 65, '登录成功，自动关闭登录窗口');
                clearInterval(loginPollers[accountId]);
                delete loginPollers[accountId];
                try { if (win && !win.isDestroyed()) win.close(); } catch (e) {}
                return;
              }
            } else if (pageLogin === 'logged_out') {
              console.log('[登录] 房间', accountId, '页面显示未登录，等待用户重新登录');
              sendProgress(accountId, 45, '页面未登录：请在窗口内完成登录（登录成功后自动抓 Cookie 并关窗）');
            }
          }
        }
      } else {
        if ((urlNow.includes('tiktok.com/login') || urlNow.includes('livecenter'))) {
          sendProgress(accountId, 30, '等待登录：请在窗口内登录 TikTok（成功后自动保存并关闭）');
        }
      }

      // 推流码扫描（直播中心页面：含 iframe/shadow，自动点击获取推流码；登录页 redirect_url 参数含 livecenter 需排除）
      const urlForScan = win.webContents.getURL() || '';
      if (urlForScan.includes('livecenter') && !/\/login\b|\/auth\//.test(urlForScan)) {
        try {
          // v1.12.26 扫描脚本加 8s 超时（页面 busy/Service Worker 干扰会让 executeJavaScript 永久挂起 → 轮询器卡死）
          const result = await Promise.race([
            win.webContents.executeJavaScript(SCAN_STREAM_SCRIPT),
            new Promise(r => setTimeout(() => r({ __timeout: true }), 8000)),
          ]);
          if (result && result.__timeout) {
            sendProgress(accountId, 70, '正在扫描直播中心页面查找推流码（页面响应慢，已超时跳过本轮）...');
          } else if (result && (result.rtmp || result.streamKey)) {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('tiktok:streamKeyFound', {
                accountId,
                rtmpUrl: result.rtmp || '',
                streamKey: result.streamKey || '',
                source: 'phone_live',
              });
            }
            console.log('[推流码] 房间', accountId, '已抓取 rtmp=', !!result.rtmp, 'key=', !!result.streamKey);
            sendProgress(accountId, 100, '推流码获取成功：已自动回填并关闭窗口');
            // 手机直播推流码获取成功：立即自动关闭直播中心窗口（用户要求）
            if (autoCloseOnKey) {
              clearInterval(loginPollers[accountId]);
              delete loginPollers[accountId];
              try { if (win && !win.isDestroyed()) win.close(); } catch (e) {}
            }
          } else if (result && result.clicked) {
            console.log('[推流码] 房间', accountId, '已自动点击「' + result.clicked + '」，等待页面显示推流码');
            sendProgress(accountId, 75, '已自动点击「' + result.clicked + '」，等待页面显示推流码...');
            // 有进展：重置无进展计数
            if (scanRetry[accountId]) scanRetry[accountId].stall = 0;
          } else {
            // 自动重试循环：连续无进展 → 自动刷新 / 切换入口，直到拿到推流码
            // refreshCount = 窗口刷新次数，entryCount = 换入口次数（日志区展示）
            scanRetry[accountId] = scanRetry[accountId] || { stall: 0, phase: 0, refreshCount: 0, entryCount: 0 };
            const rs = scanRetry[accountId];
            rs.stall++;
            if (rs.stall >= 6) { // ~12 秒无任何进展
              rs.stall = 0;
              rs.phase++;
              try { await Promise.race([win.webContents.executeJavaScript('try{sessionStorage.clear()}catch(e){}'), new Promise(r => setTimeout(() => r(), 3000))]); } catch (e) {}
              if (rs.phase === 1) {
                rs.refreshCount++;
                sendProgress(accountId, 78, '界面无推流码入口，自动刷新重试（第' + rs.refreshCount + '次，窗口刷新 ' + rs.refreshCount + ' 次 · 换入口 ' + rs.entryCount + ' 次）...');
                try { win.webContents.reload(); } catch (e) {}
              } else if (rs.phase === 2) {
                rs.entryCount++;
                sendProgress(accountId, 80, '刷新无进展，切换入口到直播中心首页重试（窗口刷新 ' + rs.refreshCount + ' 次 · 换入口 ' + rs.entryCount + ' 次）...');
                try { await win.loadURL('https://livecenter.tiktok.com/', { userAgent: UA }); } catch (e) {}
              } else if (rs.phase === 3) {
                rs.entryCount++;
                sendProgress(accountId, 82, '再次切换回开播页面重试（窗口刷新 ' + rs.refreshCount + ' 次 · 换入口 ' + rs.entryCount + ' 次）...');
                try { await win.loadURL('https://livecenter.tiktok.com/producer', { userAgent: UA }); } catch (e) {}
              } else {
                sendProgress(accountId, 85, '自动重试已完成（窗口刷新 ' + rs.refreshCount + ' 次 · 换入口 ' + rs.entryCount + ' 次），请在窗口内手动点击「开始直播 / Go LIVE」获取推流码（获取成功后自动回填）');
              }
            } else {
              const rs2 = scanRetry[accountId] || { refreshCount: 0, entryCount: 0 };
              sendProgress(accountId, 70, '正在扫描直播中心页面查找推流码（' + rs.stall + '/6 · 窗口刷新 ' + rs2.refreshCount + ' 次 · 换入口 ' + rs2.entryCount + ' 次）...');
            }
          }
        } catch (e) { /* 页面加载中 */ }
      }
    } catch (e) { /* 忽略瞬时错误 */ }
  }, 2000);
}

// ============================================================
// IPC：Cookie 登录 / 独立窗口 / 自动推流
// ============================================================
// 已保存 Cookie 预注入（打开窗口前先写入，避免重复登录）
async function injectSavedCookies(accountId, ses) {
  try {
    const data = loadAccounts();
    const info = data[accountId];
    if (!info || !info.cookies || info.cookies.length === 0) return false;
    let n = 0;
    const now = Date.now() / 1000;
    for (const c of info.cookies) {
      try {
        // 跳过已过期 Cookie
        if (c.expirationDate && c.expirationDate < now) continue;
        await ses.cookies.set({
          url: 'https://www.tiktok.com' + (c.path || '/'),
          name: c.name, value: c.value, domain: c.domain || '.tiktok.com',
          path: c.path || '/', secure: !!c.secure, httpOnly: !!c.httpOnly,
          expirationDate: c.expirationDate,
        });
        n++;
      } catch (e) {}
    }
    console.log('[Cookie] 房间', accountId, '已预注入', n, '条 Cookie');
    return n > 0;
  } catch (e) { return false; }
}

ipcMain.handle('tiktok:openLogin', async (event, { accountId, accountName, autoCloseLogin }) => {
  sendProgress(accountId, 15, '正在打开独立登录窗口（TikTok LIVE Studio 通道）...');
  const win = createAccountWindow(accountId, {
    title: 'TikTok 登录 · 房间' + accountId + (accountName ? ' · @' + accountName : ''),
    width: 1200, height: 820,
  });
  // 登录窗口不注入旧 Cookie：旧失效 Cookie 会引发 producer 服务端错误，登录流程必须是全新会话
  // v1.14.3 只清 cookies、保留 localstorage（设备标识 ttwid 等）——清了会变成"全新设备"，TikTok 会话极短 → 登录后自动掉线
  try { await win.webContents.session.clearStorageData({ storages: ['cookies'] }); } catch (e) {}
  // v1.14.4 登录前再探测一次代理并应用（内置 xray → 桌面 v2 → 直连；无代理直连，确保登录页能加载）
  await refreshEffectiveProxy();
  applyProxyToWindow(win);
  try {
    await win.loadURL('https://livecenter.tiktok.com/producer', { userAgent: UA });
  } catch (e) { console.error('[登录窗口] 加载失败:', e.message); }
  const data = loadAccounts();
  const info = data[accountId];
  if (info && info.loggedIn) sendLoginState(accountId, info);
  startLoginMonitor(accountId, accountName, win, { autoCloseLogin: autoCloseLogin !== false });
  return { success: true, message: '已新建独立登录窗口（房间' + accountId + '），登录后自动抓取 Cookie 并自动关闭窗口' };
});

// ============================================================
// v1.6.1 野路子主通道：webcast API 直接创建直播间获取推流码
// 原理：网页端 UI 被服务端按账号锁定（只有「取得 LIVE Studio」按钮，点啥都跳回首页），
// 但 webcast API 层权限完全开放。实测（账号 vivianer549）：
//   POST https://webcast.tiktok.com/webcast/room/create/  → 200 创建直播间成功
//   响应 stream_url.rtmp_push_url = 完整推流地址（含签名），stream_id_str → Stream Key = 'stream-' + stream_id
// 全程隐藏窗口 + 已登录 Cookie + 页面上下文 fetch（同源 CORS 放行），无需任何页面点击，不卡界面。
// ============================================================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const PAGE_AUTH_CHECK_SCRIPT = `(function(){
  // v1.12.21 通用化：sessionid/sid_tt 多为 HttpOnly（document.cookie 看不到）→ 原检查永远"未就绪"误判；改判任一 cookie 存在即可
  try { return (document.cookie || '').length > 20 ? 'logged_in' : 'not_logged'; }
  catch (e) { return 'unknown'; }
})()`;

// v1.7.0 拿码脚本（官方通道链路，2026-10-04 实测全链路验证通过）：
// ① 手机 App 已开播（Device camera）时：POST /webcast/room/create/ 创建新直播间 B
//    → create 后 B 成为账号「当前直播间」（观众入口 https://tiktok.com/@<user>/live 指向 B）
//    → GET /webcast/room/info/?room_id=B 拿 B 的完整推流地址（rtmp_push_url）
//    → 软件推视频到 B = 观众看到画面编辑视频；手机端 A 仍显示摄像头画面（官方通道效果）
// ② 手机未开播时：同一流程 create 新直播间纯软件开播（观众入口同样指向新直播间）
// 关键参数（TikTok直播 studio-platform-provider 同款）：aid=8311 & app_name=tiktok_live_studio
//   & device_platform=windows & live_mode=6 & webcast_sdk_version=1366 & 官方 UA
const GET_STREAM_KEY_SCRIPT = `(async function(){
  var out = { ok: false };
  // v1.12.20 所有 fetch 加超时（防止页面 fetch 挂起→executeJavaScript 拿不到结果→"未知错误"）
  function fet(url, opts, ms){
    var ctl = new AbortController();
    var t = setTimeout(function(){ ctl.abort(); }, ms || 8000);
    opts = opts || {};
    opts.signal = ctl.signal;
    return fetch(url, opts).then(function(r){ clearTimeout(t); return r; }, function(e){ clearTimeout(t); throw e; });
  }
  var csrf = '';
  document.cookie.split(';').forEach(function(c){ var p = c.trim().split('='); if (p[0] === 'passport_csrf_token') csrf = p[1]; });
  var ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) TikTokLIVEStudio/1.36.6 Chrome/136.0.7103.59 Electron/36.4.0-alpha.17 TTElectron/36.4.0-alpha.17 Safari/537.36';
  var common = 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&timezone_name=America%2FLos_Angeles&screen_width=1920&screen_height=1080&browser_language=en-US&browser_platform=Win32&browser_name=Mozilla&browser_version=' + encodeURIComponent(ua) + '&language=en&app_language=en&webcast_language=en&priority_region=US&webcast_sdk_version=1366&live_mode=6';
  var h = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (csrf) h['x-tt-passport-csrf-token'] = csrf;
  // v1.12.15 页面化等效单端：create 成功后，同源 api-live（带页面签名）查账号当前直播间，若手机直播间还在 → 主动关掉（手机被挤）
  async function closeMobileIfAny(newRoomId){
    try {
      var un = ((location.pathname || '').match(/^\/@([^/]+)/) || [])[1] || '';
      if (!un) return;
      var resp = await fet('https://www.tiktok.com/api-live/user/room/?aid=1988&sourceType=54&uniqueId=' + encodeURIComponent(un), { credentials: 'include' }, 8000);
      var txt = await resp.text();
      var j; try { j = JSON.parse(txt); } catch (e) { return; }
      var cur = j && j.data && j.data.room;
      var curId = cur && (cur.id_str || cur.room_id_str || '');
      if (curId && String(curId) !== String(newRoomId)) {
        try { await fet('https://webcast.tiktok.com/webcast/room/status/?' + common, { method: 'POST', credentials: 'include', headers: h, body: 'status=4&room_id=' + curId }, 8000); } catch (e) {}
      }
    } catch (e) {}
  }
  function pick(d){
    if (!d) return null;
    var su = d.stream_url || {};
    var rtmp = su.rtmp_push_url || (su.push_urls && su.push_urls.length ? su.push_urls[0] : '') || (su.complete_push_urls && su.complete_push_urls.length ? su.complete_push_urls[0] : '') || '';
    if (!rtmp) return null;
    return { rtmpUrl: rtmp, streamKey: d.stream_id_str ? 'stream-' + d.stream_id_str : '', roomId: d.id_str || d.room_id_str || '' };
  }
  // ① 创建直播间（官方通道：create 使新直播间成为账号当前直播间，观众入口指向它）
  try {
    var form = new URLSearchParams();
    form.append('title', 'LIVE');
    form.append('cover', '');
    form.append('live_scenario', 'LIVE_VIDEO');
    form.append('biz', 'web_live');
    var r2 = await fet('https://webcast.tiktok.com/webcast/room/create/?' + common, { method: 'POST', credentials: 'include', headers: h, body: form.toString() }, 8000);
    var t2 = await r2.text();
    var j2; try { j2 = JSON.parse(t2); } catch (e) {}
    if (j2 && j2.data && (j2.data.id_str || j2.data.room_id_str || (j2.data.room && j2.data.room.room_id_str))) {
      var roomId = j2.data.id_str || j2.data.room_id_str || j2.data.room.room_id_str;
      // ② 用新直播间 roomId 查完整推流地址（实测返回 rtmp_push_url）
      try {
        var r3 = await fet('https://webcast.tiktok.com/webcast/room/info/?' + common + '&room_id=' + roomId, { credentials: 'include' }, 8000);
        var t3 = await r3.text();
        var j3; try { j3 = JSON.parse(t3); } catch (e) {}
        if (j3 && j3.data) {
          var p3 = pick(j3.data);
          if (p3) { await closeMobileIfAny(roomId); out.ok = true; out.via = '官方通道(create→room/info)'; out.rtmpUrl = p3.rtmpUrl; out.streamKey = p3.streamKey; out.roomId = p3.roomId; return JSON.stringify(out); }
          out.msg = '创建成功但未拿到推流地址: ' + (t3 || '').substring(0, 150);
        } else { out.msg = 'room/info 无数据: ' + (t3 || '').substring(0, 150); }
      } catch (e3) { out.msg = 'room/info 异常: ' + e3.message; }
      // ③ 兜底：create 响应里直接找推流地址
      var p2 = pick(j2.data.room || j2.data);
      if (p2) { await closeMobileIfAny(roomId); out.ok = true; out.via = 'create(直接返回)'; out.rtmpUrl = p2.rtmpUrl; out.streamKey = p2.streamKey; out.roomId = p2.roomId; return JSON.stringify(out); }
    } else { out.msg = 'create 失败: ' + (t2 || '').substring(0, 200); }
  } catch (e) { out.msg = e.message; }
  return JSON.stringify(out);
})()`;

// v1.14.7 内置签名服务（4k版 RapidAPI 签名，所有电脑/版本/账号默认使用；账号自定义配置优先）
const BUILTIN_SIGNER = {
  baseUrl: 'https://tiktok-live-studio-api-signer1.p.rapidapi.com/',
  // 凭据由开发者本机配置，不随源码分发。
  apiKey: process.env.TK_SIGNER_API_KEY || '',
  authMode: 'header',
};

// v1.12.37 获取签名头（60s 缓存复用，避免 RapidAPI 免费额度限流；生成时软件日志可见）
async function getSignHeaders(accountId, info) {
  const sc = (info && info.signer && info.signer.apiKey) ? info.signer : BUILTIN_SIGNER;
  const cache = signerCache[accountId];
  if (cache && Date.now() - cache.at < 60000) return cache.headers;
  try {
    const sig = await getSignatures({ baseUrl: sc.baseUrl, apiKey: sc.apiKey, authMode: sc.authMode || 'header', device_id: '7689692413648635393', params: '', stub: '' });
    const headers = {};
    if (sig['X-Bogus']) headers['X-Bogus'] = sig['X-Bogus'];
    if (sig['X-Argus']) headers['X-Argus'] = sig['X-Argus'];
    if (sig['X-Ladon']) headers['X-Ladon'] = sig['X-Ladon'];
    if (sig['X-Khronos']) headers['x-khronos'] = sig['X-Khronos'];
    signerCache[accountId] = { headers, at: Date.now() };
    if (sig['X-Argus'] && (!lastSignerInfo[accountId] || Date.now() - lastSignerInfo[accountId].at > 60000)) {
      lastSignerInfo[accountId] = { ok: true, at: Date.now(), argusLen: sig['X-Argus'].length };
      try { sendProgress(accountId, 56, '签名服务已自动生成（X-Argus ' + sig['X-Argus'].length + ' 字符）'); } catch (e) {}
    }
    return headers;
  } catch (e) { console.log('[签名] 获取失败:', e.message); return {}; }
}

// v1.12.35 Node 直连创建直播间（带签名头，抖歪同款）：页面 fetch create 失败时的可靠兜底
async function createRoomViaNode(accountId) {
  const info = loadAccounts()[accountId];
  if (!info) return null;
  const cookie = buildCookieHeader(info);
  const csrf = getCsrfToken(info);
  const signHeaders = await getSignHeaders(accountId, info);
  const common = 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&timezone_name=America%2FLos_Angeles&screen_width=1920&screen_height=1080&browser_language=en-US&browser_platform=Win32&browser_name=Mozilla&browser_version=' + encodeURIComponent(UA) + '&language=en&app_language=en&webcast_language=en&priority_region=US&webcast_sdk_version=1366&live_mode=6';
  const headers = { 'User-Agent': UA, 'Accept': 'application/json', 'Cookie': cookie, 'sdk_aid': '8311', 'Referer': 'https://www.tiktok.com/', 'Content-Type': 'application/x-www-form-urlencoded', ...signHeaders };
  if (csrf) headers['x-tt-passport-csrf-token'] = csrf;
  try {
    const r = await httpsJson('https://webcast.tiktok.com/webcast/room/create/?' + common, { method: 'POST', headers, body: 'title=LIVE&cover=&live_scenario=LIVE_VIDEO&biz=web_live' });
    if (r.status === 200 && r.text) {
      const j = JSON.parse(r.text);
      const d = (j && j.data) || {};
      const roomId = String(d.id_str || d.room_id_str || (d.room && d.room.room_id_str) || '');
      if (!roomId) { const why = (r.text || '').slice(0, 200); console.log('[Node create] 无 roomId:', why); try { sendProgress(accountId, 70, 'Node create 无 roomId：' + why); } catch (e) {} return null; }
      // 用新房间查推流地址
      const r2 = await httpsJson('https://webcast.tiktok.com/webcast/room/info/?' + common + '&room_id=' + roomId, { headers });
      if (r2.status === 200 && r2.text) {
        const j2 = JSON.parse(r2.text);
        const d2 = (j2 && j2.data) || {};
        const su = d2.stream_url || {};
        const rtmp = su.rtmp_push_url || (su.push_urls && su.push_urls.length ? su.push_urls[0] : '') || (su.complete_push_urls && su.complete_push_urls.length ? su.complete_push_urls[0] : '') || '';
        if (rtmp) {
          const sk = d2.stream_id_str ? 'stream-' + d2.stream_id_str : '';
          console.log('[Node create] 创建成功 roomId=' + roomId + ' rtmp=' + rtmp.slice(0, 60));
          return { rtmpUrl: rtmp, streamKey: sk, roomId };
        }
        const why2 = (r2.text || '').slice(0, 200);
        console.log('[Node create] room/info 无推流地址:', why2);
        try { sendProgress(accountId, 72, 'Node create 无推流地址：' + why2); } catch (e) {}
      } else { const why2 = 'HTTP ' + r2.status; console.log('[Node create] room/info ' + why2); try { sendProgress(accountId, 72, 'Node create room/info ' + why2); } catch (e) {} }
    } else { const why = 'HTTP ' + r.status + ' ' + (r.error || '') + ' ' + (r.text || '').slice(0, 160); console.log('[Node create] ' + why); try { sendProgress(accountId, 71, 'Node create 失败：' + why); } catch (e) {} }
  } catch (e) { console.log('[Node create] 异常:', e.message); try { sendProgress(accountId, 71, 'Node create 异常：' + e.message); } catch (e2) {} }
  return null;
}

// API 通道：隐藏窗口 + 已登录 Cookie → 创建直播间 → 取推流码 → 自动关窗
async function fetchStreamKeyByApi(accountId, accountName) {
  let preRoomId = '', mobileRoomId = '', curRoom = ''; // v1.14.7 curRoom 提到 try 外：获取失败时 1072 处引用不再 ReferenceError
  // v1.9.6 单端开播：开播前检查账号是否已有直播间在播（手机/其他端）
  sendProgress(accountId, 55, '开播前检查账号当前直播状态...');
  // v1.15.0 精简提速：移除 v1.14.16 的 3 秒代理出口自检（多余等待；节点不通时首次查询失败即提示，不再白等）
  try {
    preRoomId = await getRoomIdViaApi(accountId, accountName);
    if (preRoomId) {
      const preStatus = await getRoomStatusViaApi(accountId, preRoomId);
      if (preStatus === 2) {
        // v1.10.0 手机直播间模式：手机端开播中 → 直接接管该直播间（拿它的推流码推流，手机端被挤掉）
        sendProgress(accountId, 60, '检测到手机/当前直播间在播（' + preRoomId + '），将获取该直播间推流码并接管（手机直播间模式）');
      }
    }
  } catch (e) {}
  // v1.10.0 抖歪模式（手机直播间推流码优先）：手机端已开播时，直接拿手机直播间的推流码
  // 流程：api-live 拿账号当前直播间 roomId（手机开播时=手机直播间）→ room/info 拿该直播间完整推流地址
  sendProgress(accountId, 62, '正在获取账号当前直播间推流码（手机直播间模式）...');
  try {
    // v1.15.0 精简提速：房间号查询只做 1 次（原 3 次重试+2.5s sleep 是多余等待；节点通时首次即秒回，不通时快速失败提示）
    curRoom = await getRoomIdViaApi(accountId, accountName);
    if (curRoom) {
      mobileRoomId = curRoom; // v1.12.14 记录手机直播间 roomId（等效单端关手机用）
      const info = loadAccounts()[accountId];
      const cookie = buildCookieHeader(info);
      const csrf = getCsrfToken(info);
      // v1.12.34 签名服务（抖歪同款）：配置了 RapidAPI Key 时 Node 直连带签名头 → 不被风控
      const signHeaders = await getSignHeaders(accountId, info);
      const headers = { 'User-Agent': UA, 'Accept': 'application/json', 'Cookie': cookie, 'sdk_aid': '8311', 'Referer': 'https://www.tiktok.com/', ...signHeaders };
      if (csrf) headers['x-tt-passport-csrf-token'] = csrf;
      // v1.12.7 多参数组合重试（room/info 对手机直播间可能要求不同 live_mode/device_platform）
      const combos = [
        { q: 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&live_mode=6', tag: 'studio6' },
        { q: 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&live_mode=1', tag: 'studio1' },
        { q: 'aid=1233&app_name=tiktok_web&device_platform=web&channel=web&version_code=1.0.0&live_mode=6', tag: 'web6' },
        { q: 'aid=1233&app_name=tiktok_web&device_platform=web&channel=web&version_code=1.0.0&live_mode=1', tag: 'web1' },
      ];
      let mobileRtmp = '', mobileKey = '';
      for (const c of combos) {
        try {
          const r = await httpsJson('https://webcast.tiktok.com/webcast/room/info/?' + c.q + '&room_id=' + curRoom, { headers });
          if (r.status === 200 && r.text) {
            const j = JSON.parse(r.text);
            const d = (j && j.data) || {};
            const su = d.stream_url || {};
            const rtmp = su.rtmp_push_url || (su.push_urls && su.push_urls.length ? su.push_urls[0] : '') || (su.complete_push_urls && su.complete_push_urls.length ? su.complete_push_urls[0] : '') || '';
            if (rtmp) { mobileRtmp = rtmp; mobileKey = d.stream_id_str ? 'stream-' + d.stream_id_str : ''; break; }
          }
        } catch (e) {}
      }
      // v1.12.10 页面上下文同源 fetch 兜底（Node https 被风控/网络波动拿不到时，页面 fetch 带完整签名更可靠）
      // v1.12.47 修复：Node 直连拿不到 roomId 时，页面通道 room/inspect 独立查手机直播间（不依赖 curRoom）
      if (!mobileRtmp) {
        try {
          let capWin = findLiveDataWindow(accountId);
          if (!capWin) {
            capWin = createAccountWindow(accountId, { title: '推流码捕获 · 房间' + accountId, width: 420, height: 320, show: false });
            capWin._captureTemp = true;
            await injectSavedCookies(accountId, capWin.webContents.session);
            const nm = (loadAccounts()[accountId] || {}).name || '';
            try { await Promise.race([capWin.loadURL('https://www.tiktok.com/@' + encodeURIComponent(nm.replace(/^@/, '')) + '/live', { userAgent: UA }), sleep(15000)]); } catch (e) {}
          }
          const pageRes = await Promise.race([
            capWin.webContents.executeJavaScript(`(async () => {
              // v1.14.7 修复：room_id 用主进程传入的 CR（原 ${curRoom} 在页面上下文是字面量，请求必失败）
              const CR = ${JSON.stringify(String(curRoom || ''))};
              // v1.12.11 优先 room/inspect：一步查账号当前活跃直播间（手机直播间）推流地址（抖歪同款机制，页面带签名最可靠）
              const combos = [
                'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&live_mode=6',
                'aid=1233&app_name=tiktok_web&device_platform=web&channel=web&version_code=1.0.0&live_mode=6'
              ];
              for (const q of combos) {
                try {
                  const resp = await fetch('https://webcast.tiktok.com/webcast/room/inspect/?' + q, { credentials: 'include' });
                  const txt = await resp.text();
                  const j = JSON.parse(txt);
                  const d = (j && j.data) || {};
                  const room = d.room || d;
                  const su = room.stream_url || d.stream_url || {};
                  const rtmp = su.rtmp_push_url || (su.push_urls && su.push_urls[0]) || (su.complete_push_urls && su.complete_push_urls[0]) || '';
                  const rid = room.room_id_str || room.room_id || d.room_id_str || '';
                  const sid = room.stream_id_str || d.stream_id_str || '';
                  if (rtmp) return JSON.stringify({ rtmp: rtmp, key: sid ? 'stream-' + sid : '', roomId: String(rid || '') });
                } catch (e) {}
              }
              // fallback room/info（指定 room_id）
              for (const q of combos) {
                try {
                  const resp = await fetch('https://webcast.tiktok.com/webcast/room/info/?' + q + '&room_id=' + CR, { credentials: 'include' });
                  const txt = await resp.text();
                  const j = JSON.parse(txt);
                  const su = (j && j.data && j.data.stream_url) || {};
                  const rtmp = su.rtmp_push_url || (su.push_urls && su.push_urls[0]) || (su.complete_push_urls && su.complete_push_urls[0]) || '';
                  if (rtmp) return JSON.stringify({ rtmp: rtmp, key: (j.data.stream_id_str ? 'stream-' + j.data.stream_id_str : ''), roomId: CR });
                } catch (e) {}
              }
              return '';
            })()`, true),
            sleep(25000).then(() => '')
          ]);
          if (pageRes && pageRes !== '') {
            const pr = JSON.parse(pageRes);
            mobileRtmp = pr.rtmp; mobileKey = pr.key;
            if (pr.roomId) curRoom = pr.roomId;
            console.log('[推流码] 手机直播间模式（页面上下文同源fetch）获取成功 roomId=' + curRoom);
          }
        } catch (e) { console.log('[推流码] 页面上下文兜底失败:', e.message); }
      }
      if (mobileRtmp) {
        // v1.12.50 补 uid（帧签名 binding 用）：room/info owner → cookie uid_tt → api-live user
        if (!streamUids[accountId]) {
          try {
            const _info = loadAccounts()[accountId] || {};
            const cks = Array.isArray(_info.cookies) ? _info.cookies : [];
            for (const c of cks) {
              if (/^uid_tt/.test(c.name || '') && /^\d+$/.test(String(c.value || ''))) { streamUids[accountId] = String(c.value); break; }
            }
          } catch (e) {}
        }
        // v1.12.52 手机流接管（实测验证）：返回当场码 → 提示用户手机断网（飞行模式/断网，勿点 End）→ 软件推流接管
        // 服务器在手机断流（房间保留 status=3）时接受软件推流；手机恢复网络会自动顶回（平台机制，用户已接受）
        sendProgress(accountId, 100, '已获取手机直播间当场推流码（roomId=' + curRoom + '）。请手机断网（飞行模式，不要点End），断网后点「开始推流」接管（观众看软件画面）');
        return { success: true, rtmpUrl: mobileRtmp, streamKey: mobileKey, roomId: String(curRoom), via: '手机直播间(当场码,断流接管)', uid: streamUids[accountId] || '' };
      }
    }
  } catch (e) { console.log('[推流码] 手机直播间模式失败:', e.message); }
  // v1.12.45 用户要求：不要纯软件 create 开播；必须手机端先开播，软件实时抓当场新码
  if (!curRoom && !mobileRoomId) {
    sendProgress(accountId, 100, '未检测到手机端开播（无当前直播间）。请先在手机端点开直播，再点获取推流码（软件只接手机直播间当场真实码）');
    return { success: false, error: '未检测到手机端开播，请先在手机端点开直播后重试' };
  }
  // 手机已开播但码未拿到 → Node 签名 create 兜底（观众看软件画面，等效接管）
  sendProgress(accountId, 68, '签名直连创建新直播间（Node create）...');
  const created = await createRoomViaNode(accountId);
  if (created) {
    sendProgress(accountId, 90, '签名创建直播间成功 roomId=' + created.roomId + '，关闭手机直播间实现单端...');
    // 等效单端：关掉手机直播间（手机被挤，只剩软件推流）
    if (mobileRoomId) {
      try { await closeRoomViaApi(accountId, mobileRoomId, ''); } catch (e) {}
    }
    return { success: true, rtmpUrl: created.rtmpUrl, streamKey: created.streamKey, roomId: created.roomId, via: '签名创建直播间(Node create)' };
  }
  console.log('[推流码] Node create 未成功，走 CDP 捕获兜底');
  // v1.12.23 手机开播场景：CDP 捕获到的是手机直播间流（同账号同房间两路推流被服务器拒 duplicate）
  // → 捕获结果只作 create 失败时的兜底；优先 create 新直播间（推新房间流+主动关手机直播间=等效单端，v1.7.0 同款链路）
  let capFallback = null;
  // v1.12.33 CDP 捕获重试（最多 2 轮；attachStreamCapture 内部每次已自动刷新重试 1 次 = 每轮 2 次机会）
  for (let capRound = 1; capRound <= 2; capRound++) {
    sendProgress(accountId, 66, '开直播页并用 CDP 网络监听捕获推流码（第 ' + capRound + '/2 轮）...');
    try {
      let capWin = findLiveDataWindow(accountId);
      if (!capWin) {
        capWin = createAccountWindow(accountId, {
          title: '推流码捕获 · 房间' + accountId,
          width: 420, height: 320, show: false,
        });
        capWin._captureTemp = true;
        await injectSavedCookies(accountId, capWin.webContents.session);
        // v1.12.2 预加载 live 页（20s 超时，不卡流程）
        const name = (loadAccounts()[accountId] || {}).name || '';
        const liveUrl = name
          ? 'https://www.tiktok.com/@' + encodeURIComponent(name.replace(/^@/, '')) + '/live'
          : 'https://www.tiktok.com/live';
        try { await Promise.race([capWin.loadURL(liveUrl, { userAgent: UA }), sleep(20000)]); } catch (e) {}
      }
      const cap = await runStreamCaptureBounded(accountId, capWin);
      if (cap && cap.serverUrl && cap.streamKey) {
        capFallback = cap;
        sendProgress(accountId, 70, '已捕获到直播页推流码，优先创建新直播间接管（手机在播时直接推会被服务器拒）...');
        break;
      }
      if (capRound < 2) sendProgress(accountId, 70, '第 ' + capRound + ' 轮未捕获到推流码，重试第 2 轮...');
    } catch (e) { console.error('[推流码] CDP 捕获失败(' + capRound + '/2):', e.message); }
  }
  if (!capFallback) sendProgress(accountId, 70, '直播页未捕获到推流码，改用创建新直播间（API 通道）...');
  let win = null;
  try {
    // v1.12.18 create 通道优先复用数据窗口（tiktok.com 域→create/closeMobileIfAny 页面签名最可靠+等效单端能拿到账号名）；
    // 无数据窗口才新建隐藏窗口兜底
    win = findLiveDataWindow(accountId);
    if (!win) {
      win = createAccountWindow(accountId, {
        title: 'TikTok 开播通道 · 房间' + accountId,
        width: 480, height: 360, show: false,
      });
      await injectSavedCookies(accountId, win.webContents.session);
      // v1.12.19 兜底窗口用 tiktok.com 直播页（同域页面 fetch webcast 才通；livecenter 域被 CORS 拦截导致 create 返回未知错误）
      const name = (loadAccounts()[accountId] || {}).name || '';
      const liveUrl = name
        ? 'https://www.tiktok.com/@' + encodeURIComponent(name.replace(/^@/, '')) + '/live'
        : 'https://www.tiktok.com/live';
      try {
        await Promise.race([win.loadURL(liveUrl, { userAgent: UA }), sleep(20000)]);
      } catch (e) { console.error('[API推流码] 页面加载:', e.message); }
    }
    // 等待登录态就绪（最多 30s），就绪后页面 fetch 才带得上 Cookie
    let logged = false;
    for (let i = 0; i < 20; i++) {
      await sleep(1500);
      try {
        const st = await Promise.race([
          win.webContents.executeJavaScript(PAGE_AUTH_CHECK_SCRIPT),
          new Promise(r => setTimeout(() => r(''), 5000)),
        ]);
        if (st === 'logged_in') { logged = true; break; }
      } catch (e) {}
    }
    if (!logged) { sendProgress(accountId, 82, '登录态未就绪，仍尝试直接调 API...'); }
    // v1.12.21 执行 create 前等页面稳定（readyState complete，最多 10s），避免 executeJavaScript 在页面加载/导航窗口期失败
    for (let i = 0; i < 10; i++) {
      try {
        const rs = await Promise.race([
          win.webContents.executeJavaScript('document.readyState', true),
          new Promise(r => setTimeout(() => r(''), 5000)),
        ]);
        if (rs === 'complete') break;
      } catch (e) {}
      await sleep(1000);
    }
    // v1.12.18 executeJavaScript 失败自动重试（页面导航/加载窗口期会抛 Script failed to execute，等页面稳定后重试）
    // v1.12.21 重试失败时把真实错误显示到日志（之前"未知错误"无法定位根因）
    let raw = null;
    for (let i = 0; i < 3 && !raw; i++) {
      try {
        // v1.12.27 executeJavaScript 加 8s 超时（页面 busy 会让执行永久挂起 → 流程卡死；超时按失败重试，不卡流程）
        raw = await Promise.race([
          win.webContents.executeJavaScript(GET_STREAM_KEY_SCRIPT, true),
          new Promise(r => setTimeout(() => r('__timeout'), 8000)),
        ]);
        if (raw === '__timeout') { raw = null; throw new Error('脚本执行超时'); }
      } catch (e) {
        console.error('[API推流码] 执行创建脚本失败(' + (i + 1) + '/3):', e.message);
        sendProgress(accountId, 84, '创建脚本执行失败(' + (i + 1) + '/3)：' + e.message);
        if (i < 2) await sleep(3500);
      }
    }
    let res = null;
    try { res = JSON.parse(raw); } catch (e) {}
    if (res && res.ok) {
      // v1.12.14 等效单端：create 推流成功后，若手机直播间在播 → 主动关掉手机直播间（手机被挤，只剩软件直播）
      const mobileId = mobileRoomId || preRoomId;
      if (mobileId && String(mobileId) !== String(res.roomId || '')) {
        sendProgress(accountId, 93, '检测到手机直播间在播，自动关闭手机直播间（等效单端开播）...');
        closeRoomViaApi(accountId, String(mobileId), '');
      }
      sendProgress(accountId, 100, '推流码获取成功（' + (res.via || 'API 通道') + '），窗口已自动关闭');
      return { success: true, rtmpUrl: res.rtmpUrl, streamKey: res.streamKey, roomId: res.roomId, via: res.via || 'api' };
    }
    const msg = (res && res.msg) || '未知错误';
    sendProgress(accountId, 88, 'API 创建直播间失败：' + msg);
    // v1.12.35 Node 签名 create 兜底：页面 create 失败后，签名直连创建新直播间（等效单端，抖歪同款）
    sendProgress(accountId, 89, '改用签名直连创建新直播间（Node create）...');
    const createdNode = await createRoomViaNode(accountId);
    if (createdNode) {
      const mobileId = mobileRoomId || preRoomId;
      if (mobileId && String(mobileId) !== String(createdNode.roomId || '')) {
        sendProgress(accountId, 93, '检测到手机直播间在播，自动关闭手机直播间（等效单端开播）...');
        try { await closeRoomViaApi(accountId, String(mobileId), ''); } catch (e) {}
      }
      sendProgress(accountId, 100, '推流码获取成功（签名创建直播间 Node create），窗口已自动关闭');
      return { success: true, rtmpUrl: createdNode.rtmpUrl, streamKey: createdNode.streamKey, roomId: createdNode.roomId, via: '签名创建直播间(Node create)' };
    }
    // v1.12.23 create 失败时回退 CDP 已捕获推流码（手机直播间流；手机不在播时可直接推，在播时推流会报 duplicate 属兜底尝试）
    if (capFallback && capFallback.serverUrl && capFallback.streamKey) {
      sendProgress(accountId, 92, 'create 失败，回退使用已捕获推流码（' + (capFallback.sourcePath || '') + '）...');
      // v1.12.28 等效单端：回退的是手机直播间流，手机在播时直接推会被服务器拒（duplicate，FFmpeg 秒退）
      // → 推流前先主动关闭手机直播间（status=4），手机被挤、只剩软件直播，再推同一路不冲突
      const mobileId = mobileRoomId || preRoomId || capFallback.roomId;
      if (mobileId) {
        sendProgress(accountId, 93, '检测到手机直播间在播，自动关闭手机直播间（等效单端开播）...');
        closeRoomViaApi(accountId, String(mobileId), '');
        await sleep(1500);
      }
      return { success: true, rtmpUrl: capFallback.serverUrl, streamKey: capFallback.streamKey, roomId: capFallback.roomId || '', via: '直播页网络捕获(create失败回退)' };
    }
    return { success: false, error: msg };
  } catch (e) {
    console.error('[API推流码] 房间', accountId, e.message);
    return { success: false, error: e.message };
  } finally {
    if (win && !win.isDestroyed()) { try { win.close(); } catch (e) {} }
  }
}

// v1.12.2 复用数据窗口（避免新建窗口+loadURL+close 时序导致主进程崩溃）
function findLiveDataWindow(accountId) {
  const wins = accountWindows[accountId] || [];
  // v1.12.22 排除临时捕获窗口（_captureTemp 会被定时关闭→复用后 executeJavaScript 报 Object has been destroyed）
  return wins.find(w => !w.isDestroyed() && !w._captureTemp && /tiktok\.com/.test(w.webContents.getURL())) || null;
}

// v1.12.0 抖歪机制移植：CDP 附加调试器 + Network.enable，监听直播页网络响应，
// 匹配 webcast/room/* 等推流相关 URL，读取响应体提取 rtmp 推流码（watchDog 超时自动刷新重试一次）
async function attachStreamCapture(accountId, win, timeoutMs = 25000) {
  const wc = win.webContents;
  try { wc.debugger.attach('1.3'); } catch (e) { return null; }
  let captured = null;
  const onMsg = async (_e, method, params) => {
    if (method !== 'Network.responseReceived' || captured) return;
    const url = (params.response && params.response.url) || '';
    if (!isStreamResponseUrl(url)) return;
    try {
      const { body } = await wc.debugger.sendCommand('Network.getResponseBody', { requestId: params.requestId });
      const info = extractStreamInfoFromBody(body);
      if (info) {
        captured = { ...info, responseUrl: url, roomId: '' };
        const rm = String(url).match(/room_id=(\d+)/);
        if (rm) captured.roomId = rm[1];
        sendProgress(accountId, 88, '直播页网络捕获到推流码（' + info.sourcePath + '）');
      }
    } catch (e) {}
  };
  wc.debugger.on('message', onMsg);
  try { await wc.debugger.sendCommand('Network.enable'); } catch (e) {}
  // v1.12.2：不新建窗口/不 loadURL——直接刷新数据窗口触发 room/enter 响应
  try { win.reload(); } catch (e) { console.error('[捕获] 刷新数据窗口失败:', e.message); }
  const waitCapture = async (ms) => {
    const deadline = Date.now() + ms;
    while (!captured && Date.now() < deadline) { await sleep(1000); }
  };
  await waitCapture(timeoutMs);
  if (!captured) {
    sendProgress(accountId, 82, '首次未捕获到推流码，自动刷新直播页重试一次...');
    try { win.reload(); } catch (e) {}
    await waitCapture(timeoutMs);
  }
  wc.debugger.removeListener('message', onMsg);
  try { wc.debugger.detach(); } catch (e) {}
  return captured;
}

// v1.12.1 修复：CDP 捕获段加总超时（90s），避免流程挂起
async function runStreamCaptureBounded(accountId, capWin) {
  try {
    return await Promise.race([
      attachStreamCapture(accountId, capWin, 30000),
      sleep(90000).then(() => null),
    ]);
  } finally {
    // v1.12.2：只关闭本次新建的临时捕获窗口（数据窗口保留不关，避免崩溃）
    if (capWin && capWin._captureTemp) {
      try { if (!capWin.isDestroyed()) setTimeout(() => { try { capWin.close(); } catch (e) {} }, 3000); } catch (e) {}
    }
  }
}

// 前端「获取推流码」优先走 API 通道（成功后回填+自动关窗；失败再开页面扫描兜底）
ipcMain.handle('tiktok:getStreamKeyByApi', async (event, { accountId, accountName }) => {
  return await fetchStreamKeyByApi(accountId, accountName);
});

// v1.12.34 签名服务：保存配置（baseUrl/apiKey/authMode 存 accounts.json 的 signer 字段）
ipcMain.handle('tiktok:signerSave', async (event, { accountId, baseUrl, apiKey, authMode }) => {
  try {
    const data = loadAccounts();
    if (!data[accountId]) return { success: false, error: '账号不存在' };
    data[accountId].signer = { baseUrl: baseUrl || '', apiKey: apiKey || '', authMode: authMode || 'header' };
    saveAccounts(data);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

// v1.12.34 签名服务：连通性检测（无自定义配置时检测内置签名）
ipcMain.handle('tiktok:signerCheck', async (event, { accountId }) => {
  try {
    const info = loadAccounts()[accountId];
    const sc = (info && info.signer && info.signer.apiKey) ? info.signer : BUILTIN_SIGNER;
    const r = await checkSigner({ baseUrl: sc.baseUrl, apiKey: sc.apiKey, authMode: sc.authMode || 'header' });
    return { success: true, message: r.message };
  } catch (e) { return { success: false, error: e.message }; }
});

// v1.12.36 签名服务状态（配置 + 最近自动生成信息，软件内可见；无自定义时显示内置签名状态）
ipcMain.handle('tiktok:signerStatus', async (event, { accountId }) => {
  try {
    const info = loadAccounts()[accountId];
    const sc = (info && info.signer && info.signer.apiKey) ? info.signer : BUILTIN_SIGNER;
    const ls = lastSignerInfo[accountId] || null;
    return {
      configured: !!(sc && sc.apiKey),
      builtin: !(info && info.signer && info.signer.apiKey), // v1.14.7 是否在使用内置签名
      keyTail: sc && sc.apiKey ? String(sc.apiKey).slice(-4) : '',
      baseUrl: (sc && sc.baseUrl) || '',
      lastOk: ls ? { at: ls.at, argusLen: ls.argusLen } : null,
    };
  } catch (e) { return { configured: false, builtin: true, keyTail: '', baseUrl: '', lastOk: null }; }
});

ipcMain.handle('tiktok:openProducerWindow', async (event, { accountId, accountName, autoGoLive, mode, autoClose }) => {
  // v1.13.4 幂等：同一账号已开的「直播中心」窗口 → 聚焦不复开
  const pWins = accountWindows[accountId] || [];
  const pExisting = pWins.find(w => w && !w.isDestroyed() && w.__liveWindowKind === 'producer');
  if (pExisting) {
    try { pExisting.show(); pExisting.focus(); } catch (e) {}
    return { success: true, reused: true };
  }
  autoGoLiveFlags[accountId] = !!autoGoLive;
  autoCloseFlags[accountId] = !!autoClose;
  sendProgress(accountId, 15, '正在打开直播中心窗口（TikTok LIVE Studio 通道）...');
  const win = createAccountWindow(accountId, {
    title: 'TikTok 直播中心 · 房间' + accountId + (accountName ? ' · @' + accountName : ''),
    width: 1320, height: 860,
  });
  win.__liveWindowKind = 'producer';
  // 预注入已保存 Cookie
  await injectSavedCookies(accountId, win.webContents.session);
  try {
    await win.loadURL('https://livecenter.tiktok.com/producer', { userAgent: UA });
  } catch (e) { console.error('[后台窗口] 加载失败:', e.message); }
  startLoginMonitor(accountId, accountName, win, { mode: mode || 'mobile', autoCloseOnKey: autoClose !== false });
  win.on('closed', () => { delete autoGoLiveFlags[accountId]; delete autoCloseFlags[accountId]; delete scanRetry[accountId]; });
  return { success: true };
});

ipcMain.handle('tiktok:openLiveWindow', async (event, { accountId, accountName }) => {
  // v1.13.4 幂等改用窗口标记（网页加载后 getTitle() 返回网页标题，按标题匹配会失效 → 每次点击都新开窗口）
  const wins = accountWindows[accountId] || [];
  const existing = wins.find(w => w && !w.isDestroyed() && w.__liveWindowKind === 'live');
  if (existing) {
    try { existing.show(); existing.focus(); } catch (e) {}
    return { success: true, reused: true };
  }
  const url = accountName
    ? 'https://www.tiktok.com/@' + encodeURIComponent(accountName.replace(/^@/, '')) + '/live'
    : 'https://www.tiktok.com/live';
  const win = createAccountWindow(accountId, {
    title: '直播间 · 房间' + accountId + (accountName ? ' · @' + accountName : ''),
    width: 1100, height: 780,
  });
  win.__liveWindowKind = 'live';
  try {
    await win.loadURL(url, { userAgent: UA });
  } catch (e) { console.error('[直播间窗口] 加载失败:', e.message); }
  return { success: true };
});

let _helpWindow = null;
ipcMain.handle('app:openHelp', async () => {
  // v1.14.1 说明书窗口（幂等：已开则聚焦）
  if (_helpWindow && !_helpWindow.isDestroyed()) {
    try { _helpWindow.show(); _helpWindow.focus(); } catch (e) {}
    return { success: true, reused: true };
  }
  _helpWindow = new BrowserWindow({
    title: '使用说明书 · TikTok 直播工作台',
    width: 880, height: 760, autoHideMenuBar: true,
    backgroundColor: '#0d1526',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
  });
  _helpWindow.on('closed', () => { _helpWindow = null; });
  try { _helpWindow.loadFile(path.join(__dirname, 'help.html')); } catch (e) { console.error('[说明书] 加载失败:', e.message); }
  return { success: true };
});

ipcMain.handle('tiktok:saveManualCookies', async (event, { accountId, accountName, cookieString }) => {
  if (!cookieString || !cookieString.trim()) return { success: false, error: 'Cookie 内容为空' };
  try {
    const ses = accountSession(accountId);
    let pairs = [];
    const trimmed = cookieString.trim();
    if (trimmed.startsWith('[')) {
      const arr = JSON.parse(trimmed);
      pairs = arr.map(c => ({ name: c.name, value: c.value, domain: c.domain || '.tiktok.com', path: c.path || '/' }));
    } else {
      trimmed.split(';').forEach(seg => {
        const idx = seg.indexOf('=');
        if (idx > 0) {
          pairs.push({ name: seg.substring(0, idx).trim(), value: seg.substring(idx + 1).trim(), domain: '.tiktok.com', path: '/' });
        }
      });
    }
    pairs = pairs.filter(p => p.name && p.value);
    for (const p of pairs) {
      try {
        await ses.cookies.set({
          url: 'https://www.tiktok.com' + (p.path || '/'),
          name: p.name, value: p.value, domain: p.domain, path: p.path || '/',
          secure: true, httpOnly: p.httpOnly !== false,
        });
      } catch (e) {}
    }
    const data = loadAccounts();
    data[accountId] = {
      name: accountName || (data[accountId] ? data[accountId].name : ''),
      cookies: pairs.map(p => ({ name: p.name, value: p.value, domain: p.domain, path: p.path || '/', secure: true, httpOnly: true })),
      cookieCount: pairs.length, capturedAt: Date.now(), loggedIn: true,
    };
    saveAccounts(data);
    sendLoginState(accountId, data[accountId]);
    return { success: true, cookieCount: pairs.length };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('tiktok:exportCookies', async (event, { accountId }) => {
  const data = loadAccounts();
  const info = data[accountId];
  if (!info || !info.cookies || info.cookies.length === 0) return { success: false, error: '该房间还没有已保存的 Cookie' };
  const str = info.cookies.map(c => c.name + '=' + c.value).join('; ');
  return { success: true, cookieString: str, cookieCount: info.cookies.length };
});

ipcMain.handle('tiktok:getAccountAuth', async (event, { accountId }) => {
  const info = loadAccounts()[accountId] || null;
  return { accountId, loggedIn: !!(info && info.loggedIn), cookieCount: info ? (info.cookieCount || 0) : 0, capturedAt: info ? info.capturedAt : null, name: info ? (info.name || '') : '' };
});

ipcMain.handle('tiktok:clearLogin', async (event, { accountId }) => {
  try {
    const ses = accountSession(accountId);
    await ses.clearStorageData({ storages: ['cookies', 'localstorage', 'cachestorage'] });
    const cookies = await ses.cookies.get({});
    for (const c of cookies) {
      try { await ses.cookies.remove('https://www.tiktok.com' + (c.path || '/'), c.name); } catch (e) {}
    }
  } catch (e) { console.error('[清除登录] 会话清理失败:', e.message); }
  const data = loadAccounts();
  delete data[accountId];
  saveAccounts(data);
  sendLoginState(accountId, null);
  return { success: true };
});

ipcMain.handle('tiktok:closeAccountWindows', async (event, { accountId }) => {
  closeAccountWindows(accountId);
  return { success: true };
});

// ============================================================
// 真实节点测试（socks5 直连测速；vless/vmess 需本地代理客户端）
// ============================================================
function parseProxyUrl(url) {
  const m = url.match(/^socks5:\/\/(?:(.+?):(.+?)@)?([^:/]+):(\d+)/i);
  if (!m) return null;
  return { username: m[1], password: m[2], host: m[3], port: parseInt(m[4], 10) };
}

function socks5Test(url, targetHost = 'api.ipify.org', targetPort = 443, timeout = 15000) {
  const p = parseProxyUrl(url);
  if (!p) return Promise.resolve({ success: false, error: '无法解析 socks5 节点链接（格式 socks5://user:pass@host:port）' });
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const socket = net.connect(p.port, p.host);
    socket.setTimeout(timeout);
    const finish = (result) => { if (!settled) { settled = true; try { socket.destroy(); } catch (e) {} resolve(result); } };
    socket.on('error', (e) => finish({ success: false, error: '代理连接失败: ' + e.message }));
    socket.on('timeout', () => finish({ success: false, error: '代理连接超时' }));

    let buf = Buffer.alloc(0);
    let phase = 'greet';

    let tcpMs = 0; // v1.14.7 延迟口径：TCP 建连耗时（1 次往返，与 v2rayN 同口径）
    socket.on('connect', () => {
      tcpMs = Date.now() - start;
      const methods = p.username ? [0x02, 0x00] : [0x00];
      socket.write(Buffer.from([0x05, methods.length, ...methods]));
    });

    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (phase === 'greet' && buf.length >= 2) {
        const ver = buf[0], method = buf[1];
        buf = buf.slice(2);
        if (ver !== 5) return finish({ success: false, error: '代理协议不兼容' });
        if (method === 0xff) return finish({ success: false, error: '代理要求认证但未提供账号密码' });
        if (method === 0x02) {
          phase = 'auth';
          const user = Buffer.from(p.username || '');
          const pass = Buffer.from(p.password || '');
          socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
          return;
        }
        phase = 'connect';
        sendConnect();
      } else if (phase === 'auth' && buf.length >= 2) {
        if (buf[1] !== 0) return finish({ success: false, error: '代理认证失败（账号或密码错误）' });
        buf = buf.slice(2);
        phase = 'connect';
        sendConnect();
      } else if (phase === 'connect' && buf.length >= 4) {
        const rep = buf[1];
        if (rep !== 0) return finish({ success: false, error: '经代理连接目标失败 (SOCKS5 code=' + rep + ')' });
        const atype = buf[3];
        let skip = 4;
        if (atype === 1) skip += 4;
        else if (atype === 4) skip += 16;
        else if (atype === 3) skip += 1 + buf[4];
        else return finish({ success: false, error: '代理返回未知地址类型' });
        buf = buf.slice(skip);
        phase = 'tls';
        const secure = tls.connect({ socket, servername: targetHost, rejectUnauthorized: false });
        let tbuf = Buffer.alloc(0);
        let doneTls = false;
        secure.setTimeout(timeout);
        secure.on('secureConnect', () => {
          secure.write('GET /?format=json HTTP/1.1\r\nHost: ' + targetHost + '\r\nConnection: close\r\n\r\n');
        });
        secure.on('data', (td) => {
          tbuf = Buffer.concat([tbuf, td]);
          if (!doneTls && tbuf.includes(Buffer.from('\r\n\r\n'))) {
            doneTls = true;
            const raw = tbuf.toString('utf8');
            const body = raw.split('\r\n\r\n')[1] || '';
            let ip = 'unknown';
            try {
              const j = JSON.parse(body.split('\n')[0].trim());
              ip = j.ip || 'unknown';
            } catch (e) {}
            finish({ success: true, ip, ping: tcpMs || (Date.now() - start), protocol: 'socks5' });
          }
        });
        secure.on('error', (e) => finish({ success: false, error: '目标请求失败: ' + e.message }));
        secure.on('timeout', () => finish({ success: false, error: '目标请求超时' }));
        return;
      }
    });

    function sendConnect() {
      const hostBuf = Buffer.from(targetHost, 'ascii');
      socket.write(Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
        hostBuf,
        Buffer.from([0x01, 0xBB]),
      ]));
    }
  });
}

// v1.14.7 节点测速：起独立 xray（随机端口，不打断当前 10888）→ 经代理实测下行/上行（Cloudflare 测速端点）
// 实现用 Node 原生 net/tls 手写 SOCKS5+HTTPS（零外部依赖，避免打包版依赖不完整）
function reserveTestPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(e => e ? reject(e) : resolve(p)); });
  });
}
function socks5ConnectTls(proxyPort, targetHost, targetPort, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let buf = Buffer.alloc(0), phase = 'greet';
    const sock = net.connect({ host: '127.0.0.1', port: proxyPort });
    sock.setTimeout(timeoutMs || 20000);
    sock.on('connect', () => sock.write(Buffer.from([0x05, 1, 0x00])));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (phase === 'greet' && buf.length >= 2) {
        if (buf[1] === 0xff) { sock.destroy(); if (!settled) { settled = true; reject(new Error('代理要求认证但未提供账号')); } return; }
        buf = buf.slice(2);
        phase = 'connect';
        const hb = Buffer.from(targetHost, 'ascii');
        sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb, Buffer.from([0x01, 0xBB])]));
      } else if (phase === 'connect' && buf.length >= 4) {
        if (buf[1] !== 0) { sock.destroy(); if (!settled) { settled = true; reject(new Error('SOCKS5 连接目标失败 code=' + buf[1])); } return; }
        const atype = buf[3]; let skip = 4;
        if (atype === 1) skip += 4; else if (atype === 4) skip += 16; else if (atype === 3) skip += 1 + buf[4];
        buf = buf.slice(skip);
        phase = 'tls';
        const secure = tls.connect({ socket: sock, servername: targetHost, rejectUnauthorized: false });
        secure.setTimeout(timeoutMs || 20000);
        secure.once('secureConnect', () => { if (!settled) { settled = true; resolve(secure); } });
        secure.on('error', (e) => { if (!settled) { settled = true; reject(e); } });
        secure.on('timeout', () => { if (!settled) { settled = true; reject(new Error('TLS 握手超时')); } });
      }
    });
    sock.on('error', (e) => { if (!settled) { settled = true; reject(e); } });
    sock.on('timeout', () => { if (!settled) { settled = true; reject(new Error('SOCKS5 握手超时')); } });
  });
}
function nodeSpeedTest(port) {
  return new Promise(async (resolve) => {
    const result = { downMBps: 0, upMBps: 0, downError: '', upError: '' };
    // 下行：GET speed.cloudflare.com/__down 8MB 计时（解析 Content-Length，收到足量即完成；无长度则等 end；全程 30s 超时防挂起）
    try {
      const secure = await socks5ConnectTls(port, 'speed.cloudflare.com', 443, 15000);
      const start = Date.now();
      const data = await new Promise((res, rej) => {
        let b = Buffer.alloc(0), headersEnd = -1, need = -1, done = false;
        const to = setTimeout(() => { if (!done) { done = true; secure.destroy(); rej(new Error('下行超时')); } }, 30000);
        secure.write('GET /__down?bytes=8388608 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n');
        secure.on('data', (d) => {
          b = Buffer.concat([b, d]);
          if (need < 0 && headersEnd < 0) {
            const idx = b.indexOf('\r\n\r\n');
            if (idx >= 0) {
              headersEnd = idx + 4;
              const m = /Content-Length:\s*(\d+)/i.exec(b.toString('latin1', 0, idx));
              need = m ? parseInt(m[1], 10) : -1;
            }
          }
          if (!done && ((need === 0 && headersEnd >= 0) || (need > 0 && b.length >= headersEnd + need))) { done = true; clearTimeout(to); res(b); }
        });
        secure.on('end', () => { if (!done) { done = true; clearTimeout(to); res(b); } });
        secure.on('error', (e) => { if (!done) { done = true; clearTimeout(to); rej(e); } });
      });
      try { secure.destroy(); } catch (e) {}
      const body = data.slice(data.indexOf('\r\n\r\n') + 4);
      const secs = Math.max((Date.now() - start) / 1000, 0.01);
      result.downMBps = +(body.length / 1048576 / secs).toFixed(2);
      if (result.downMBps <= 0) result.downError = '下行无数据';
    } catch (e) { result.downError = e.message; }
    // 上行：POST speed.cloudflare.com/__up 2MB 计时（等响应头或 end；全程 30s 超时防挂起）
    try {
      const secure = await socks5ConnectTls(port, 'speed.cloudflare.com', 443, 15000);
      const body = Buffer.alloc(2097152, 0x61);
      const start = Date.now();
      await new Promise((res, rej) => {
        let b = Buffer.alloc(0), done = false;
        const to = setTimeout(() => { if (!done) { done = true; secure.destroy(); rej(new Error('上行超时')); } }, 30000);
        secure.write('POST /__up?bytes=2097152 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nContent-Type: application/octet-stream\r\nContent-Length: ' + body.length + '\r\nConnection: close\r\n\r\n');
        secure.write(body);
        secure.on('data', (d) => {
          b = Buffer.concat([b, d]);
          if (!done && b.indexOf('\r\n\r\n') >= 0) { done = true; clearTimeout(to); res(); }
        });
        secure.on('end', () => { if (!done) { done = true; clearTimeout(to); res(); } });
        secure.on('error', (e) => { if (!done) { done = true; clearTimeout(to); rej(e); } });
      });
      try { secure.destroy(); } catch (e) {}
      const secs = Math.max((Date.now() - start) / 1000, 0.01);
      result.upMBps = +(body.length / 1048576 / secs).toFixed(2);
      if (result.upMBps <= 0) result.upError = '上行无数据';
    } catch (e) { result.upError = e.message; }
    resolve(result);
  });
}

ipcMain.handle('node:test', async (event, { url }) => {
  if (!url || !url.trim()) return { success: false, error: '节点链接为空' };
  const u = url.trim();
  let base;
  if (/^socks5:\/\//i.test(u)) {
    base = await socks5Test(u);
  } else if (/^vless:\/\//i.test(u) || /^vmess:\/\//i.test(u)) {
    // v1.6.2：VLESS/VMESS 直接解析节点地址做真实连通测试（TCP 建连 + TLS 握手测延迟），不再要求本机代理客户端
    base = await proxyNodeProbe(u);
  } else {
    return { success: false, error: '暂不支持的节点格式（支持 socks5://、vless://、vmess://）' };
  }
  if (!base || !base.success) return base || { success: false, error: '节点不可达' };
  // v1.14.7 连通通过后：起独立 xray 实测下行/上行（不打断当前运行节点）
  try {
    const proc = new XrayProcess({ executable: unpackedPath(path.join(__dirname, 'xray-portable', 'xray.exe')) });
    const ep = await proc.startWithNode(u, await reserveTestPort());
    const sp = await nodeSpeedTest(ep.port);
    await proc.stop().catch(() => {});
    return { ...base, downMBps: sp.downMBps, upMBps: sp.upMBps, downError: sp.downError, upError: sp.upError };
  } catch (e) {
    return { ...base, downMBps: 0, upMBps: 0, downError: '测速引擎: ' + e.message };
  }
});

// v1.13.11 内置 xray 代理：节点保存（写 nodes.json，重启后软件自起内置代理）；代理状态查询
ipcMain.handle('node:save', (event, { nodes }) => {
  writeNodesFile(Array.isArray(nodes) ? nodes : []);
  return { ok: true, saved: Array.isArray(nodes) ? nodes.length : 0 };
});
// v1.14.19 节点权威来源：前端启动时从此处读回 nodes.json（localStorage 保存有异步落盘延迟，快速重启会丢节点）
ipcMain.handle('node:list', () => {
  const nodes = readNodesFile();
  return { nodes: nodes.map(n => ({ id: n.id, name: n.name || '', link: n.link })) };
});
ipcMain.handle('node:proxyStatus', () => ({
  enabled: _builtinProxyOn,
  running: !!(xrayRuntime && xrayRuntime.isRunning()),
  port: (xrayRuntime && xrayRuntime.endpoint() && xrayRuntime.endpoint().port) || (_builtinProxyOn ? XRAY_PROXY_PORT : 0),
}));

// 解析 vless/vmess 链接 → 服务器地址与是否 TLS
function parseProxyNodeUrl(str) {
  try {
    const s = str.trim();
    if (/^vmess:\/\//i.test(s)) {
      // vmess 常见两种：vless 式直写 或 base64(JSON)
      const b64 = s.replace(/^vmess:\/\//i, '');
      if (/^[A-Za-z0-9+/=]+$/.test(b64) && b64.length > 20) {
        try {
          const dec = Buffer.from(b64, 'base64').toString('utf8');
          const j = JSON.parse(dec);
          if (j && j.add && j.port) return { host: j.add, port: parseInt(j.port, 10), tls: (j.tls || '') === 'tls' || (j.tls || '') === '1', type: 'vmess', sni: j.sni || j.host || '' };
        } catch (e) {}
      }
      const at = b64.indexOf('@');
      const hp0 = (at >= 0 ? b64.slice(at + 1) : b64).split('?')[0];
      const idx = hp0.lastIndexOf(':');
      if (idx > 0) {
        let sni = '';
        try { const q = new URL(s); sni = q.searchParams.get('sni') || ''; } catch (e) {}
        return { host: hp0.slice(0, idx), port: parseInt(hp0.slice(idx + 1), 10), tls: /security=tls|security=reality/i.test(s), type: 'vmess', sni };
      }
    }
    if (/^vless:\/\//i.test(s)) {
      const rest = s.replace(/^vless:\/\//i, '');
      const at = rest.indexOf('@');
      const hp0 = (at >= 0 ? rest.slice(at + 1) : rest).split('?')[0];
      const idx = hp0.lastIndexOf(':');
      if (idx > 0) {
        // v1.14.3 reality/tls 节点必须用 sni= 参数做 SNI（用服务器 IP 做 SNI 会被 Reality 拒绝 → 节点测试误报失败）
        let sni = '';
        try { const q = new URL(s); sni = q.searchParams.get('sni') || ''; } catch (e) {}
        return { host: hp0.slice(0, idx), port: parseInt(hp0.slice(idx + 1), 10), tls: /security=tls|security=reality/i.test(s), type: 'vless', sni };
      }
    }
  } catch (e) {}
  return null;
}

// 直连节点服务器测连通与延迟（TCP + TLS 握手；非全链路代理，仅验证节点可达性与网络延迟）
function proxyNodeProbe(url) {
  return new Promise((resolve) => {
    const p = parseProxyNodeUrl(url);
    if (!p) return resolve({ success: false, error: '无法解析节点地址（格式：vless://uuid@host:port?security=tls... 或 vmess://...）' });
    const start = Date.now();
    // v1.14.3 用 sni= 参数做 TLS servername（Reality 节点必须，否则握手失败）
    const sock = p.tls ? tls.connect({ host: p.host, port: p.port, servername: p.sni || p.host, rejectUnauthorized: false }) : net.connect({ host: p.host, port: p.port });
    let done = false;
    let tcpMs = 0; // v1.14.7 延迟口径：TCP 建连耗时（1 次往返，与 v2rayN 同口径）；可用性仍由 TLS 握手判定（真实不变）
    const finish = (r) => { if (!done) { done = true; try { sock.destroy(); } catch (e) {} resolve(r); } };
    const timer = setTimeout(() => finish({ success: false, error: '连接超时（' + (p.tls ? 'TLS' : 'TCP') + ' 握手超过 6 秒）' }), 6000);
    sock.on('connect', () => {
      tcpMs = Date.now() - start;
      // TCP 已连通；TLS 模式下等 secureConnect
      if (!p.tls) { clearTimeout(timer); finish({ success: true, ip: p.host, ping: tcpMs, protocol: p.type + (p.tls ? '+tls' : '') + ' 连通测试' }); }
    });
    sock.on('secureConnect', () => { clearTimeout(timer); finish({ success: true, ip: p.host, ping: tcpMs, protocol: p.type + '+tls 连通测试' }); });
    sock.on('error', (e) => { clearTimeout(timer); finish({ success: false, error: '无法连接 ' + p.host + ':' + p.port + '（' + e.message + '）' }); });
    sock.on('timeout', () => { clearTimeout(timer); finish({ success: false, error: '连接超时' }); });
    sock.setTimeout(6000);
  });
}

// ============================================================
// FFmpeg 推流
// ============================================================
// v1.14.7 内置 curl：实时动态 im/fetch 的 curl fallback 原依赖系统 curl.exe（Windows 10 1803+ 自带），
// 精简版系统可能缺失 → 把 curl.exe（0.5MB，微软签名）内置到软件 curl\bin，优先内置，找不到再退回系统 PATH。
function findCurl() {
  const cands = [
    path.join(process.resourcesPath, 'app', 'curl', 'bin', 'curl.exe'),
    path.join(process.resourcesPath, 'app.asar.unpacked', 'curl', 'bin', 'curl.exe'),
    unpackedPath(path.join(__dirname, 'curl', 'bin', 'curl.exe')),
    path.join(app.getAppPath(), 'curl', 'bin', 'curl.exe'),
    'C:\\Windows\\System32\\curl.exe',
    'curl.exe',
  ];
  for (const c of cands) {
    try { if (c && fs.existsSync(c)) return c; } catch (e) {}
  }
  return null;
}

// v1.14.7 修复 FFmpeg ENOENT：旧实现无条件 return 第一个候选 'ffmpeg'（裸命令名），
// 新电脑 PATH 无 ffmpeg 时 spawn 报 ENOENT（-4058）——即使内置 ffmpeg.exe 就躺在软件目录里也没被用上。
// 现在：按真实路径逐候选 existsSync 验证（内置三处部署路径 + 常见安装位置），全部落空才退回 PATH 裸命令（且 spawnSync 真验证）。
function findFFmpeg() {
  const candidates = [
    path.join(process.resourcesPath, 'app', 'ffmpeg', 'bin', 'ffmpeg.exe'),
    path.join(process.resourcesPath, 'app.asar.unpacked', 'ffmpeg', 'bin', 'ffmpeg.exe'),
    unpackedPath(path.join(__dirname, 'ffmpeg', 'bin', 'ffmpeg.exe')),
    unpackedPath(path.join(app.getAppPath(), 'ffmpeg', 'bin', 'ffmpeg.exe')),
    'C:\\ffmpeg\\bin\\ffmpeg.exe',
    'C:\\Program Files\\ffmpeg\\bin\\ffmpeg.exe',
  ];
  for (const c of candidates) {
    try {
      if (c && fs.existsSync(c)) {
        const t = execSync('"' + c + '" -version', { stdio: ['ignore', 'ignore', 'ignore'], timeout: 8000 });
        return c;
      }
    } catch (e) {}
  }
  // 兜底：系统 PATH 里的 ffmpeg（spawnSync 真验证，避免裸名 ENOENT 误选）
  try {
    const { spawnSync } = require('child_process');
    const t = spawnSync('ffmpeg', ['-version'], { stdio: 'ignore', timeout: 8000 });
    if (t && !t.error) return 'ffmpeg';
  } catch (e) {}
  return null;
}

// v1.13.0 编码器自动选择：NVIDIA GPU(h264_nvenc) 优先（4 账号并发推流 CPU 友好），无则 libx264 软编码
// v1.14.9 修复：-encoders 列表有 nvenc ≠ 真实可用（驱动不完整时实际编码报 -40 Function not implemented / Could not open encoder，FFmpeg 启动 2-3 秒退出）
// → 新增实际编码验证，通过才启用 nvenc，失败立即回退 libx264
// v1.14.11 优化：验证提速（320x240→160x120、1s→0.4s）+ 结果缓存到磁盘（首次验证后不再重复耗时，换机/换卡后自动重测）
let cachedEncoder = null;
const ENC_CACHE_PATH = () => path.join(app.getPath('userData'), '_encoder_cache.json');
function getEncoderArgs() {
  if (cachedEncoder === null) {
    // 磁盘缓存：同机同驱动下编码器结论不变，避免每次启动都跑验证测试
    try {
      const _c = JSON.parse(fs.readFileSync(ENC_CACHE_PATH(), 'utf8'));
      if (_c && (_c.enc === 'nvenc' || _c.enc === 'libx264')) { cachedEncoder = _c.enc; }
    } catch (e) {}
  }
  if (cachedEncoder === null) {
    try {
      const { execSync } = require('child_process');
      const ff = findFFmpeg();
      if (ff) {
        const out = execSync('"' + ff + '" -hide_banner -encoders', { encoding: 'utf8', timeout: 20000 });
        if (/h264_nvenc/.test(out)) {
          try {
            execSync('"' + ff + '" -hide_banner -loglevel error -f lavfi -i testsrc=size=160x120:rate=5 -c:v h264_nvenc -preset p1 -t 0.4 -f null -', { stdio: ['ignore', 'ignore', 'ignore'], timeout: 15000 });
            cachedEncoder = 'nvenc';
            console.log('[推流] 编码器: h264_nvenc(NVIDIA GPU) 真实验证通过');
          } catch (e2) {
            cachedEncoder = 'libx264';
            console.log('[推流] 编码器: h264_nvenc 实际编码失败（' + (e2.message || '驱动不完整') + '），回退 libx264(CPU)');
          }
        } else {
          cachedEncoder = 'libx264';
        }
      } else {
        cachedEncoder = 'libx264';
      }
    } catch (e) { cachedEncoder = 'libx264'; }
    try { fs.writeFileSync(ENC_CACHE_PATH(), JSON.stringify({ enc: cachedEncoder, ts: Date.now() })); } catch (e) {}
    if (cachedEncoder === 'libx264') console.log('[推流] 编码器: libx264(CPU)');
  }
  if (cachedEncoder === 'nvenc') {
    return ['-c:v', 'h264_nvenc', '-preset', 'p5', '-tune', 'hq', '-b:v', '2500k', '-maxrate', '2500k', '-bufsize', '5000k', '-g', '30'];
  }
  return ['-c:v', 'libx264', '-preset', 'veryfast', '-b:v', '2500k', '-maxrate', '2500k', '-bufsize', '5000k', '-g', '30'];
}

// v1.14.10 默认素材动态查找：不再写死用户桌面路径（换电脑失效）→ 扫描 软件数据目录\默认素材 下的视频，存在才用；用户也可直接放任意视频进去
ipcMain.handle('assets:listDefaults', async () => {
  try {
    const dir = path.join(app.getPath('userData'), '默认素材');
    if (fs.existsSync(dir)) {
      return fs.readdirSync(dir)
        .filter(f => /\.(mp4|mkv|mov|flv|ts|webm)$/i.test(f))
        .map(f => path.join(dir, f));
    }
  } catch (e) {}
  return [];
});

ipcMain.handle('ffmpeg:check', async () => {
  const ffmpegPath = findFFmpeg();
  return { available: !!ffmpegPath, path: ffmpegPath };
});

// 探测 Windows 音频输入设备（dshow），存在则推流带麦克风声音，否则用静音轨保证推流稳定
function detectAudioDevice(timeoutMs) {
  return new Promise((resolve) => {
    const ffmpegPath = findFFmpeg();
    if (!ffmpegPath) return resolve(null);
    try {
      const probe = spawn(ffmpegPath, ['-hide_banner', '-f', 'dshow', '-list_devices', 'true', '-i', 'dummy'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      probe.stdout.on('data', d => out += d.toString());
      probe.stderr.on('data', d => out += d.toString());
      const timer = setTimeout(() => { try { probe.kill(); } catch (e) {} resolve(null); }, timeoutMs || 3500);
      probe.on('close', () => {
        clearTimeout(timer);
        // v1.9.10 只接受正常的设备名（字母数字空格-），空名/含换行的无效设备一律视为无设备（走静音轨兜底，不再崩溃）
        const m = out.match(/"([^"]+)"[^\n]*\(audio\)/i);
        let name = (m ? m[1] : '').replace(/\r?\n/g, '').trim();
        if (name && !/^[a-zA-Z0-9_ ()（）\-\u4e00-\u9fa5]+$/.test(name)) name = '';
        resolve(name || null);
      });
      probe.on('error', () => { clearTimeout(timer); resolve(null); });
    } catch (e) { resolve(null); }
  });
}

// 探测视频文件是否含音轨（用 ffmpeg -i 读 stderr，缓存结果）
const audioProbeCache = {}; // filePath -> bool
function probeAudioStream(filePath) {
  return new Promise((resolve) => {
    try {
      const st = fs.statSync(filePath);
      const cacheKey = filePath + ':' + st.size + ':' + st.mtimeMs;
      if (audioProbeCache[cacheKey] !== undefined) return resolve(audioProbeCache[cacheKey]);
      const ffmpegPath = findFFmpeg();
      if (!ffmpegPath) return resolve(false);
      const probe = spawn(ffmpegPath, ['-hide_banner', '-t', '1', '-i', filePath, '-f', 'null', '-'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      probe.stderr.on('data', d => out += d.toString());
      const timer = setTimeout(() => { try { probe.kill(); } catch (e) {} resolve(false); }, 8000);
      probe.on('close', () => {
        clearTimeout(timer);
        const hasAudio = /Stream #0:.*Audio/i.test(out);
        audioProbeCache[cacheKey] = hasAudio;
        resolve(hasAudio);
      });
      probe.on('error', () => { clearTimeout(timer); resolve(false); });
    } catch (e) { resolve(false); }
  });
}

// 组装最终推流地址（v1.6.2 关键修复）
// TikTok API 通道返回的 rtmp_push_url 已是「完整推流地址」：rtmp://host/stage/stream-{stream_id}?amun=...&sign=...
// 其中 stream id 就是推流密钥、签名就在 query 里——若再拼 '/streamKey' 会把签名 query 截断成非法地址，
// 导致推流连接失败，直播间无流、观众端显示默认摄像头画面。
// 仅当推流地址是纯服务器地址（不含 stream-、无 query）时，才按传统 RTMP + 推流码拼接。
function buildPushUrl(rtmpUrl, streamKey) {
  const u = (rtmpUrl || '').trim();
  if (!u) return '';
  if (/stream-/.test(u) || /\?/.test(u)) return u;
  return u + '/' + (streamKey || '');
}

// v1.13.11 探测本机代理（优先内置 xray 10888；桌面 v2rayN SOCKS5 10808/HTTP 10809 兜底；用于 MediaEgress 隧道）
function detectHttpProxy(port) {
  return new Promise((resolve) => {
    const candidates = port ? [Number(port)] : [XRAY_PROXY_PORT, 10808, 10809];
    const tryNext = (i) => {
      if (i >= candidates.length) { resolve(null); return; }
      const p = candidates[i];
      const s = net.connect(p, '127.0.0.1');
      s.setTimeout(1500);
      s.on('connect', () => { s.destroy(); resolve({ host: '127.0.0.1', port: p, type: (p === 10808 || p === XRAY_PROXY_PORT ? 'socks5' : 'http') }); });
      s.on('error', () => { try { s.destroy(); } catch (e) {} tryNext(i + 1); });
      s.on('timeout', () => { try { s.destroy(); } catch (e) {} tryNext(i + 1); });
    };
    tryNext(0);
  });
}

ipcMain.handle('stream:start', async (event, payload) => {
  const accountId = payload && payload.accountId;
  // v1.13.12 立即试探推流 + 自动重试：不再固定等 45 秒。
  // 点击后立即推流；若手机推流权未释放（duplicate）→ 10 秒后自动重试（最多 6 次/60 秒上限），成功即止，可点击取消。
  if (accountId) {
    if (autoStreamTimers[accountId]) { clearTimeout(autoStreamTimers[accountId]); delete autoStreamTimers[accountId]; }
    streamStartPayloads[accountId] = payload;
    // v1.14.11 duplicate 重试 8 次/15 秒间隔（覆盖平台释放推流权最长约 2 分钟；v1.14.10 之前 6 次/10 秒在释放期较长时不够）
    streamRetries[accountId] = { left: 8 };
    if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] 开始尝试推流（若手机推流权未释放会自动重试，最多 8 次）' });
  }
  return startStreamNow(accountId, payload);
});
async function startStreamNow(accountId, payload) {
  try {
  const { rtmpUrl, streamKey, videoFilePaths, roomId } = payload || {};
  if (!accountId) return { success: false, error: '缺少账号' };
  // v1.14.13 启动互斥：同一账号同一时刻只允许一个推流启动流程（防按钮连点/手动+自动重试叠加 → 多 FFmpeg 并发互相杀 → 服务器 not_allowed 风暴）
  if (streamStarting[accountId]) return { success: false, error: '推流正在启动中，请稍候（已忽略重复请求）' };
  streamStarting[accountId] = true;
  const ffmpegPath = findFFmpeg();
  // v1.13.0 编码器自动选择：NVIDIA GPU(h264_nvenc) 优先（4 账号并发推流 CPU 友好），无则 libx264 软编码
  // v1.14.9 若本账号推流时 nvenc 实际编码失败，回退标志已置位 → 直接 libx264 重推
  const encArgs = streamEncoderFallback[accountId] ? ['-c:v', 'libx264', '-preset', 'veryfast', '-b:v', '2500k', '-maxrate', '2500k', '-bufsize', '5000k', '-g', '30'] : getEncoderArgs();
  if (streamProcesses[accountId]) {
    // v1.14.11 杀旧进程时置位主动停止意图（旧进程 close 只收尾，不误清重试链）
    streamStopIntent[accountId] = true;
    stopStream(accountId);
  }
  // v1.14.11 旧进程已清理，本轮新进程是活跃推流 → 恢复意图标志（之后被动退出仍走 duplicate 重试逻辑）
  streamStopIntent[accountId] = false;
  // v1.14.11 stopStream 会清 streamRetries → 补回，保证本轮仍可 duplicate 自动重试（自动重试链保留递减计数，不覆盖）
  if (!streamRetries[accountId]) streamRetries[accountId] = { left: 8 };
  // v1.12.10 记录软件推流直播间（监控跟随：观众互动发生在该直播间）
  if (roomId) streamRooms[accountId] = String(roomId);
  if (streamKey) streamKeys[accountId] = String(streamKey);

  // v1.9.7 直播间就绪等待：create 后房间需 status=2（直播中）才能接受推流，否则 RTMP 被拒 FFmpeg 退出（首次推流必失败的根因）
  // v1.15.0 精简提速：最多等 3 次×1 秒（原 20 次；手机直播间模式房间已在播首次即 break；节点异常时快速放弃不阻塞推流尝试）
  if (roomId) {
    for (let i = 0; i < 3; i++) {
      const st = await getRoomStatusViaApi(accountId, String(roomId));
      if (st === 2) break;
      await sleep(1000);
    }
  }

  // ===== v1.12.52 FFmpeg 内置引擎（默认，已验证成功：unsigned + 当场码 + 直连，无需 OBS）=====
  // OBS 引擎仅在账号显式配置 useOBS=true 时启用（默认不启动 OBS，不弹窗、不常开）
  const useOBSEngine = (loadAccounts()[accountId] || {}).useOBS === true;
  const obsVideo = useOBSEngine && (Array.isArray(videoFilePaths) ? videoFilePaths : []).find(p => p && typeof p === 'string' && fs.existsSync(p));
  if (useOBSEngine && obsVideo) {
    try {
      console.log(`[OBS引擎] 房间 ${accountId} 尝试 OBS 推流（媒体源 ${obsVideo}）`);
      const engine = new OBSEngine();
      await engine.ensureRunning();
      const connected = await engine.connect();
      if (connected) {
        await engine.identify();
        const srcOk = await engine.ensureMediaSource(obsVideo);
        const streamOk = await engine.setStream(rtmpUrl, streamKey);
        const started = srcOk && streamOk && await engine.startStream();
        if (started) {
          // 推流启动 → 同步监控窗口房间号 + 8s 保护期
          if (monitors[accountId]) {
            if (roomId) monitors[accountId].roomId = String(roomId);
            monitors[accountId].streamGraceUntil = Date.now() + 8000;
          }
          engine._isOBS = true;
          engine._accountId = accountId;
          engine._roomId = roomId ? String(roomId) : '';
          engine._streamKey = streamKey ? String(streamKey) : '';
          streamProcesses[accountId] = engine;
          console.log(`[OBS引擎] 房间 ${accountId} OBS 推流已启动`);
          if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[OBS引擎] 推流已启动（OBS 视频源代替摄像头）' });
          // v1.15.0 推流中启动手机下播检测（识别手机端下播 → 自动停推+清码）
          try { startDownWatcher(accountId, roomId || streamRooms[accountId]); } catch (e) {}
          return { success: true, message: 'OBS 引擎推流已启动', via: 'obs' };
        }
        console.log('[OBS引擎] 启动失败，回退 FFmpeg');
        try { await engine.stopStream(); await engine.disconnect(); } catch (e) {}
      } else {
        console.log('[OBS引擎] 连接失败（OBS 未就绪），回退 FFmpeg');
      }
    } catch (e) {
      console.log('[OBS引擎] 异常，回退 FFmpeg:', e.message);
      try { if (engine) { await engine.disconnect(); } } catch (e2) {}
    }
  }

  // ===== FFmpeg 兜底（OBS 不可用时）=====
  if (!ffmpegPath) return { success: false, error: '未找到内置FFmpeg引擎（应在 resources\\app\\ffmpeg\\bin\\ffmpeg.exe 或 app.asar.unpacked\\ffmpeg\\bin\\ffmpeg.exe，约 97MB）。请重新安装软件或完整拷贝成品文件夹（含 ffmpeg 目录），不要只拷主程序' };

  const fullUrl = buildPushUrl(rtmpUrl, streamKey);
  console.log(`[推流] 房间 ${accountId} 开始 FFmpeg 推流到 ${fullUrl}`);

  // 视频原声轨：收集画面编辑器里所有含音轨的视频文件路径
  const audioFiles = [];
  if (Array.isArray(videoFilePaths)) {
    for (const p of videoFilePaths) {
      if (!p || typeof p !== 'string') continue;
      if (!fs.existsSync(p)) { console.log('[推流] 视频文件不存在，跳过:', p); continue; }
      const hasAudio = await probeAudioStream(p);
      if (hasAudio) audioFiles.push(p);
      else console.log('[推流] 视频无音轨，跳过音频:', p);
    }
  }
  console.log('[推流] 视频音轨源:', audioFiles.length > 0 ? audioFiles.length + ' 个视频' : '无（使用麦克风/静音轨）');

  const hasVideoAudio = audioFiles.length > 0;
  const audioDevice = hasVideoAudio ? null : await detectAudioDevice(3000);
  const useMic = !hasVideoAudio && audioDevice && audioDevice.trim();

  let args;
  // v1.12.52 手机流接管：有视频文件时直接视频直推（验证通过形态：视频文件 + unsigned + 当场码 + 直连）
  const videoFileDirect = (Array.isArray(videoFilePaths) ? videoFilePaths : []).find(p => p && typeof p === 'string' && fs.existsSync(p));
  if (videoFileDirect) {
    console.log('[推流] 视频文件直推（手机流接管形态）: ' + videoFileDirect);
    if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] 视频文件直推（手机流接管形态，unsigned 当场码）' });
    args = ['-nostdin', '-hide_banner', '-loglevel', 'error', '-re', '-stream_loop', '-1', '-i', videoFileDirect,
      '-vf', 'scale=720:1280:force_original_aspect_ratio=decrease,pad=720:1280:(ow-iw)/2:(oh-ih)/2',
      ...encArgs,
      '-pix_fmt', 'yuv420p', '-r', '30', '-c:a', 'aac', '-b:a', '128k', '-ar', '44100', '-ac', '2',
      '-map_metadata', '-1'];
  } else if (hasVideoAudio) {
    // 画面：image2pipe；音频：视频文件音轨 amix
    args = ['-y', '-f', 'image2pipe', '-framerate', '15', '-i', '-'];
    audioFiles.forEach(f => args.push('-stream_loop', '-1', '-i', f));
    const fcParts = audioFiles.map((_, i) => `[${i + 1}:a]aresample=44100,volume=1.0[a${i}]`);
    let mixExpr;
    if (audioFiles.length === 1) {
      mixExpr = '[a0]atrim=0:86400[aout]';
    } else {
      const ins = audioFiles.map((_, i) => `[a${i}]`).join('');
      mixExpr = `${ins}amix=inputs=${audioFiles.length}:normalize=0,atrim=0:86400[aout]`;
    }
    args.push('-filter_complex', fcParts.join(';') + ';' + mixExpr, '-map', '0:v', '-map', '[aout]');
  } else {
    // 无视频音轨：麦克风或静音轨兜底
    const audioInputs = useMic
      ? ['-f', 'dshow', '-i', 'audio=' + audioDevice]
      : ['-f', 'lavfi', '-i', 'anullsrc=channel_layout=stereo:sample_rate=44100'];
    args = ['-y', '-f', 'image2pipe', '-framerate', '15', '-i', '-', ...audioInputs, '-map', '0:v', '-map', '1:a'];
    console.log('[推流] 音频输入:', useMic ? ('麦克风 ' + audioDevice) : '静音轨（未探测到音频设备）');
  }
  if (!videoFileDirect) {
    args.push(
      // v1.12.51 固定输出 720x1280（与 SEI push_video_width/height 一致，防 invalid_sign）
      '-vf', 'scale=720:1280:force_original_aspect_ratio=decrease,pad=720:1280:(ow-iw)/2:(oh-ih)/2',
      ...encArgs,
      '-pix_fmt', 'yuv420p',
      '-r', '30', '-c:a', 'aac', '-b:a', '128k', '-ar', '44100',
      '-map_metadata', '-1',
    );
  }
  // v1.12.52 手机流接管：unsigned 直推，不需要帧签名（帧签名仅伴侣流 create 场景；手机流实测无签名被服务器接受）
  let frameSigner = null;

  // v1.12.49 抖歪式推流：MediaEgress 本机隧道（FFmpeg 推本机 → TCP 透传 TikTok，解决直推 not_allowed）
  let pushTarget = fullUrl;
  let egressOut = null;
  try {
    // v1.13.13 RTMP 隧道走代理：实测直连 TikTok RTMP（push-rtmp-f5-tt03… 1935/443）不可达 → 必须经代理出口（内置 xray 10888 优先、桌面 v2 10808 兜底）；代理不可用才回退直连
    let proxy = null;
    try {
      const _detected = await detectHttpProxy(null);
      if (_detected) proxy = _detected;
    } catch (e) {}
    if (proxy) {
      console.log('[推流] RTMP 隧道走代理 ' + proxy.host + ':' + proxy.port + ' (' + proxy.type + ')');
      if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] RTMP 经代理出口（' + proxy.port + '）推流' });
    } else {
      console.log('[推流] 未检测到可用代理（10888/10808/10809），RTMP 直连（当前网络直连 TikTok 可能不可达，失败请检查节点）');
      if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] 未检测到可用代理，RTMP 直连（直连 TikTok 可能不通，失败请检查节点管理里的节点）' });
    }
    const egress = new MediaEgress({ proxy });
    const out = await egress.start(fullUrl);
    mediaEgresses[accountId] = egress;
    egressOut = out;
    console.log(`[推流] MediaEgress隧道已启动: app=${out.args[0]} 本机=${out.url} 代理=${proxy ? ('127.0.0.1:' + proxy.port) : '直连'}`);
    if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: `[推流] 本机隧道转发已启动（抖歪式${proxy ? ' 代理' : ' 直连'}）` });
  } catch (e) {
    console.log('[推流] MediaEgress启动失败，用完整URL兜底:', e.message);
    try {
      const _u = new URL(fullUrl);
      const _pathname = _u.pathname || '';
      const _idx = _pathname.lastIndexOf('/');
      if (_idx > 0 && _idx < _pathname.length - 1) {
        const _app = _pathname.slice(1, _idx);
        const _playpath = _pathname.slice(_idx + 1) + _u.search;
        if (_app && _playpath) {
          args.push('-rtmp_app', _app, '-rtmp_playpath', _playpath);
          pushTarget = _u.protocol + '//' + _u.host + '/' + _app;
        }
      }
    } catch (e2) { console.log('[推流] 推流地址解析失败，用完整URL:', e2.message); }
  }

  // v1.12.52 unsigned：手机流接管不用帧签名管道（useSignPipe=false；egress 直连当场码即可）
  const useSignPipe = false;
  if (useSignPipe) {
    args.push('-f', 'flv', '-flush_packets', '1', 'pipe:1');
  } else {
    if (egressOut) {
      // v1.12.52 修正：unsigned 也走 MediaEgress 本机隧道（展开完整 egress args：-rtmp_app/-rtmp_playpath/-rtmp_tcurl，推本机端口）
      // 之前直推完整 URL（无 tcurl/丢 playpath）→ FFmpeg 连接失败 → 触发 stream:stopped → 推流码被清空（用户实测"推流码掉了"）
      args.push(...egressOut.args);
      args.push('-f', 'flv', egressOut.url);
    } else {
      args.push('-f', 'flv', pushTarget);
    }
  }
  try {
    const proc = spawn(ffmpegPath, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    streamProcesses[accountId] = proc;
    let proc2 = null, transform = null;
    if (useSignPipe && egressOut) {
      // FFmpeg#2（签名输出）：收管道 → 直推 MediaEgress（-rtmp_app/-rtmp_playpath/-rtmp_tcurl 由 egress 提供，tcUrl=真实服务器）
      const args2 = ['-nostdin', '-hide_banner', '-loglevel', 'error',
        '-f', 'flv', '-i', 'pipe:0',
        '-map', '0:v:0', '-map', '0:a?', '-c', 'copy', '-rw_timeout', '15000000',
        ...(/^rtmps:/i.test(egressOut.args[5] || '') ? ['-tls_verify', '1'] : []),
        ...egressOut.args,
        '-f', 'flv', egressOut.url];
      proc2 = spawn(ffmpegPath, args2, { stdio: ['pipe', 'ignore', 'pipe'] });
      transform = new FlvSeiTransform({
        signer: frameSigner,
        width: 720, height: 1280,   // 与编码输出 -vf scale=720:1280 一致（防 invalid_sign）
      });
      proc.stdout.pipe(transform).pipe(proc2.stdin);
      frameSignerTransforms[accountId] = transform;
      console.log('[帧签名] 签名管道已启动（FlvSeiTransform → FFmpeg#2 → MediaEgress）');
      proc2.stderr.on('data', (data) => {
        const msg = data.toString();
        try { fs.appendFileSync(FF_STDERR, '[SEI:' + new Date().toISOString() + '] ' + msg); } catch (e) {}
        if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: msg });
      });
      proc2.on('error', (err) => { console.error('[推流] FFmpeg#2 启动失败:', err.message); });
      proc2.on('close', (code) => {
        console.log(`[推流] 房间 ${accountId} FFmpeg#2(签名输出)退出，代码 ${code}`);
        try { proc.kill('SIGKILL'); } catch (e) {}
      });
    }
    // v1.9.7 推流启动 → 同步监控窗口房间号 + 8s 保护期（避免 pollIm 把软件自己刚创建的新直播间误判为"被替换"而自动停流）
    if (monitors[accountId]) {
      if (roomId) monitors[accountId].roomId = String(roomId);
      monitors[accountId].streamGraceUntil = Date.now() + 8000;
    }
    // v1.15.0 推流中启动手机下播检测（识别手机端下播 → 自动停推+清码）
    try { startDownWatcher(accountId, roomId || streamRooms[accountId]); } catch (e) {}
    // v1.13.9 stderr 缓存（close 时判断 duplicate 等服务器拒绝原因，给前端明确提示）
    let _stderrBuf = '';
    proc.stderr.on('data', (data) => {
      const msg = data.toString();
      if (_stderrBuf.length < 8192) _stderrBuf += msg;
      try { fs.appendFileSync(FF_STDERR, '[' + new Date().toISOString() + '] ' + msg); } catch (e) {}
      if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: msg });
    });
    proc.on('error', (err) => {
      console.error('[推流] FFmpeg启动失败:', err.message);
      if (mainWindow) mainWindow.webContents.send('stream:error', { accountId, error: err.message });
      delete streamProcesses[accountId];
    });
    proc.on('close', (code) => {
      console.log(`[推流] 房间 ${accountId} FFmpeg退出，代码 ${code}`);
      try { fs.appendFileSync(FF_STDERR, '=== FFmpeg退出 code=' + code + ' ===\n'); } catch (e) {}
      // v1.14.11 主动停止 / 或该进程已被新进程替换（如自动重试期间旧进程 close）：只收尾，不处理重试链与通知，避免竞态误清
      if (streamStopIntent[accountId] || streamProcesses[accountId] !== proc) {
        try { fs.appendFileSync(FF_STDERR, '=== 旧进程/主动停止 close，跳过重试处理 ===\n'); } catch (e) {}
        return;
      }
      // v1.14.11 当前活跃进程已退出 → 先清引用，后续 duplicate/编码器回退分支的 !streamProcesses[accountId] 才能成立（此前 close 时引用未清导致自动重试从不触发）
      delete streamProcesses[accountId];
      // v1.14.9 编码器实际不可用检测：FFmpeg 启动 2-3 秒退出 code -40（4294967256）且 stderr 含编码器错误
      // → 立即自动回退 libx264 重推（同一当场码），无需用户干预；本会话该账号固定 libx264
      const _encFail = (code === -40 || code === 4294967256 || /Could not open encoder|Function not implemented|Cannot open (?:NVIDIA|video) encoder/i.test(_stderrBuf));
      if (_encFail && !streamEncoderFallback[accountId] && streamStartPayloads[accountId] && !streamProcesses[accountId]) {
        streamEncoderFallback[accountId] = true;
        console.log('[推流] 房间 ' + accountId + ' 检测到 GPU 编码器实际不可用（code=' + code + '），自动回退 libx264 重推');
        if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] GPU 编码器实际不可用，自动回退 CPU 编码重推…' });
        const _payload = streamStartPayloads[accountId];
        const _eg2 = mediaEgresses[accountId];
        if (_eg2) { try { _eg2.close(); } catch (e) {} delete mediaEgresses[accountId]; }
        delete streamProcesses[accountId];
        startStreamNow(accountId, _payload).catch(e => {
          console.error('[推流] libx264 回退重推失败:', e.message);
          if (mainWindow) mainWindow.webContents.send('stream:error', { accountId, error: 'libx264 回退重推失败: ' + e.message });
        });
        return;
      }
      // v1.13.9 服务器拒绝原因（duplicate=同房间已有手机推流）→ 前端明确提示，不再让用户猜
      const _dup = /rscr\.Code:duplicate|Code:duplicate|duplicate/i.test(_stderrBuf);
      // v1.14.15 服务器关闭连接（api_close，非用户停止/非编码器失败）→ 与 duplicate 同链自动重试：
      // 实测场景：手机断网+推流权已释放后软件接管成功，但 78 秒左右服务器 api_close（流会话抖动/服务器临时关闭），重试可恢复
      const _apiClose = /rscr\.Code:api_close|Code:api_close|api_close/i.test(_stderrBuf);
      // v1.13.12 duplicate 自动重试：手机断网后平台释放推流权通常 10-30 秒（实测有时更久）；点击后立即试探，未释放则自动重试
      // v1.14.11 重试间隔 10s → 15s（释放期最长约 2 分钟，6 次/60s 不够）；修复重试链被旧进程 close 误清的问题
      const _retry = streamRetries[accountId];
      if ((_dup || _apiClose) && _retry && _retry.left > 0 && !streamProcesses[accountId]) {
        _retry.left--;
        const _payload = streamStartPayloads[accountId];
        if (mainWindow) mainWindow.webContents.send('stream:stopped', { accountId, code, duplicate: _dup, retrying: true });
        const _why = _dup ? '推流权未释放（duplicate）' : '服务器关闭连接（api_close）';
        if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] ' + _why + '，15 秒后自动重试（剩余 ' + _retry.left + ' 次，可点按钮取消）' });
        autoStreamTimers[accountId] = setTimeout(() => {
          delete autoStreamTimers[accountId];
          if (_payload) {
            startStreamNow(accountId, _payload).catch(e => {
              console.error('[推流] 自动重试失败:', e.message);
              if (mainWindow) mainWindow.webContents.send('stream:error', { accountId, error: '自动重试失败: ' + e.message });
              delete streamRetries[accountId];
            });
          }
        }, 15000);
        // 清理本路（隧道等），但保留重试链
        if (proc2) { try { proc2.kill('SIGKILL'); } catch (e) {} }
        if (transform) { try { transform.destroy(); } catch (e) {} }
        delete frameSignerTransforms[accountId];
        delete frameSigners[accountId];
        const _eg2 = mediaEgresses[accountId];
        if (_eg2) { try { _eg2.close(); } catch (e) {} delete mediaEgresses[accountId]; }
        delete streamProcesses[accountId];
        return;
      }
      delete streamRetries[accountId];
      if (mainWindow) mainWindow.webContents.send('stream:stopped', { accountId, code, duplicate: _dup });
      // v1.12.50 清理签名管道
      if (proc2) { try { proc2.kill('SIGKILL'); } catch (e) {} }
      if (transform) { try { transform.destroy(); } catch (e) {} }
      delete frameSignerTransforms[accountId];
      delete frameSigners[accountId];
      // v1.12.49 FFmpeg 退出 → 关闭 MediaEgress 本机隧道
      const _eg2 = mediaEgresses[accountId];
      if (_eg2) { try { _eg2.close(); } catch (e) {} delete mediaEgresses[accountId]; }
      // v1.13.8 FFmpeg 退出/结束 → 不再自动关手机直播间（用户要求手动下播手机）
      // 保留 streamRooms/streamKeys（推流码不立即清空，UI 仍显示，便于用户判断/重新获取当场新码）
      const _rid = streamRooms[accountId];
      if (_rid) {
        // 只提示，不自动 status=4 关房间（用户手动下播手机，避免平台把房间结束导致后续推流码失效）
        console.log(`[推流] 房间 ${accountId} 推流已停止（如需下播请手动关闭手机端直播间）`);
      }
    });
    proc.stdin.on('error', () => {});
    if (mainWindow) mainWindow.webContents.send('stream:log', { accountId, log: '[推流] 推流已启动（开始向直播间推流）' });
    return { success: true, message: '推流已启动' };
  } catch (e) { return { success: false, error: e.message }; }
  } finally { delete streamStarting[accountId]; }
}

ipcMain.handle('stream:pushFrame', async (event, { accountId, frameData }) => {
  const proc = streamProcesses[accountId];
  // v1.12.47 OBS 引擎模式：OBS 直接播放视频文件，不需要帧推送
  if (proc && proc._isOBS) return { success: true, via: 'obs' };
  if (!proc || !proc.stdin || proc.stdin.destroyed) return { success: false, error: '推流进程不存在' };
  try {
    proc.stdin.write(Buffer.from(frameData, 'base64'));
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('stream:stop', async (event, { accountId }) => {
  await stopStream(accountId);
  return { success: true };
});

async function stopStream(accountId, opts) {
  // v1.14.11 主动停止意图：置位后旧进程 close 只做轻量收尾（不重试、不清重试链、不重复发 stopped）
  streamStopIntent[accountId] = true;
  // v1.15.0 opts.autoDown = 手机下播检测自动停止（区别于用户手动停止）
  delete streamStarting[accountId]; // v1.14.13 停止 → 解除启动互斥（若正在启动中）
  // v1.13.11 取消待执行的自动推流 / v1.13.12 取消 duplicate 重试链
  if (autoStreamTimers[accountId]) { clearTimeout(autoStreamTimers[accountId]); delete autoStreamTimers[accountId]; }
  delete streamRetries[accountId];
  const proc = streamProcesses[accountId];
  if (proc) {
    // v1.12.47 OBS 引擎：StopStream + 优雅关闭(Shutdown) + 断开 WebSocket；否则 FFmpeg kill
    if (proc._isOBS) {
      try { await proc.stopStream(); } catch (e) {}
      try { await proc.shutdown(); } catch (e) {}
      try { await proc.disconnect(); } catch (e) {}
      console.log(`[OBS引擎] 房间 ${accountId} 已停止`);
    } else {
      try {
        proc.stdin?.end();
        proc.kill('SIGTERM');
        setTimeout(() => { if (!proc.killed) proc.kill('SIGKILL'); }, 3000);
      } catch (e) {}
    }
    delete streamProcesses[accountId];
    // v1.12.49 关闭 MediaEgress 本机隧道（抖歪式）
    const _eg = mediaEgresses[accountId];
    if (_eg) { try { _eg.close(); } catch (e) {} delete mediaEgresses[accountId]; }
    // v1.14.11 主动停止也通知前端复位按钮（原来只靠 close 事件，kill 后 close 被 intent 拦截会漏通知）
    if (mainWindow) mainWindow.webContents.send('stream:stopped', { accountId, code: 0, user: true, autoDown: !!(opts && opts.autoDown) });
    // v1.13.8 停止推流不再自动 status=4 关房间（用户要求手动下播手机；保留码显示，便于判断）
    console.log(`[推流] 房间 ${accountId} 已停止（如需下播请手动关闭手机端直播间）`);
  }
  // v1.15.0 停止推流 → 停止该账号下播检测轮询
  stopDownWatcher(accountId);
}

// ---------- v1.15.0 手机下播自动检测 ----------
// 软件推流中每 30 秒查一次房间状态；识别手机端下播（房间不再直播）→ 自动停推 + 清空推流码 + 状态复位
// 防误判：网络查询失败(-1)连续 3 次才判；非直播状态连续 2 次才判
const downWatchers = {};
function startDownWatcher(accountId, roomId) {
  stopDownWatcher(accountId);
  if (!roomId) return;
  downWatchers[accountId] = { timer: null, failCount: 0, nonLiveCount: 0 };
  const w = downWatchers[accountId];
  w.timer = setInterval(async () => {
    try {
      // v1.15.0 自停：推流进程与重试链都不存在（推流已彻底结束）→ watcher 不再空转轮询
      if (!streamProcesses[accountId] && !streamRetries[accountId] && !autoStreamTimers[accountId]) {
        stopDownWatcher(accountId);
        return;
      }
      const st = await getRoomStatusViaApi(accountId, String(roomId));
      if (st === 2) { w.failCount = 0; w.nonLiveCount = 0; return; } // 房间仍在直播
      if (st === -1) {
        w.failCount++;
        if (w.failCount < 3) return; // 网络失败连续 3 次才判定（防节点波动误杀）
      } else {
        w.nonLiveCount++;
        // v1.15.9 非直播 1 次即判定（之前 2 次太慢，用户手动下播后软件还在重推）——平台状态一变立即停
        if (w.nonLiveCount < 1) return;
      }
      // 判定手机端下播 → 收尾
      stopDownWatcher(accountId);
      // v1.15.37 下播瞬间同步暂停监控：页面渲染"直播已结束"前残留的推荐流礼物/评论（图三 swat_skydiamond 假礼物）不再被推
      if (monitors[accountId]) { monitors[accountId].clearedFlag = true; monitors[accountId].roomId = ''; }
      console.log('[下播检测] 房间', accountId, '识别到手机端下播（房间状态 ' + st + '）→ 自动停推 + 清空推流码');
      sendToUI('stream:log', { accountId, log: '[下播检测] 识别到手机端下播：自动停止推流并清空推流码（下次开播重新获取）' });
      try { await stopStream(accountId, { autoDown: true }); } catch (e) {}
      // v1.15.3 手机下播 → 实时监控弹窗不关闭，数据只暂停保留（v1.15.32：下播不调 stopMonitor，弹窗留着等用户手动停止监控才关+清空）
      // 暂停由 pollDom 的"直播已结束"检测触发（sendMonitorCleared → clearedFlag）
      try {
        const accs = loadAccounts();
        const a = accs[accountId];
        if (a) {
          a.streamKey = ''; a.rtmpUrl = ''; a.roomId = ''; a.streaming = false; a.status = 'connected';
          saveAccounts(accs);
        }
      } catch (e) {}
      try { if (streamRooms[accountId]) delete streamRooms[accountId]; } catch (e) {}
      try { if (streamKeys[accountId]) delete streamKeys[accountId]; } catch (e) {}
      try { if (streamRetries[accountId]) delete streamRetries[accountId]; } catch (e) {}
      try { if (autoStreamTimers[accountId]) { clearTimeout(autoStreamTimers[accountId]); delete autoStreamTimers[accountId]; } } catch (e) {}
      sendToUI('tiktok:progress', { accountId, percent: 100, text: '已识别手机端下播：推流已停止，推流码已清空' });
      // v1.15.4 下播 → 通知前端清空界面推流码显示（存储已清，界面同步刷新）
      sendToUI('tiktok:stream-cleared', { accountId });
    } catch (e) { console.log('[下播检测] 房间', accountId, '轮询异常:', e.message); }
  }, 20000); // v1.15.9 下播检测轮询 30s→20s（更快识别手机下播，避免下播后软件还在自动重推）
}
function stopDownWatcher(accountId) {
  const w = downWatchers[accountId];
  if (w) { if (w.timer) { try { clearInterval(w.timer); } catch (e) {} } delete downWatchers[accountId]; }
}

// v1.12.11 停止推流后关闭直播间（抖歪同款 status=4，避免观众端残留黑屏直播）
async function closeRoomViaApi(accountId, roomId, streamId) {
  let capWin = findLiveDataWindow(accountId);
  let tempWin = null;
  // v1.12.41 无数据窗口时临时开隐藏直播页（页面上下文同源 fetch 带浏览器签名，Node 直连被 URL 校验拒绝 10013）
  if (!capWin) {
    try {
      const info = loadAccounts()[accountId];
      const name = info && info.name ? String(info.name).replace(/^@/, '') : '';
      tempWin = createAccountWindow(accountId, { title: '单端关房', width: 480, height: 360, show: false });
      await injectSavedCookies(accountId, tempWin.webContents.session);
      await tempWin.loadURL('https://www.tiktok.com/@' + encodeURIComponent(name) + '/live', { userAgent: UA });
      await sleep(6000);
      capWin = tempWin;
    } catch (e) { console.log('[推流] 关房临时窗口失败:', e.message); }
  }
  try {
    if (capWin) {
      const res = await Promise.race([
        capWin.webContents.executeJavaScript(`(async () => {
          const common = 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&live_mode=6';
          const body = 'status=4&room_id=${roomId}' + ('${streamId}' ? '&stream_id=${streamId}' : '');
          for (const p of ['status', 'finish', 'close']) {
            try {
              const r = await fetch('https://webcast.tiktok.com/webcast/room/' + p + '/?' + common, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
              const t = await r.text();
              if (r.status === 200 && (t.indexOf('"data"') >= 0 || t.indexOf('status_code') >= 0)) return 'OK:' + p + ':' + t.slice(0, 60);
            } catch (e) {}
          }
          return 'FAIL';
        })()`, true),
        sleep(15000).then(() => 'TIMEOUT')
      ]);
      console.log('[推流] 关房间 status=4 ->', String(res).slice(0, 140));
      if (String(res).indexOf('OK:') === 0) {
        try { sendProgress(accountId, 99, '已关闭手机直播间（单端达成，手机端将被挤下播）'); } catch (e) {}
        if (tempWin) { try { tempWin.destroy(); } catch (e) {} }
        return true;
      } else {
        try { sendProgress(accountId, 99, '关闭手机直播间未成功（' + String(res).slice(0, 30) + '）'); } catch (e) {}
      }
      if (tempWin) { try { tempWin.destroy(); } catch (e) {} }
    }
  } catch (e) { console.log('[推流] 关房间(页面)失败:', e.message); }
  if (tempWin) { try { tempWin.destroy(); } catch (e) {} }
  // fallback：Node 直连（v1.12.40 多接口轮试 status/finish/close + 结果写日志）
  try {
    const info = loadAccounts()[accountId];
    if (!info) return;
    // v1.12.34 签名服务：配置了 Key 时关房间请求也带签名头（不被风控）
    const signHeaders = await getSignHeaders(accountId, info);
    const headers = { 'User-Agent': UA, 'Accept': 'application/json', 'Cookie': buildCookieHeader(info), 'sdk_aid': '8311', 'Referer': 'https://www.tiktok.com/', 'Content-Type': 'application/x-www-form-urlencoded', ...signHeaders };
    const csrf = getCsrfToken(info);
    if (csrf) headers['x-tt-passport-csrf-token'] = csrf;
    const common = 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&live_mode=6';
    const body = 'status=4&room_id=' + encodeURIComponent(roomId) + (streamId ? '&stream_id=' + encodeURIComponent(streamId) : '');
    for (const ep of ['status', 'finish', 'close']) {
      try {
        const r = await httpsJson('https://webcast.tiktok.com/webcast/room/' + ep + '/?' + common, { method: 'POST', headers, body });
        const ok = r.status === 200 && (r.text || '').indexOf('"data"') >= 0;
        console.log('[推流] 关房间(Node) ' + ep + ' ->', r.status || r.error || '', ok ? 'OK' : (r.text || '').slice(0, 60));
        if (ok) { try { sendProgress(accountId, 99, '已关闭手机直播间（单端达成，手机端将被挤下播）'); } catch (e) {} return true; }
      } catch (e) {}
    }
    try { sendProgress(accountId, 99, '关闭手机直播间未成功（平台未响应）'); } catch (e) {}
    return false;
  } catch (e) { console.log('[推流] 关房间(Node)失败:', e.message); }
  return false;
}

// ============================================================
// 文件选择 / 版本
// ============================================================
ipcMain.handle('dialog:openFile', async (event, { filters }) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: filters || [
      { name: '媒体文件', extensions: ['mp4', 'mov', 'avi', 'mkv', 'webm', 'jpg', 'jpeg', 'png', 'gif'] },
      { name: '所有文件', extensions: ['*'] },
    ],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('app:version', async () => app.getVersion());

// ============================================================
// v1.8.0 实时监控引擎：IM 轮询（互动数据）+ 风险扫描（官方通道规则）
//  - 每房间独立后台监控窗口（隐藏，加载 @user/live 主播页，同源 fetch 带 Cookie）
//  - IM：webcast/im/fetch Studio 通道（aid=8311）→ 轻量 protobuf 解析 → 推送前端
//  - 风险：周期性读页面文本 → classifyRiskInfo（16 类风险规则移植）→ 命中弹提示
// ============================================================
const monitors = {};      // accountId -> { win, imTimer, riskTimer, roomId, cursor, running }
const riskLastSent = {};  // accountId -> { key -> ts } 同类风险 5 分钟内不重复弹
// v1.14.11 风险告警整体停用（用户实测反馈数据不准确、误报多：直播正常时误报"状态异常"、礼物文案误判）。保留全部代码，改此开关为 true 可一键恢复
const RISK_ALERTS_ENABLED = false;
const IM_POLL_MS = 4000;      // v1.15.9 互动轮询间隔 8s→4s（pollIm 每 16s 查官方在线数，观众进出更快记录）
const RISK_POLL_MS = 12000;   // 风险扫描间隔
const RISK_DEDUP_MS = 5 * 60 * 1000;

function monitorStateOf(accountId) {
  const m = monitors[accountId];
  return m ? { running: true, roomId: m.roomId || '' } : { running: false };
}
// v1.10.0 独立监控窗口（可拖出软件页面外）映射：accountId → 监控UI BrowserWindow
const monitorUIs = {};
function sendToUI(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, data);
  // v1.10.0 独立监控窗口同步接收（弹窗可拖出软件页面外仍实时更新）
  if (data && data.accountId && monitorUIs[data.accountId]) {
    const w = monitorUIs[data.accountId];
    if (w && !w.isDestroyed()) w.webContents.send(channel, data);
  }
}

// ---------- v1.12.43 手机下播提醒（醒目但不抢焦点：系统通知+软件内横幅+蜂鸣，自动检测手机下播后停止） ----------
// v1.14.11 僵尸清理：startPhoneDownReminder 函数已删除（用户已确认不需要"自动检测被顶并提示"；手机下播提示看实时动态即可）。
// 保留 reminderTimers 与 phoneDownConfirm IPC（前端确认按钮仍调用，响应 success 兼容）
const reminderTimers = {};
ipcMain.handle('tiktok:phoneDownConfirm', (event, { accountId }) => {
  try { if (reminderTimers[accountId]) { clearInterval(reminderTimers[accountId]); delete reminderTimers[accountId]; } } catch (e) {}
  return { success: true };
});

// ---------- 轻量 protobuf 读取器（TikTok webcast 消息） ----------
function pbFields(buf, start, end, depth) {
  const out = [];
  let off = start || 0;
  const len = end || buf.length;
  while (off < len) {
    let tag = 0, shift = 0, b = 0;
    do { b = buf[off++]; tag |= (b & 0x7f) << shift; shift += 7; if (shift > 70) return out; } while (b & 0x80);
    const field = tag >>> 3, wt = tag & 7;
    if (wt === 0) {
      let v = 0, s = 0, bb = 0;
      do { bb = buf[off++]; v += (bb & 0x7f) * Math.pow(2, s); s += 7; if (s > 70) break; } while (bb & 0x80);
      out.push({ f: field, t: 'varint', v });
    } else if (wt === 1) { off += 8; }
    else if (wt === 2) {
      let sl = 0, ss = 0, bb = 0;
      do { bb = buf[off++]; sl += (bb & 0x7f) * Math.pow(2, ss); ss += 7; if (ss > 70) break; } while (bb & 0x80);
      if (sl < 0 || off + sl > len) break;
      const raw = buf.slice(off, off + sl); off += sl;
      let text = null;
      try { text = raw.toString('utf8'); } catch (e) {}
      const printable = text && text.length > 0 && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(text) &&
        /^[\x20-\x7E\u00A0-\uFFFF\u4E00-\u9FFF]*$/.test(text);
      if (printable) out.push({ f: field, t: 'str', v: text });
      else out.push({ f: field, t: 'msg', raw, fields: depth >= 1 ? [] : pbFields(raw, 0, raw.length, 1) });
    }
    else if (wt === 5) { off += 4; }
    else break;
  }
  return out;
}

// v1.13.0 评论内容清洗/过滤（防虚假评论：系统文案/序号/重复昵称混入实时动态）
function isSystemCommentText(s) {
  if (!s) return true;
  if (s.length > 200) return true;
  if (/^[\s\d.,:;'"\-!?]+$/.test(s)) return true; // v1.13.8 纯数字短评论("111")不再当系统文本过滤
  if (/(已加入|赞了直播|欢迎使用|社区自律公约|年满|必须.*才能|充值|赠送|进入直播间|分享了直播|关注了主播|系统提示|直播已结束|正在加载|加载中)/.test(s)) return true;
  // v1.15.19 页面导航/非聊天元素过滤（监控窗口页面含侧边导航：这些被聊天容器选择器误抓 → 全当评论 → 评论数虚高）
  // v1.15.20 增加英文按钮/推荐流入口：Recharge（充值）、More（更多）
  // v1.15.23 单行推荐流元素：LIVE 徽标 / 直播 N（观众数）/ 立即观看（引导文案）
  // v1.15.25 推荐流区块：推荐的直播 / 开启直播 / 与观众即时互动（误当评论/进场）
  if (/(发现直播|LIVE Studio|创作者工具|公司计划条款|^返回$|^更多$|^More$|Recharge|^TikTok$|推荐的主播|^LIVE\s+|^LIVE$|^直播\s*\d+$|立即观看|主播推荐|看更多|猜你喜欢|你可能喜欢|推荐的直播|开启直播|与观众即时互动)/.test(s)) return true;
  // 长系统文案中的"第N条评论/消息"（"第第1"这类短评论内容不误杀）
  if (s.length > 8 && /第\s*\d.*(评论|条|消息|次)/.test(s)) return true;
  return false;
}
function cleanCommentText(c, nickname) {
  if (!c) return '';
  let out = String(c).replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  // 去重复：整句重复（"X X"）→ 取一半
  const halves = out.split(/ {2,}/).filter(Boolean);
  if (halves.length === 2 && halves[0] === halves[1]) out = halves[0];
  // 首词重复（"X X Y" / "Mardin Mardin Abi"）→ 去首重复
  const words = out.split(' ');
  if (words.length >= 2 && words[0] === words[1]) { words.shift(); out = words.join(' '); }
  // 内容等于昵称 → 视为解析错（丢弃）
  if (nickname && out === nickname) return '';
  return out;
}
function pickChatContent(fields, strs, nickname) {
  // 1) 标准字段 3（str）
  let c = (fields.find(x => x.f === 3 && x.t === 'str') || {}).v || '';
  if (isSystemCommentText(c) || c === nickname) c = '';
  // 2) 新版结构：field 4/5/7/6（str）
  if (!c) {
    for (const f of [4, 5, 7, 6]) {
      const v = (fields.find(x => x.f === f && x.t === 'str') || {}).v || '';
      if (!isSystemCommentText(v) && v !== nickname) { c = v; break; }
    }
  }
  // 3) 其他 str 候选（排除昵称/系统词/纯数字/超长）
  if (!c) {
    const cands = (strs || []).filter(s => s && s !== nickname && !isSystemCommentText(s) && !/^[\d\s.,:;'"\-]+$/.test(s));
    if (cands.length) c = cands[0];
  }
  return cleanCommentText(c, nickname);
}

// 解析单条 IM 消息（启发式：按常见 webcast schema 字段号提取，兜底输出原文）
function parseImMessage(msg) {
  const method = msg.method || '';
  try {
    const buf = Buffer.from(msg.payload || '', 'base64');
    const fields = pbFields(buf, 0, buf.length, 0);
    const strFields = fields.filter(x => x.t === 'str').map(x => x.v);
    const varintFields = fields.filter(x => x.t === 'varint').map(x => x.v);
    const out = { method, nickname: '', content: '', giftName: '', online: 0, likeCount: 1, giftCount: 1, rawStrings: strFields };

    // 用户昵称：User 子消息（field 2）内优先 field 3(nickname)/field 4(displayId)，再兜底非数字 str
    const userMsg = fields.find(x => x.f === 2 && x.t === 'msg');
    if (userMsg && userMsg.fields) {
      const nf = userMsg.fields.find(x => x.f === 3 && x.t === 'str') || userMsg.fields.find(x => x.f === 4 && x.t === 'str') ||
        userMsg.fields.find(x => x.t === 'str' && x.v && !/^\d+$/.test(x.v));
      if (nf) out.nickname = nf.v;
    }
    if (!out.nickname) {
      const nf = strFields.find(s => s && s.length < 40 && !/^https?:/i.test(s) && !/^[\d\s.,:;'"\-]+$/.test(s));
      if (nf) out.nickname = nf;
    }

    if (method === 'WebcastChatMessage') {
      out.content = pickChatContent(fields, strFields, out.nickname);
    } else if (method === 'WebcastLikeMessage') {
      const lc = fields.find(x => x.f === 3 && x.t === 'varint') || fields.find(x => x.f === 4 && x.t === 'varint') || fields.find(x => x.f === 6 && x.t === 'varint');
      out.likeCount = (lc && lc.v) || 1;
    } else if (method === 'WebcastGiftMessage') {
      const gMsg = fields.find(x => x.f === 3 && x.t === 'msg');
      if (gMsg && gMsg.fields) {
        const nf = gMsg.fields.find(x => x.f === 4 && x.t === 'str') || gMsg.fields.find(x => x.t === 'str');
        if (nf) out.giftName = nf.v;
      }
      const rc = fields.find(x => x.f === 6 && x.t === 'varint') || fields.find(x => x.f === 9 && x.t === 'varint');
      out.giftCount = (rc && rc.v) || 1;
    } else if (method === 'WebcastRoomUserSeqMessage') {
      const t = fields.find(x => x.f === 3 && x.t === 'varint') || fields.find(x => x.f === 5 && x.t === 'varint');
      out.online = (t && t.v) || 0;
    }
    // v1.13.8 系统文本词不当昵称（im/fetch 偶发返回系统 MemberMessage：推荐直播/1名观众/直播已结束等）
    if (out.nickname && /推荐直播|推荐的主播|1名观众|直播已结束|直播已暂停|已暂停|进入了直播间|主播推荐|系统消息|观众已进入|正在加载|加载中|还没有在线观众|还没有观众|暂无观众|^观众[·\s]*\d*$|^最新$|^第\s*\d+$|^\d+$/i.test(out.nickname)) out.nickname = '';
    return out;
  } catch (e) { return { method, nickname: '', content: '', giftName: '', online: 0, likeCount: 1, giftCount: 1, rawStrings: [], error: e.message }; }
}

function imEventToFeedItem(ev) {
  const user = ev.nickname || '';
  const ts = Date.now();
  // v1.13.8 推荐流系统消息过滤（未开播时 im/fetch 偶发返回 TikTok 推荐流消息 → 零假数据）
  if (ev.method === 'WebcastMemberMessage') {
    const raw = user + ' ' + (ev.action || '') + ' ' + (ev.rawStrings || []).join(' ');
    if (/推荐直播|推荐的主播|recommended|推荐主播/i.test(raw)) return null;
    if (!user) return null; // 进场无昵称 → 无意义（解析失败或系统推荐流），不产生条目
  }
  switch (ev.method) {
    case 'WebcastChatMessage': {
      // v1.13.0 虚假评论过滤：解析后为空/系统文案/与昵称重复 → 不生成条目（实时动态零虚假数据）
      const text = cleanCommentText(ev.content || '', user);
      if (!text || isSystemCommentText(text) || text === user) return null;
      return { type: 'comment', user, text, ts };
    }
    case 'WebcastLikeMessage': return { type: 'like', user, likeCount: ev.likeCount || 1, text: '点赞了直播' + (ev.likeCount > 1 ? ' ×' + ev.likeCount : ''), ts };
    case 'WebcastLikeCountMessage': return { type: 'like', user: '', likeCount: ev.likeCount || 0, isTotal: true, text: '点赞', ts };
    case 'WebcastGiftMessage': return { type: 'gift', user, text: '送出了礼物 ' + (ev.giftName || '礼物') + (ev.giftCount > 1 ? ' ×' + ev.giftCount : ''), giftCount: ev.giftCount || 1, ts };
    case 'WebcastMemberMessage': return { type: 'enter', user, text: '进入了直播间', ts };
    case 'WebcastSocialMessage': return { type: 'follow', user, text: '关注了主播', ts };
    case 'WebcastRoomUserSeqMessage': return null; // v1.10.0 在线事件不加入动态流（在线数走顶部数据栏，动态只显示观众对话）
    default: {
      const hint = (ev.rawStrings || []).filter(s => s && s.length < 60 && !/^https?:/i.test(s)).slice(0, 2).join(' ');
      return { type: 'system', user: '', text: (ev.method || '互动事件') + (hint ? ' · ' + hint : ''), ts };
    }
  }
}

// ---------- 风险分类（TikTok直播 risk-classify 完整规则移植，用户已授权） ----------
const STATUS_WORDS = ['停用', '被封', '已封', '封禁', '被关闭', '关闭', '暂停', '已被暂停', '已限制', '受限', '被限流', '限流', '无法', '不能', '暂时无法', '不再', '禁止', '被禁', '已禁', '下架', '中断', '扣除', '降权', '权限受限', '流量及权限受限', '违规已被', 'disabled', 'banned', 'suspended', 'taken down', 'not eligible', 'has ended', 'permanently ended', 'can\'t', 'blocked', 'removed', 'restricted'];
const RISK_CATEGORY_RULES = [
  { key: 'verify', cn: '需要验证', detail: 'TikTok 要求完成滑块或真人（人机）验证，通常由登录环境异常或操作频繁触发。', advice: '在窗口内完成滑块/验证码验证后重试；如频繁出现请检查节点与登录环境。', severity: 'mid', needVerify: true, match: ['verify', 'verification code', 'slide to verify', 'captcha', 'puzzle verification', '验证码', '滑块', '真人验证', '人脸验证', '实名认证', '操作过于频繁', '操作频繁', '登录已过期', 'log in to tiktok'] },
  { key: 'sexual', cn: '色情内容违规', detail: '包含裸露、色情或性暗示内容已被立即强制关闭。', advice: '立即下播并移除违规画面，避免账号被永久限制。', severity: 'high', match: ['sexual content', 'sexually explicit content', '色情内容', '性暗示'], weak: ['裸露', '全裸', '半裸', '色情', '性挑逗', '露骨', '裸体'] },
  { key: 'authenticity', cn: '真实性与诚信违规', detail: '违反关于真实性与诚信的规定已被中断，账号流量及权限受限（虚假互动/群控/冒充/欺诈）。', advice: '停止虚假互动、群控等行为，用真实账号真实互动，按提示申诉。', severity: 'mid', match: ['违反关于真实性与诚信的规定已被中断', '真实性与诚信', '账号流量及权限受限', 'authenticity', 'inauthentic behavior', 'deceptive commercial practices', '虚假互动与群控', '虚假互动'], weak: ['群控', '刷量', '刷赞', '刷粉', '虚假观众', '机器评论', '冒充', '水军', '控评', 'coordinated', 'artificial'] },
  { key: 'recorded', cn: '录播/循环画面/挂机无互动', detail: '平台判定直播在播放预录视频、电影电视片段、往期回放、动态或3D循环画面、多段切片拼接，或长时间静态无人、纯风景/萌宠监控、仅放音乐/电台/ASMR 而缺乏真人实时互动，已暂停直播（非真人实时直播违规）。', advice: '保持画面有人/有真实互动或周期性真人出镜，避免纯循环录播；若被暂停按提示整改后重开。', severity: 'mid', match: ['previously recorded', 'static image', 'inauthentic or low-quality', '循环画面', '预录视频轮播', '无人直播', 'reused content'], weak: ['录播', '循环轮播', '挂机', '无人出镜', '往期回放', '预录', '动态循环', 'pre-recorded', 'prerecorded', 'recorded', 'static', 'low-quality'] },
  { key: 'minor', cn: '未成年人违规', detail: '涉及未成年人单独开播或未成年人出镜无成人陪同，已限制直播。', advice: '未成年人不得独自开播；若未成年人出镜须有成年监护人全程陪同，立即下播调整。', severity: 'high', match: ['未成年人单独', '未成年人开播', 'underage user', 'minor safety', '系统检测到未成年人'], weak: ['儿童', '童模', '小孩', 'minor', 'child'] },
  { key: 'banned', cn: '直播被封禁/停播', detail: '直播已被临时或永久封禁，账号可能暂停开播。', advice: '查看封禁时长（如“X分钟后可重新开播”），期间不要反复重试开播；严重封禁需申诉。', severity: 'mid', match: ['被封禁', '停播', '禁播', '直播已被临时封禁', '分钟后可重新开播', 'permanently banned', 'permanently suspended', 'temporarily suspended', 'temporarily banned', 'account has been suspended', 'taken down', 'access denied', 'banned'], weak: ['封禁', '被封', '禁播', '停播', 'suspended', 'banned'] },
  { key: 'gift_ban_combo', cn: '送礼功能被封禁且直播被限流', detail: '送礼功能被封禁，且直播被限流。', advice: '停止诱导送礼与违规互动，按提示申诉恢复送礼与流量。', severity: 'mid', comboPriority: true, match: ['送礼功能被封禁，且', '且直播被限流', 'gift suspended and', 'gifting disabled and', 'disabled and your live has been limited'] },
  { key: 'gift_ban', cn: '送礼（打赏）功能被停', detail: '该直播间的送礼（打赏）功能被平台关闭，观众暂时无法送礼物；直播画面本身可能仍在继续。', advice: '检查是否诱导打赏/违规变现；按提示整改，必要时申诉恢复送礼功能。', severity: 'mid', match: ['送礼功能被停', '送礼功能暂停', '送礼被暂停', '收礼功能关闭', '不能送礼', '暂时无法送', '暂不可送礼', '暂时关闭送礼', '暂时无法赠送', 'gifting is disabled', 'gifting has been suspended', 'gifts are disabled', 'can\'t send gifts', 'gifting unavailable', 'gifting is unavailable', 'gifts temporarily', 'gift is temporarily', 'try again in'], weak: ['送礼物', '送礼功能', '送礼', 'gifting', 'send gifts'] },
  { key: 'redirect', cn: '站外导流违规', detail: '检测到引导观众离开 TikTok 平台（站外导流/引流）的违规行为。', advice: '立即移除站外联系方式与导流话术，避免账号被永久限制。', severity: 'high', match: ['redirect viewers', '站外导流', '站外引流', '第三方独立站'], weak: ['telegram', '电报', '微信', '邮箱', 'paypal', '亚马逊店铺', '私域', 'off platform', 'external', 'third party'] },
  { key: 'politics', cn: '政治敏感违规', detail: '涉及地缘政治冲突、宗教对立、种族歧视、敏感历史事件等违规内容。', advice: '立即移除相关内容并下播，避免账号被永久限制。', severity: 'high', match: ['地缘政治冲突', '宗教对立', '种族歧视', '敏感历史事件', 'political'], weak: ['政治', '宗教', '种族', '歧视', '地缘', '冲突', '灾难', '悲剧', 'political', 'racial'] },
  { key: 'copyright', cn: '知识产权侵权', detail: '直播内容涉及版权/商标侵权（盗播、盗版素材等）。', advice: '移除侵权素材，避免多次侵权导致账号封禁。', severity: 'mid', match: ['知识产权侵权', 'infringement'], weak: ['版权', '侵权', '盗版', '商标', 'infring'] },
  { key: 'region_ban', cn: '直播在部分地区被禁止', detail: '平台限制了该直播在某些国家/地区的可见性，这些地区的观众将看不到你的直播。', advice: '核对目标地区与内容是否符合当地法规及 TikTok 地区政策；如判定有误，点「提交意见反馈」申诉。', severity: 'mid', match: ['地区被禁止', '部分地区不可见', 'not available in your region'], weak: ['some regions', 'region'] },
  { key: 'partial_restrict', cn: '部分观众限制', detail: '直播被限制向部分观众展示（限流降权）。', advice: '提升内容原创度与真实互动，避免重复/搬运/录播，持续产出合规原创内容以恢复推荐。', severity: 'mid', match: ['限制向部分观众展示', '限制向部分观众', '部分观众无法看到', 'partially restricted', 'limited number of viewers can'], weak: ['部分观众', 'limited group'] },
  { key: 'throttled', cn: '直播被限流', detail: '直播被限制推荐/流量（限流），曝光减少。', advice: '提升内容原创度与真实互动，避免重复/搬运/录播、水印与违规话术，持续产出合规原创内容以恢复推荐。', severity: 'mid', match: ['被限流', '直播限流', '减少曝光', '直播推荐已减少', '降低你的直播曝光', '限制流量推荐', 'reduced distribution', 'limited distribution', 'reduced reach', 'limited reach', 'isn\'t eligible for recommendation', 'your live is not eligible', 'reduce the reach'], weak: ['限流', 'throttled'] },
  { key: 'violation', cn: '违反社区规则', detail: '直播因违反社区规则被处罚（可含虚假互动、站外引流、搬运等）。', advice: '立刻移除违规要素，查看对应规则条目，按指引申诉/Appeal，避免用同类内容再次开播。', severity: 'mid', match: ['违反社区规则', 'violates community guidelines', '违规已被', 'violation'], weak: ['预录制', '抄袭', '搬运', '重制内容', '违规', '处罚', '社区公约', '申诉', 'penalty', 'strike', 'community guidelines'] },
  { key: 'warning', cn: '系统警告/违规预警', detail: '平台发出系统警告，检测到你的直播可能存在异常行为。', advice: '重视本次预警，立即自查直播内容、画面与话术，避免再次触发导致升级处罚。', severity: 'mid', match: ['系统警告', '违规警告', '检测到你的直播', '直播可能存在异常', '异常行为', 'account warning', 'account strike', 'warning'], weak: ['警告', 'warning'] },
];

function classifyRiskInfo(info) {
  // v1.12.38 先剔除系统横幅/公约文案（避免"送出了礼物 礼物"等误判为风险告警）
  const rawText = String(((info && info.title) || '') + '\n' + ((info && info.text) || '') + '\n' + ((info && info.url) || ''));
  const cleaned = rawText.replace(/欢迎使用 TikTok 直播[\s\S]*?(?:社区自律公约。|直播。)/g, ' ').replace(/创作者必须[\s\S]*?开启直播。/g, ' ').replace(/观众必须[\s\S]*?礼物。/g, ' ');
  const text = cleaned.toLowerCase();
  const hasStrong = (rule) => rule.match && rule.match.some(w => { try { return text.includes(String(w).toLowerCase()); } catch (e) { return false; } });
  const hasWeak = (rule) => rule.weak && rule.weak.some(w => { try { return text.includes(String(w).toLowerCase()); } catch (e) { return false; } });
  const hasStatusWord = () => STATUS_WORDS.some(w => text.includes(String(w).toLowerCase()));
  const pick = (rule) => ({ key: rule.key, cn: rule.cn, detail: rule.detail, advice: rule.advice, severity: rule.severity || 'mid', needVerify: !!rule.needVerify });
  const combo = RISK_CATEGORY_RULES.find(r => r.comboPriority);
  if (combo && hasStrong(combo)) return pick(combo);
  for (const rule of RISK_CATEGORY_RULES) { if (hasStrong(rule)) return pick(rule); }
  if (hasStatusWord()) {
    for (const rule of RISK_CATEGORY_RULES) { if (hasWeak(rule)) return pick(rule); }
    return { key: 'generic', cn: '直播状态异常', detail: '检测到直播状态词（封禁/暂停/受限/中断等），请打开直播间窗口查看系统具体提示。', advice: '点开直播窗口查看系统具体提示，按提示处理，必要时提交意见反馈。', severity: 'mid', needVerify: false };
  }
  return null;
}

// ---------- 监控数据通道（v1.8.2 起用主进程 Node https 直连，绕开 TikTok 页面 fetch 劫持） ----------
const STUDIO_COMMON = 'aid=8311&app_name=tiktok_live_studio&device_id=7689692413648635393&install_id=7689693516830754581&channel=studio&version_code=1.36.6&device_platform=windows&timezone_name=America%2FLos_Angeles&screen_width=1920&screen_height=1080&browser_language=en-US&browser_platform=Win32&browser_name=Mozilla&browser_version=' + encodeURIComponent(UA) + '&language=en&app_language=en&webcast_language=en&priority_region=US&webcast_sdk_version=1366&live_mode=6';

function httpsJson(url, opts) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const method = (opts && opts.method) || 'GET';
      const headers = (opts && opts.headers) || {};
      const body = opts && opts.body;
      const _tmo = (opts && opts.timeout) || 15000; // v1.15.0 支持单次调用指定超时（房间查询类传 8 秒快速失败）
      const parseRes = (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            const buf = Buffer.concat(chunks);
            let text = buf.toString('utf8');
            const enc = String(res.headers['content-encoding'] || '').toLowerCase();
            if (enc.includes('gzip')) { try { text = zlib.gunzipSync(buf).toString('utf8'); } catch (e) {} }
            else if (enc.includes('deflate')) { try { text = zlib.inflateSync(buf).toString('utf8'); } catch (e) {} }
            resolve({ status: res.statusCode, text });
          } catch (e) { resolve({ status: res.statusCode, error: e.message }); }
        });
      };
      // v1.15.2 修复：优先 electronNet（Chromium 浏览器 TLS 指纹 + defaultSession 代理 10888）。
      // 实测根因：node+socks（socks-proxy-agent）的 Node TLS 指纹被 TikTok 服务端断开
      // （"Client network socket disconnected before secure TLS connection was established"），
      // 而 curl / electronNet（浏览器指纹）正常 → 查询房间号/获取推流码必须走 electronNet 才不被拒。
      if (typeof electronNet !== 'undefined' && electronNet.request) {
        try {
          const hdrs = Object.assign({}, headers);
          if (body && !hdrs['Content-Length']) hdrs['Content-Length'] = Buffer.byteLength(body);
          const req = electronNet.request({ method, url, headers: hdrs });
          req.on('response', parseRes);
          req.on('error', (e) => resolve({ error: e.message }));
          if (body) req.write(body);
          req.end();
          return;
        } catch (eNet) { console.log('[httpsJson] electronNet 异常，回退 socks:', eNet.message); }
      }
      // 回退：node + socks（TLS 可能被 TikTok 拒，仅 electronNet 不可用时使用）
      if (_effectiveProxy && /^socks5:\/\//.test(_effectiveProxy)) {
        import('socks-proxy-agent').then(({ SocksProxyAgent }) => {
          try {
            const agent = new SocksProxyAgent(_effectiveProxy);
            const req = https.request({ hostname: u.hostname, port: 443, path: u.pathname + u.search, method, headers, agent }, parseRes);
            req.on('error', (e) => resolve({ error: e.message }));
            req.setTimeout(_tmo, () => { try { req.destroy(new Error('timeout')); } catch (e) {} });
            if (body) req.write(body);
            req.end();
          } catch (e2) { resolve({ error: e2.message }); }
        }).catch(() => {
          const req = https.request({ hostname: u.hostname, port: 443, path: u.pathname + u.search, method, headers }, parseRes);
          req.on('error', (e) => resolve({ error: e.message }));
          req.setTimeout(_tmo, () => { try { req.destroy(new Error('timeout')); } catch (e) {} });
          if (body) req.write(body);
          req.end();
        });
        return;
      }
      // 无代理可用：node 直连（被墙时超时，最后兜底）
      const req = https.request({
        hostname: u.hostname, port: 443, path: u.pathname + u.search,
        method, headers,
      }, parseRes);
      req.on('error', (e) => resolve({ error: e.message }));
      req.setTimeout(_tmo, () => { try { req.destroy(new Error('timeout')); } catch (e) {} });
      if (body) req.write(body);
      req.end();
    } catch (e) { resolve({ error: e.message }); }
  });
}

function buildCookieHeader(info) {
  try {
    const now = Date.now() / 1000;
    return (info.cookies || []).filter(c => !c.expirationDate || c.expirationDate > now)
      .map(c => c.name + '=' + c.value).join('; ');
  } catch (e) { return ''; }
}

// 当前直播间 roomId（主播视角 api-live/user/room）
async function getRoomIdViaApi(accountId, accountName) {
  try {
    const info = loadAccounts()[accountId];
    const cookie = buildCookieHeader(info);
    // v1.12.36 签名直连（api-live 无签名被风控返回空 → 手机直播间模式直接失效；签名后不被拦）
    const signHeaders = await getSignHeaders(accountId, info);
    const headers = { 'User-Agent': UA, 'Accept': 'application/json', 'Cookie': cookie, ...signHeaders };
    const url = 'https://www.tiktok.com/api-live/user/room/?aid=1988&sourceType=54&uniqueId=' + encodeURIComponent(String(accountName || '').replace(/^@/, ''));
    // v1.15.0 房间查询快速失败：8 秒超时（原 15 秒），节点不通时不再白等
    const r = await httpsJson(url, { headers, timeout: 8000 });
    if (r.status === 200 && r.text) {
      const j = JSON.parse(r.text);
      const rid = j && j.data && j.data.user && j.data.user.roomId;
      if (rid) return String(rid);
      // v1.12.37 诊断：手机直播间房间号拿不到（签名/风控/未开播）→ 软件日志可见
      try { sendProgress(accountId, 57, '查询直播间房间号无结果（手机未开播或接口拦截）：' + (r.text || '').slice(0, 120)); } catch (e) {}
      return '';
    }
    try { sendProgress(accountId, 57, '查询直播间房间号失败：' + (r.error || ('HTTP ' + r.status))); } catch (e) {}
    return '';
  } catch (e) { console.log('[监控] roomId获取:', e.message); return ''; }
}

// v1.9.6 直播间状态（room/info status：2=直播中，其他=未开播/已结束）
async function getRoomStatusViaApi(accountId, roomId) {
  try {
    const info = loadAccounts()[accountId];
    const cookie = buildCookieHeader(info);
    const csrf = getCsrfToken(info);
    const headers = { 'User-Agent': UA, 'Accept': 'application/json', 'Cookie': cookie, 'sdk_aid': '8311' };
    if (csrf) headers['x-tt-passport-csrf-token'] = csrf;
    const url = 'https://webcast.tiktok.com/webcast/room/info/?' + STUDIO_COMMON + '&room_id=' + roomId;
    // v1.15.0 房间状态快速失败：8 秒超时（原 15 秒），节点不通时不再白等
    const r = await httpsJson(url, { headers, timeout: 8000 });
    if (r.status === 200 && r.text) {
      const j = JSON.parse(r.text);
      const d = j && j.data;
      const st = d && d.status;
      // v1.15.3 在线人数：room/info 官方 user_count → 更新监控在线数（IM 通道不保证返回 RoomUserSeqMessage）
      if (d && typeof d.user_count === 'number' && monitors[accountId]) {
        try { monitors[accountId].onlineCount = d.user_count; } catch (e) {}
      }
      return typeof st === 'number' ? st : -1;
    }
    return -1;
  } catch (e) { console.log('[监控] 房间状态:', e.message); return -1; }
}

// v1.9.6 直播间下播/结束 → 前端实时数据自动清零
// v1.13.3 去重：同一下播状态只清一次（观众页持续显示"直播已结束"时避免每 4 秒重复清空刷日志）；
// 有新数据/房间切换时重置（见 pollDom/pollIm/直播间切换处）
function sendMonitorCleared(accountId, reason) {
  const mon = monitors[accountId];
  if (mon && mon.clearedFlag) return;
  if (mon) mon.clearedFlag = true;
  // v1.13.8 下播清零 → 同时重置 DOM/互动去重状态（下一场重新记录，不被旧场次的"已加入/赞了直播"文本去重吞掉）
  try {
    if (domSeen[accountId]) domSeen[accountId] = { set: new Set(), list: [] };
    if (domPanelLast[accountId]) domPanelLast[accountId] = { gifts: 0, comments: 0, likes: 0 };
  } catch (e) {}
  sendToUI('tiktok:monitor-cleared', { accountId, reason });
  // v1.15.34 主进程强制推在线 0（双保险：任何暂停/下播场景在线立即归 0，不冻结旧数字）
  sendToUI('tiktok:im-events', { accountId, items: [], methods: [], online: 0 });
  console.log('[监控] 房间', accountId, reason, '→ 实时数据已自动清零');
}

// v1.9.6 单端开播：软件推流中若直播间被替换/下播 → 自动停止推流（避免手机+软件双开）
// v1.12.13 禁用自动停流：等效单端已由"create 成功后自动关手机直播间"实现（v1.12.12），
// 自动停流反而误杀推流（FFmpeg code=null，用户实测"推流自己掉了"）→ 只告警不杀流
function stopStreamIfStreaming(accountId, reason) {
  // v1.9.7 保护期：软件刚开播（自己 create 的新直播间）roomId 变化不触发停流，避免误杀
  const mon = monitors[accountId];
  if (mon && mon.streamGraceUntil && Date.now() < mon.streamGraceUntil) return;
  if (streamProcesses[accountId]) {
    sendToUI('tiktok:monitor-state', { accountId, running: true, warning: reason });
    console.log('[单端开播] 房间', accountId, reason, '（v1.12.13 不再自动停流，等效单端由关手机直播间实现）');
  }
}

// webcast/im/fetch Studio 通道（aid=8311 + 主播 Cookie）
async function imFetchViaApi(accountId, roomId, cursor) {
  // v1.15.36 IM 通道修复：im/fetch 补 history_len（拉取历史评论）+ enter_from + unique_id（主播身份），修复"观众页有评论但面板 0"
  const _info0 = loadAccounts()[accountId];
  const _un0 = _info0 && _info0.name ? String(_info0.name).replace(/^@/, '') : '';
  const IM_EXTRA = '&history_len=50&enter_from=studio_live_room&unique_id=' + encodeURIComponent(_un0);
  // v1.12.14 页面上下文优先（数据窗口内 fetch 带完整签名）；数据窗口已关闭（获取推流码后自动关窗）时回退用监控窗口（直播页，同域带 Cookie）
  try {
    let capWin = findLiveDataWindow(accountId);
    if (!capWin && monitors[accountId] && monitors[accountId].win && !monitors[accountId].win.isDestroyed()) capWin = monitors[accountId].win;
    if (capWin) {
      const res = await Promise.race([
        capWin.webContents.executeJavaScript(`(async () => {
          try {
            const common = '${STUDIO_COMMON}${IM_EXTRA}';
            const resp = await fetch('https://webcast.tiktok.com/webcast/im/fetch/?' + common + '&room_id=${roomId}', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cursor: '${String(cursor || '').replace(/'/g, "\\'")}', internal_ext: '{}' }) });
            const txt = await resp.text();
            const j = JSON.parse(txt);
            if (j.status_code === 0) return JSON.stringify({ ok: true, cursor: (j.data && j.data.cursor) || '', messages: (j.data && j.data.messages) || [] });
            return JSON.stringify({ ok: false, code: j.status_code });
          } catch (e) { return JSON.stringify({ ok: false, error: e.message }); }
        })()`, true),
        sleep(12000).then(() => 'TIMEOUT')
      ]);
      if (res && res !== 'TIMEOUT' && res !== '') {
        const j = JSON.parse(res);
        if (j.ok) return j;
      }
    }
  } catch (e) {}
  // fallback Node 直连
  try {
    const info = loadAccounts()[accountId];
    const cookie = buildCookieHeader(info);
    const csrf = getCsrfToken(info);
    const headers = {
      'User-Agent': UA, 'Accept': 'application/json', 'Accept-Encoding': 'gzip, deflate, br',
      'Content-Type': 'application/json', 'Cookie': cookie, 'sdk_aid': '8311',
    };
    if (csrf) headers['x-tt-passport-csrf-token'] = csrf;
    const url = 'https://webcast.tiktok.com/webcast/im/fetch/?' + STUDIO_COMMON + IM_EXTRA + '&room_id=' + roomId;
    const r = await httpsJson(url, { method: 'POST', headers, body: JSON.stringify({ cursor: cursor || '', internal_ext: '{}' }) });
    if (r.status === 200 && r.text) {
      const j = JSON.parse(r.text);
      if (j.status_code === 0) {
        const msgs = (j.data && j.data.messages) || [];
        return { ok: true, cursor: (j.data && j.data.cursor) || '', messages: msgs };
      }
      return { ok: false, code: j.status_code };
    }
    return { ok: false, code: r.status, error: r.error };
  } catch (e) { /* 继续 curl fallback */ }
  // v1.13.15 curl+代理 fallback（electronNet 对超长 URL 报 ERR_INVALID_ARGUMENT；curl 走内置 xray/v2rayN 实测 status_code=0）
  try {
    const info = loadAccounts()[accountId];
    const cookie = buildCookieHeader(info);
    const csrf = getCsrfToken(info);
    const proxy = await detectHttpProxy(null);
    const proxyHost = '127.0.0.1:' + (proxy && proxy.port ? proxy.port : XRAY_PROXY_PORT);
    const args = ['--socks5-hostname', proxyHost, '-m', '15', '-s', '-X', 'POST',
      '-H', 'User-Agent: ' + UA, '-H', 'Accept: application/json', '-H', 'Accept-Encoding: gzip, deflate, br',
      '-H', 'Content-Type: application/json', '-H', 'Cookie: ' + cookie, '-H', 'sdk_aid: 8311'];
    if (csrf) args.push('-H', 'x-tt-passport-csrf-token: ' + csrf);
    args.push('--data-binary', JSON.stringify({ cursor: cursor || '', internal_ext: '{}' }));
    args.push('https://webcast.tiktok.com/webcast/im/fetch/?' + STUDIO_COMMON + IM_EXTRA + '&room_id=' + roomId);
    const { execFileSync } = require('child_process');
    const buf = execFileSync(findCurl() || 'curl.exe', args, { encoding: 'buffer', timeout: 25000 });
    let text;
    try { text = zlib.gunzipSync(buf).toString('utf8'); } catch (e) { text = buf.toString('utf8'); }
    if (text) {
      const j = JSON.parse(text);
      if (j.status_code === 0) {
        const msgs = (j.data && j.data.messages) || [];
        return { ok: true, cursor: (j.data && j.data.cursor) || '', messages: msgs, via: 'curl' };
      }
      return { ok: false, code: j.status_code };
    }
    return { ok: false, error: 'curl empty' };
  } catch (e) { return { ok: false, error: e.message }; }
}

// v1.10.0 直播画面小电视已移除（v1.13.0 起监控窗口隐藏，用户要看直播间画面 → 打开直播间按钮）；TV_RECT_SCRIPT 已删（v1.14.11 僵尸清理）

const RISK_SCAN_SCRIPT = `(() => {
  try {
    var t = document.title || '';
    var u = location.href || '';
    var body = (document.body && document.body.innerText) || '';
    return JSON.stringify({ title: t, url: u, text: body.slice(0, 8000) });
  } catch (e) { return JSON.stringify({ title: '', url: '', text: '' }); }
})()`;

// v1.9.2 DOM 扫描脚本：读主播控制台页面的公屏/互动面板/在线（页面自带签名拉流，绕过 im/fetch API 空返回问题）
// v1.15.16 极简版：只读元素级数据（person-count / like-count / 聊天容器），去掉全部全页 div 遍历
//   （全页遍历上千元素导致 executeJavaScript 报错 → 整个 DOM 扫描挂掉 → 在线/评论/关注全断）
const DOM_SCAN_SCRIPT = `(() => {
  try {
    function q(s) { return document.querySelector(s); }
    function qa(s) { return Array.prototype.slice.call(document.querySelectorAll(s)); }
    var out = { online: '', chat: [], chatItems: [], likes: '', risk: '', ended: '', chatGifts: [] };
    // v1.15.33 "直播已结束"只在"无直播间头部"时检测：直播中页面推荐流里的结束卡片（"直播已结束"字样）不再误判下播暂停一切
    // v1.15.28 以"房间 header 存在"作为直播页就绪信号（参考点赞 room-header-like-count）
    var bd = (document.body && document.body.innerText) || '';
    var lk = q('[data-e2e="room-header-like-count" i]');
    out.likes = lk ? (lk.innerText || '').trim() : '';
    if (!lk && /直播已结束/.test(bd)) { out.online = '0'; out.ended = '1'; return JSON.stringify(out); }
    // 在线：页面就绪（lk 存在）才读 person-count（实时加减）；未就绪/无直播 → 在线留空（推荐流观众数不污染，消除横跳虚假数字）
    if (lk) {
      // v1.15.34 未开播页可能残留直播间头部（header+person-count 误抓上次直播/推荐观众数）→ 页面含未开播专属文案立即判 ended（直播中页面不会出现"尚未开播/暂未开播"，推荐流卡片也不含）
      if (/尚未开播|暂未开播|暂无直播|未开播/.test(bd)) { out.online = '0'; out.ended = '1'; return JSON.stringify(out); }
      var pc = q('[data-e2e="person-count" i]');
      var pct = pc ? (pc.innerText || '').trim() : '';
      if (/还没有在线观众|还没有观众|暂无观众/.test(pct)) out.online = '0';
      else { var pcm = pct.match(/(\d+)/); out.online = pcm ? pcm[1] : ''; }
    } else {
      out.online = '';
    }
    // 聊天区：优先精确的聊天消息列表 chat-list（只含消息行），退回落大容器 live-chat-container
    var chatEl = q('[data-e2e="chat-list" i]') || q('[data-e2e="live-chat-container" i]') || q('[data-e2e="public-screen-live-chat-slot" i]');
    out.chatElE2E = chatEl ? (((chatEl.getAttribute && chatEl.getAttribute('data-e2e')) || '') + ' ' + ((chatEl.className && chatEl.className.toString()) || '')).slice(0, 80) : 'NULL';
    if (chatEl) {
      // v1.15.18 模板字符串内不能用反斜杠加 n（会被转义成真实换行 → 脚本跨行字符串 → 编译失败）；用 String.fromCharCode(10) 表示换行
      out.chat = (chatEl.innerText || '').split(String.fromCharCode(10)).map(function(s){ return s.trim(); }).filter(Boolean).slice(0, 80);
      var kids = qa.call(chatEl, 'div');
      var items = [];
      var seenT = {};
      for (var i = 0; i < kids.length && items.length < 60; i++) {
        var el = kids[i];
        var txt = (el.innerText || '').trim();
        if (!txt || txt.length > 120 || seenT[txt]) continue;
        // v1.15.19 页面导航/系统元素不进 chatItems（监控页面含侧边导航：返回/发现直播/LIVE Studio/创作者工具/更多/公司条款/TikTok 等，误当评论 → 评论数虚高）
        // v1.15.20 增加英文按钮/推荐流入口：Recharge（充值）、More（更多）、看更多/猜你喜欢/你可能喜欢
        // v1.15.22 推荐直播卡片（首行 LIVE + 主播名 + 标题 + 观众数）与"直播已结束/名观众"结束文案直接丢弃
        // v1.15.23 单行推荐流元素也过滤：LIVE 徽标 / 直播 N（观众数）/ 立即观看（引导文案）
        if (/^返回$|发现直播|LIVE Studio|创作者工具|^更多$|^More$|Recharge|公司计划条款|^TikTok$|推荐的主播|^LIVE\s+|看更多|猜你喜欢|你可能喜欢/.test(txt)) continue;
        if (/直播已结束|已结束|名观众|还没有在线观众/.test(txt)) continue;
        if (/^LIVE$|^直播\s*\d+$|立即观看/.test(txt)) continue;
        // v1.15.25 推荐流区块：推荐的直播 / 开启直播 / 与观众即时互动（误当评论/进场）
        if (/推荐的直播|开启直播|与观众即时互动/.test(txt)) continue;
        var firstLine = txt.split(String.fromCharCode(10))[0] || '';
        if (/^LIVE\b/i.test(firstLine) && txt.indexOf(String.fromCharCode(10)) >= 0) continue;
        // v1.15.17 放宽到 60：评论区 3 行式评论（昵称 + 序号 + 内容，约 20-40 字符）要解析；只跳超长容器文本
        // v1.15.18 模板内换行判断用 String.fromCharCode(10)（反斜杠加 n 在模板字符串里会转义成真实换行 → 脚本编译失败）
        if (txt.indexOf(String.fromCharCode(10)) >= 0 && txt.length > 60) continue;
        seenT[txt] = 1;
        var e2e = (((el.getAttribute && el.getAttribute('data-e2e')) || '') + ' ' + ((el.className && el.className.toString()) || '')).toLowerCase();
        // v1.15.21 推荐流/直播卡片元素不进 chatItems（person-count 在线数字、live-header 直播头部、live-card 推荐卡片等——被 live-chat-container 大容器误抓 → 假评论/假进场/假在线）
        if (/person-count|live-header|live-card|recommend|related|suggest|channel-title|tiktok-1w5o2is/.test(e2e)) continue;
        // 文本优先分类（"赞了直播"=点赞、"已关注"=关注、"已加入"=进场、"送出/赠送"=礼物），最后按 e2e 兜底
        var k = 'unknown';
        if (/已加入|进入了|加入了|join|audience|viewer/i.test(txt)) k = 'enter';
        else if (/已关注|关注了|followed|follow/i.test(txt)) k = 'follow';
        else if (/赞了直播|赞了|点赞了|like/i.test(txt)) k = 'like';
        else if (/送出|赠送|打赏|sent a gift|sent you|gift|diamond/i.test(txt)) k = 'gift';
        else if (/chat|comment|message|reply/.test(e2e)) k = 'chat';
        else if (/member|enter|join|audience|viewer/.test(e2e)) k = 'enter';
        else if (/like/.test(e2e)) k = 'like';
        else if (/gift|diamond|present/.test(e2e)) k = 'gift';
        else if (/follow|social/.test(e2e)) k = 'follow';
        items.push({ t: txt, k: k, e2e: e2e.slice(0, 60) });
      }
      out.chatItems = items;
      // 礼物兜底：只在聊天容器内扫"送出/赠送"文本（不再全页面扫）
      var giftSeen = {};
      for (var j = 0; j < items.length && out.chatGifts.length < 12; j++) {
        var gt = items[j].t;
        if (!gt || gt.length > 80 || giftSeen[gt]) continue;
        if (/送出|赠送|打赏|sent a gift|sent you/i.test(gt) && !/欢迎使用|公约|创作者必须|观众必须|充值和|送出了礼物\s*礼物|礼物\s*礼物|年满|请务必/.test(gt)) {
          giftSeen[gt] = 1;
          out.chatGifts.push(gt);
        }
      }
    }
    // 直播结束检测：观众页下播后显示结束文案（只取前 2 万字符防卡）
    var bodyText = ((document.body && document.body.innerText) || '').slice(0, 20000);
    var reEnd = /直播已结束|此直播已结束|直播已下播|此直播已停止|直播已停播|LIVE HAS ENDED|This live has ended|The live has ended|The user is not live now|The user is offline|This user is offline|has ended this live/i;
    var mEnd = bodyText.match(reEnd);
    if (mEnd) out.ended = mEnd[0].slice(0, 40);
    if (!out.ended) {
      var tEnd = ((document.title || '') + ' ' + (location.href || '')).match(reEnd);
      if (tEnd) out.ended = tEnd[0].slice(0, 40);
    }
    return JSON.stringify(out);
  } catch (e) { return JSON.stringify({ online: '', chat: [], likes: '', risk: '', err: e.message }); }
})()`;

// v1.9.2 DOM 互动状态：去重 + 增量解析（每账号独立）
const domSeen = {};        // accountId -> Set(已处理公屏行文本)
const domPanelLast = {};   // accountId -> { gifts:0, comments:0, likes:0 }
const DOM_POLL_MS = 2000;  // DOM 扫描间隔（2s，点赞/评论高频场景减少遗漏）

function getDomState(accountId) {
  if (!domSeen[accountId]) domSeen[accountId] = { set: new Set(), list: [] };
  if (!domPanelLast[accountId]) domPanelLast[accountId] = { gifts: 0, comments: 0, likes: 0 };
  return { seen: domSeen[accountId], panel: domPanelLast[accountId] };
}
function markDomSeen(accountId, text) {
  const st = getDomState(accountId);
  if (!st.seen.set.has(text)) {
    st.seen.set.add(text);
    st.seen.list.push(text);
    if (st.seen.list.length > 200) { const old = st.seen.list.shift(); st.seen.set.delete(old); }
  }
}
function isDomSeen(accountId, text) {
  return getDomState(accountId).seen.set.has(text);
}

// v1.13.20 进场昵称统一清洗：剥"已加入/进入了直播间/的直播间/赞了直播"尾巴、数字前缀/"第N"（任意位置）/"观众·N"/"最新"/纯数字/系统词
// v1.13.23 加"还没有在线观众"占位、"主播"标签尾巴（"vivianer549 主播"→主播自己不进场）
function cleanEnterUser(raw) {
  let user = (raw || '').replace(/已加入.*$|的直播间.*$|进入了直播间.*$|赞了直播.*$/i, '').trim();
  // v1.15.17 剥离结尾序号数字（"isabelespada85 3 进入了直播间" → "3"是 TikTok 序号，不是昵称 → 重复计数根因）
  user = user.replace(/^\d+\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/\s+\d+\s*$/, '').replace(/^观众[·\s]*\d*/, '').replace(/^最新\s*/, '').replace(/\s*主播\s*$/, '').replace(/\s+/g, ' ').trim();
  if (/推荐直播|推荐的主播|1名观众|直播已结束|直播已暂停|进入了直播间|主播推荐|系统消息|观众已进入|正在加载|加载中|还没有在线观众|还没有观众|暂无观众|欢迎使用|年满 18|年满18|充值和赠送|社区自律公约|创作者必须|观众必须|^观众$|^最新$|^\d+$/i.test(user)) return '';
  return user;
}
// v1.13.20 同一昵称 5 秒内只记一次进场/点赞（防嵌套 DOM 元素重复上报；真实反复进出间隔通常 >5s）
const recentEnter = {};
function isRecentEnter(accountId, user) {
  const now = Date.now();
  const k = accountId + '|' + user;
  if (recentEnter[k] && now - recentEnter[k] < 5000) return true;
  recentEnter[k] = now;
  return false;
}

// v1.13.21 缩写数字解析："1.2K"→1200、"12K"→12000、"1.1M"→1100000（TikTok 点赞破千显示 K/M）
function parseAbbrNum(s) {
  if (!s) return 0;
  const m = String(s).trim().replace(/,/g, '').match(/^(\d+(?:\.\d+)?)\s*([KkMm])?$/);
  if (!m) return parseInt(s, 10) || 0;
  const n = parseFloat(m[1]);
  const u = (m[2] || '').toLowerCase();
  if (u === 'k') return Math.round(n * 1000);
  if (u === 'm') return Math.round(n * 1000000);
  return Math.round(n);
}

// 解析 DOM 扫描结果 → 兼容 im 的事件数组（增量，去重）
function parseDomEvents(accountId, dom) {
  const events = [];
  // v1.15.31 页面"直播已结束"→ 不解析任何互动（下播瞬间残留 DOM 不再重复计数）
  if (dom && dom.ended) return events;
  // v1.13.8 元素级分类优先（复刻评论区）：进场/评论/点赞/礼物/关注按 DOM 标记精确识别，避免"进场名字被当评论"
  if (Array.isArray(dom.chatItems) && dom.chatItems.length) {
    for (const it of dom.chatItems) {
      if (it.k === 'enter') {
        const origT = it.t || '';
        // v1.14.13 假进场排除：系统推荐流文案 + 账号自身进场（原硬编码 vivianer549 改为动态取当前账号，换账号同样生效）
        if (/推荐的主播|recommended/i.test(origT)) continue;
        const _accInfo = loadAccounts()[accountId];
        const _selfName = _accInfo && _accInfo.name ? String(_accInfo.name).replace(/^@/, '') : '';
        if (_selfName && new RegExp('\\b' + _selfName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(origT)) continue;
        // v1.15.49 剥列表符号前缀（"- trnhyntrinh255" → "trnhyntrinh255"，同一人进场文本格式可能不同 → 统一昵称去重，本场只记一次）
        let user = cleanEnterUser(origT).replace(/^[-–—·.\s]+/, '').trim();
        if (user && !isRecentEnter(accountId, user) && !isDomSeen(accountId, 'enterUser:' + user)) { markDomSeen(accountId, 'enterUser:' + user); events.push({ method: 'WebcastMemberMessage', nickname: user }); }
        // v1.13.20 合并行"X 赞了直播 进入了直播间" → 同时拆出点赞事件（行为点赞真实记录）
        if (/赞了直播/.test(origT)) {
          const likeUser = cleanEnterUser(origT);
          if (likeUser && !isRecentEnter(accountId, 'like:' + likeUser) && !isDomSeen(accountId, 'like:' + origT)) { markDomSeen(accountId, 'like:' + origT); events.push({ method: 'WebcastLikeMessage', nickname: likeUser }); }
        }
        continue;
      }
      // v1.15.15 unknown 也走评论解析（部分评论元素 e2e 无 chat/comment 标记 → 之前被忽略漏计评论）
      if (it.k === 'chat' || it.k === 'unknown') {
        // v1.15.6 文本二次判定：chat 元素里混入的点赞/关注/进场（分类器漏判时兜底，防止"点赞关注进场当评论"）
        const t2 = it.t || '';
        // v1.15.31 互动判定统一：排除主播自身（"vivianer549 已加入"是主播自己进自己直播间，不算观众进场）
        // + 礼物排除平台公约文案（"年满18周岁才能充值和赠送礼物"含"赠送"被误判礼物）
        const _ai = loadAccounts()[accountId];
        const _sn = _ai && _ai.name ? String(_ai.name).replace(/^@/, '') : '';
        if (/充值和|年满\s*18|年满18|社区自律公约|创作者必须|观众必须|请务必遵守|欢迎使用/.test(t2)) continue;
        if (_sn && new RegExp('\\b' + _sn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(t2)) continue;
        // v1.15.33 进场只信官方 IM 真人成员消息：DOM 评论区含 TikTok 推荐观众（垫大师/米尔瓦斯鼓点等系统占位）进入提示，无法与真人区分 → DOM 进场全部停用
        if (/已加入|进入了|加入了/.test(t2)) { continue; }
        if (/已关注|关注了/.test(t2)) {
          const u = cleanEnterUser(t2).replace(/已关注主播|关注了主播|followed/i, '');
          // v1.15.38 去重 key 统一为清洗后昵称（防同一关注走 chatItems/两行模式两分支各推一次 → 关注重复）
          if (u && !isDomSeen(accountId, 'follow:' + u)) { markDomSeen(accountId, 'follow:' + u); events.push({ method: 'WebcastSocialMessage', nickname: u }); }
          continue;
        }
        if (/赞了直播|赞了|点赞了/.test(t2)) {
          const u = cleanEnterUser(t2);
          if (u && !isRecentEnter(accountId, 'like:' + u) && !isDomSeen(accountId, 'like:' + t2)) { markDomSeen(accountId, 'like:' + t2); events.push({ method: 'WebcastLikeMessage', nickname: u }); }
          continue;
        }
        if (/送出|赠送|打赏/.test(t2)) {
          const gm2 = t2.match(/^(.+?)(?:送出了礼物|赠送了|送出了|赠送|打赏|sent a gift|sent you)/i);
          let guser2 = gm2 ? gm2[1].trim() : '';
          guser2 = guser2.replace(/^💠\s*\d*\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/^\d+\s*/, '').replace(/\s+/g, ' ').trim();
          const gname2 = t2.replace(/^.+?(?:送出了礼物|赠送了|送出了|赠送|打赏|sent a gift|sent you)/i, '').replace(/礼物$|的礼物$/i, '').trim();
          const cnt2 = gname2.match(/[×xX]\s*(\d+)\s*$/);
          if (!isDomSeen(accountId, 'gift:' + t2)) { markDomSeen(accountId, 'gift:' + t2); events.push({ method: 'WebcastGiftMessage', nickname: guser2 || '', giftName: gname2.replace(/[×xX]\s*\d+\s*$/, '').replace(/🎁|💠|💎/g, '').trim() || '礼物', giftCount: cnt2 ? parseInt(cnt2[1], 10) : 1 }); }
          continue;
        }
        // v1.15.42 评论：用户要求"评论区有消息就+1，互动关键词（中英）不计，其余全算（含系统提示）" → 只排互动词，不再排系统文案
        if (/已加入|进入了|加入了|已关注|关注了|赞了直播|点赞了直播|分享了|送出了礼物|赠送了|送出了|sent a gift|sent you|joined|followed|liked|shared|entered/i.test(t2)) continue;
        const cu = cleanEnterUser(t2);
        const ctext = t2.replace(/^.*?(?:\n|$)/, '').trim() || t2;
        if (!isDomSeen(accountId, 'comment:' + t2)) { markDomSeen(accountId, 'comment:' + t2); events.push({ method: 'WebcastChatMessage', nickname: cu || '', text: ctext }); }
        continue;
      }
      if (it.k === 'like') {
        const user = cleanEnterUser(it.t || '');
        if (user && !isRecentEnter(accountId, 'like:' + user) && !isDomSeen(accountId, 'like:' + it.t)) { markDomSeen(accountId, 'like:' + it.t); events.push({ method: 'WebcastLikeMessage', nickname: user }); }
        continue;
      }
      if (it.k === 'gift') {
        const g = it.t || '';
        // v1.14.13 平台公约/规则文案绝不能当礼物（"充值和赠送礼物…请务必遵守…"等）
        if (/欢迎使用|社区自律公约|创作者必须|观众必须|请务必遵守|年满\s*\d+\s*周岁|充值和|送出了礼物 礼物|礼物 礼物/.test(g)) continue;
        const gm = g.match(/^(.+?)(?:送出了礼物|赠送了|送出了|赠送|sent a gift|sent you)/i);
        let guser = gm ? gm[1].trim() : '';
        // v1.13.21 礼物昵称清洗："💠15 Наталія з України 第1" → 剥钻石图标+数量/"第N"（任意位置） → "Наталія з України"
        guser = guser.replace(/^💠\s*\d*\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/^\d+\s*/, '').replace(/\s+/g, ' ').trim();
        const gnameRaw = g.replace(/^.+?(?:送出了礼物|赠送了|送出了|赠送|sent a gift|sent you)/i, '').replace(/礼物$|的礼物$/i, '').trim();
        const cntM = gnameRaw.match(/[×xX]\s*(\d+)\s*$/);
        const gcount = cntM ? parseInt(cntM[1], 10) : 1;
        const gname = gnameRaw.replace(/[×xX]\s*\d+\s*$/, '').replace(/🎁|💠|💎/g, '').trim() || '礼物';
        // v1.15.5 礼物只计数不依赖昵称（昵称缺失也累计，保证礼物数量不丢）
        if (!isDomSeen(accountId, 'gift:' + g)) { markDomSeen(accountId, 'gift:' + g); events.push({ method: 'WebcastGiftMessage', nickname: guser || '', giftName: gname, giftCount: gcount }); }
        continue;
      }
      if (it.k === 'follow') {
        const user = (it.t || '').replace(/已关注主播|关注了主播|followed/i, '').replace(/^💠\s*\d*\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/^\d+\s*/, '').replace(/\s+/g, ' ').trim();
        if (user && !isDomSeen(accountId, 'follow:' + it.t)) { markDomSeen(accountId, 'follow:' + it.t); events.push({ method: 'WebcastSocialMessage', nickname: user }); }
        continue;
      }
    }
    // v1.15.9 不再提前 return：chatItems 只负责结构化元素，chat 行继续兜底解析孤立评论（如 "Dd"/"Hxcgh" 短评论单独成行）
  }
  const chat = dom.chat || [];
  const skipWords = ['还没有在线观众', '欢迎使用 TikTok 直播', '欢迎使用TikTok直播', '创作者必须', '观众必须', '请务必遵守', '社区自律公约', '送出了礼物 礼物', '送出了礼物礼物', '礼物 礼物', '已加入主播的直播间', '直播开始了', '观众', '· 1', '暂无实时动态', '暂无风险告警', '实时动态', '风险告警记录', '推荐的主播进入了直播间', '推荐的主播', '进入了直播间', 'TikTok', 'LIVE', '正在加载', '加载中'];
  const isSkip = (s) => !s || skipWords.some(w => s.includes(w)) || /^·/.test(s);
  // v1.15.5 礼物兜底行（DOM_SCAN_SCRIPT 全页面扫到的"送出/赠送"文本 → 真实礼物事件，N×几 计数）
  for (const g of (dom.chatGifts || [])) {
    if (isSkip(g)) continue;
    const gm = g.match(/^(.+?)(?:送出了礼物|赠送了|送出了|赠送|打赏|sent a gift|sent you)/i);
    let guser = gm ? gm[1].trim() : '';
    guser = guser.replace(/^💠\s*\d*\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/^\d+\s*/, '').replace(/\s+/g, ' ').trim();
    const gnameRaw = g.replace(/^.+?(?:送出了礼物|赠送了|送出了|赠送|打赏|sent a gift|sent you)/i, '').replace(/礼物$|的礼物$/i, '').trim();
    const cntM = gnameRaw.match(/[×xX]\s*(\d+)\s*$/);
    const gcount = cntM ? parseInt(cntM[1], 10) : 1;
    const gname = gnameRaw.replace(/[×xX]\s*\d+\s*$/, '').replace(/🎁|💠|💎/g, '').trim() || '礼物';
    // 礼物只计数不依赖昵称（昵称缺失也累计，保证礼物数量不丢）
    if (!isDomSeen(accountId, 'gift:' + g)) { markDomSeen(accountId, 'gift:' + g); events.push({ method: 'WebcastGiftMessage', nickname: guser || '', giftName: gname, giftCount: gcount }); }
  }
  for (let i = 0; i < chat.length; i++) {
    const a = chat[i], b = chat[i + 1] || '', c = chat[i + 2] || '';
    // 0) 点赞：X 赞了直播（v1.12.24 控制台互动区常见行）
    if (a.includes('赞了直播')) {
      // v1.13.8 合并行拆评："trnhyntrinh255 第1 赞了直播" = 昵称 + TikTok标记"第1" + 赞了直播 → 只保留点赞（"第1"是点赞序号标记，不是评论）
      const pre = a.replace(/赞了直播\s*$/, '').trim();
      const cm = pre.match(/^(.+?)\s+(第\s*\d+)$/);
      let user = pre;
      // v1.13.18 "第N"是 TikTok 点赞序号标记（不是评论内容）→ 不再拆成评论进动态流
      if (cm) user = cm[1].trim();
      if (user && !isDomSeen(accountId, 'like:' + a)) { markDomSeen(accountId, 'like:' + a); events.push({ method: 'WebcastLikeMessage', nickname: user }); }
      continue;
    }
    // 0.1) 礼物：X 送出了礼物 玫瑰 / X 赠送了玫瑰 / X sent a gift（v1.12.31 公屏礼物事件，真实数据）
    if (/送出了礼物|赠送了|送出了|赠送|sent a gift|sent you/i.test(a)) {
      // v1.12.38 系统文案（欢迎横幅/公约/年龄提示）不判礼物，避免"欢迎使用…充值和 送出了礼物 礼物"误判
      if (isSkip(a) || /欢迎使用|社区自律公约|创作者必须|观众必须/.test(a)) { continue; }
      const gm = a.match(/^(.+?)(?:送出了礼物|赠送了|送出了|赠送|sent a gift|sent you)/i);
      let guser = gm ? gm[1].trim() : '';
      // v1.13.21 兜底通道同样清洗礼物昵称（钻石图标+数量/"第N"任意位置/数字前缀）
      guser = guser.replace(/^💠\s*\d*\s*/, '').replace(/\s*第\s*\d+\s*/g, '').replace(/^\d+\s*/, '').replace(/\s+/g, ' ').trim();
      const gnameRaw = a.replace(/^.+?(?:送出了礼物|赠送了|送出了|赠送|sent a gift|sent you)/i, '').replace(/礼物$|的礼物$/i, '').trim();
      const cntM = gnameRaw.match(/[×xX]\s*(\d+)\s*$/);
      const gcount = cntM ? parseInt(cntM[1], 10) : 1;
      const gname = gnameRaw.replace(/[×xX]\s*\d+\s*$/, '').replace(/🎁|💠|💎/g, '').trim() || '礼物';
      // v1.15.5 礼物只计数不依赖昵称（昵称缺失也累计，保证礼物数量不丢）
      if (!isDomSeen(accountId, 'gift:' + a)) { markDomSeen(accountId, 'gift:' + a); events.push({ method: 'WebcastGiftMessage', nickname: guser || '', giftName: gname, giftCount: gcount }); }
      continue;
    }
    // 1) 同行模式：X 已加入 / X 已关注主播
    if (a.includes('已加入')) {
      // v1.15.33 进场只信官方 IM 真人：DOM"已加入"含 TikTok 推荐观众（垫大师等系统占位），无法区分 → 停用
      continue;
    }
    if (a.includes('已关注主播')) {
      const user = cleanEnterUser(a).replace(/已关注主播.*$/i, '');
      // v1.15.38 去重 key 统一为清洗后昵称（防同行/两行/chatItems 三分支同一关注各推一次）
      if (user && !isDomSeen(accountId, 'follow:' + user)) { markDomSeen(accountId, 'follow:' + user); events.push({ method: 'WebcastSocialMessage', nickname: user }); }
      continue;
    }
    if (isSkip(a)) continue;
    // v1.15.9 序号行（"第1"是 TikTok 点赞/互动序号标记，不是评论）单独跳过
    if (/^第\s*\d+$/.test(a)) continue;
    // 孤立评论行（v1.12.44 TikTok 观众页公屏：评论短文本单独成行，无"观众"标签，如 "Hi"、"111"）
    // v1.13.8 昵称不再取"行首词"（"Hi"→昵称"Hi"导致内容=昵称被滤）；行内无空格则昵称留空，内容完整保留
    // v1.13.20 "20 Νεκτάριος κοκονης"（数字+昵称=进场计数样式）不当评论；名字行后跟"已加入/主播/观众"等状态行 → 留给两行模式分支处理（不吞成评论）
    // v1.15.9 名字行后跟"第N"（名字+序号+内容 三段式）→ 不把名字当评论
    // v1.15.19 导航/系统词不进评论（返回/更多/TikTok/发现直播等被聊天容器误抓 → 评论数虚高）
    if (a.length < 60 && a !== 'vivianer549' && !/^第\d+条/.test(a) && !/^\d+\s+\S+$/.test(a) && !isSystemCommentText(a) && !(b === '已加入' || b === '已加入主播的直播间' || b === '已关注主播' || b === '主播' || b === '观众' || /^第\s*\d+$/.test(b))) {
      // v1.15.27 评论只信官方 IM 通道：DOM 孤立行不再作为评论推送（页面导航/账号名等永远不可能是可靠评论）
      continue;
    }
    // 2) 两行模式：名字行 + 状态行（TikTok 公屏名字和状态分行显示）
    if (b === '已加入' || b === '已加入主播的直播间' || b === '已关注主播') {
      let user = cleanEnterUser(a);
      if (user && user !== 'vivianer549') {
        const key = (b === '已关注主播' ? 'follow:' : 'enter:') + user;
        if (b === '已关注主播') {
          if (!isDomSeen(accountId, key)) { markDomSeen(accountId, key); events.push({ method: 'WebcastSocialMessage', nickname: user }); }
        }
        // v1.15.33 进场只信官方 IM 真人：DOM"已加入"（含推荐观众）不再推 WebcastMemberMessage
      }
      i += 1;
      continue;
    }
    // 3) 评论模式：[名字, 标签(主播/观众), 内容]
    if (b === '主播' || b === '观众') {
      // v1.15.27 评论只信官方 IM 通道：DOM [名字,标签,内容] 模式不再推送评论（标签"观众/主播"本身是页面元素，不是评论）
      i += 1;
      continue;
    }
    // 4) 孤立标签行
    if (a === '主播' || a === '观众') continue;
  }
  // v1.12.8 去掉互动面板增量统计：页面静态/历史/累计数字会被误读成"刚开播就有玫瑰/点赞"假数据
  // 礼物/点赞/评论全部只信 IM 通道（Webcast*Message 真实事件）
  // v1.12.30 点赞总数：观众页 room-header-like-count 真实累计（用户要求显示直播间点赞数量）
  const likesTotal = parseAbbrNum(dom.likes);
  // v1.13.23 点赞总数只在变化时推（isTotal 每 2s 重发同值会刷屏；变化才更新面板）
  if (likesTotal && !isNaN(likesTotal) && domPanelLast[accountId] && likesTotal !== domPanelLast[accountId].likes) {
    domPanelLast[accountId].likes = likesTotal;
    events.push({ method: 'WebcastLikeCountMessage', nickname: '', likeCount: likesTotal });
  }
  // 3. 在线（v1.15.34 只在官方房间已确认后推：未开播/页面加载中无 roomId → 在线不推，根除"没开播显示推荐流观众数"）
  // 开播后 roomId 由 getRoomIdViaApi 官方确认，在线跟 person-count 实时加减照常
  const online = parseInt(dom.online, 10);
  const _rm = monitors[accountId] && monitors[accountId].roomId;
  if (_rm && !isNaN(online) && online >= 0 && (!domPanelLast[accountId] || online !== domPanelLast[accountId].online)) {
    if (domPanelLast[accountId]) domPanelLast[accountId].online = online;
    events.push({ method: 'WebcastRoomUserSeqMessage', nickname: '', online });
  }
  return events;
}

// v1.9.2 DOM 轮询：主互动数据源（页面自身拉流，含签名）
// v1.14.10 修复：诊断文件原写死 D:/tk4k屏（换电脑失效）→ 统一写 userData（AppData\Roaming\TikTok直播工作台），随诊断包可导出
const POLL_DIAG_PATH = path.join(app.getPath('userData'), '_poll_diag.txt');
function pollDiag(s) {
  try { require('fs').appendFileSync(POLL_DIAG_PATH, '[' + new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '] ' + s + '\n'); } catch (e) {}
}
async function pollDom(accountId) {
  const mon = monitors[accountId];
  if (!mon || !mon.running) { pollDiag('pollDom return: no-mon/running=' + !!(mon && mon.running)); return; }
  // v1.15.39 单通道：互动事件/在线/点赞只走 preload（monitor-preload.js 注入通道，不经 executeJavaScript）
  // pollDom 的 executeJavaScript 停用 → 根治双通道重复（关注/进场各推一次）与在线横跳（两通道时序不同互相覆盖）
  try {
    const now = Date.now();
    if ((mon._singleAt || 0) + 30000 < now) { mon._singleAt = now; pollDiag('pollDom: single-channel (preload only)'); }
  } catch (e) {}
  return;
  const win = mon.win;
  if (!win || win.isDestroyed()) { pollDiag('pollDom return: win-bad'); return; }
  // v1.15.32 URL 保险：小电视页面离开自己直播间（点进别人直播间/跳到其他页面）→ 暂停记录（数据保留），回到自己直播间自动恢复
  try {
    const _acc = loadAccounts()[accountId];
    const _nm = _acc && _acc.name ? String(_acc.name).replace(/^@/, '') : '';
    if (_nm) {
      const _url = win.webContents.getURL() || '';
      if (_url && !new RegExp('@' + _nm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/live', 'i').test(_url)) {
        pollDiag('pollDom return: url-leave (url=' + _url.slice(0, 100) + ')');
        return;
      }
    }
  } catch (e) {}
  try {
    const raw = await Promise.race([
      win.webContents.executeJavaScript(DOM_SCAN_SCRIPT, true),
      new Promise(r => setTimeout(() => r('{"online":"","chat":[],"likes":"","risk":"","err":"timeout"}'), 6000)),
    ]);
    pollDiag('raw len=' + String(raw || '').length + ' head=' + String(raw || '').slice(0, 120).replace(/\n/g, ' '));
    const dom = JSON.parse(raw);
    // v1.13.2 观众页检测到"直播已结束"文案 → 连续 2 次确认（约 4s）→ 实时数据立即清零（下播就啥也看不到，开播重新记录）
    if (dom.ended) {
      // v1.15.29 下播清零 60 秒冷却：同一结束态不重复清零刷日志（页面一直"直播已结束"时不再每几秒刷一次）
      if (mon._endedLockUntil && Date.now() < mon._endedLockUntil) { /* 冷却中，不重复清零 */ }
      else {
        mon.endedStreak = (mon.endedStreak || 0) + 1;
        if (mon.endedStreak >= 1) {  // v1.15.37 1 次即确认（ended 只在无直播间头部时触发，推荐流结束卡片不误判）：下播残留窗口从 4s 缩到 2s
          mon.endedStreak = 0;
          mon._endedLockUntil = Date.now() + 60000;
          sendMonitorCleared(accountId, '直播间已下播（观众页确认）');
          stopStreamIfStreaming(accountId, '直播间已下播，已自动停止推流');
        }
      }
    } else {
      mon.endedStreak = 0;
      mon._endedLockUntil = 0;
    }
    const events = parseDomEvents(accountId, dom);
    pollDiag('parsed events=' + events.length + ' online=' + dom.online + ' chatLen=' + (dom.chat || []).length);
    // v1.13.8 诊断：chatItems 真实 DOM 标记写文件（限流 30s，核对元素级分类）
    try {
      const now = Date.now();
      if ((mon._diagAt || 0) + 30000 < now && Array.isArray(dom.chatItems) && dom.chatItems.length) {
        mon._diagAt = now;
        const lines = dom.chatItems.slice(0, 8).map(it => (it.t || '').slice(0, 24).replace(/\n/g, ' ') + ' | k=' + it.k + ' | e2e=' + it.e2e);
        fs.appendFileSync(path.join(app.getPath('userData'), '_diag_chatitems.txt'), '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] ' + lines.join('  ;;  ') + '\n');
      }
    } catch (e) {}
    // v1.12.24 风险告警：控制台"风险告警记录"区域出现真实告警（非"暂无"）→ 立即通知（复用 risk-warning 通道，前端已渲染+toast）
    // v1.12.25 与 scanRisk 共享 riskLastSent 去重（同一告警 5 分钟内只弹一次，避免双路双发）
    // v1.14.11 风险告警停用
    if (RISK_ALERTS_ENABLED && dom.risk && !dom.risk.includes('暂无') && dom.risk.includes('风险告警')) {
      const riskText = dom.risk.replace(/风险告警.*?记录|暂无/g, '').trim() || dom.risk;
      const riskKey = 'risk:' + riskText;
      const prevR = (riskLastSent[accountId] || {})[riskKey];
      if (!prevR || Date.now() - prevR > RISK_DEDUP_MS) {
        if (!riskLastSent[accountId]) riskLastSent[accountId] = {};
        riskLastSent[accountId][riskKey] = Date.now();
        sendToUI('tiktok:risk-warning', { accountId, risk: { key: riskKey, cn: riskText } });
        try { fs.appendFileSync(path.join(app.getPath('userData'), '_risk_alerts.txt'), '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] 房间' + accountId + ' ' + riskText + '\n'); } catch (e) {}
      }
      markDomSeen(accountId, riskKey);
    }
    if (events.length) {
      const items = events.map(imEventToFeedItem).filter(Boolean);
      // v1.15.12 在线事件单独推送：items 空但在线变化（含 0）也要更新面板（观众走/来实时反映，不依赖互动）
      const onlineEv = events.find(e => e.method === 'WebcastRoomUserSeqMessage');
      if (items.length || onlineEv) {
        mon.clearedFlag = false; // v1.13.3 有新互动数据 → 解除下播清零去重（重新开播后正常累积）
        sendToUI('tiktok:im-events', { accountId, items, methods: events.map(e => e.method), online: onlineEv ? onlineEv.online : null });
        console.log('[监控] 房间', accountId, 'DOM互动:', items.length, '条' + (onlineEv ? (' 在线=' + onlineEv.online) : ''));
        pollDiag('SEND im-events items=' + items.length + ' online=' + (onlineEv ? onlineEv.online : '-'));
        handleAutoInteract(accountId, events).catch(() => {});
      }
    }
  } catch (e) {
    pollDiag('pollDom ERROR: ' + e.message);
    console.log('[监控] 房间', accountId, 'DOM扫描:', e.message);
    // v1.13.10 错误诊断 + 限流：记录页面状态定位根因（URL 是否被重定向/是否仍在加载）；连续失败暂停 30s 避免 2s 一次狂刷
    try {
      const _w = monitors[accountId] && monitors[accountId].win;
      const _st = (_w && !_w.isDestroyed()) ? ('url=' + _w.webContents.getURL() + ' loading=' + _w.webContents.isLoading()) : 'win-bad';
      pollDiag('pollDom state: ' + _st);
    } catch (e2) {}
    const _m2 = monitors[accountId];
    if (_m2) {
      _m2._errStreak = (_m2._errStreak || 0) + 1;
      if (_m2._errStreak >= 3) {
        _m2._errStreak = 0;
        _m2._suspendedUntil = Date.now() + 30000;
        pollDiag('pollDom: 连续失败 3 次，暂停 30s（页面可能导航/登录中）');
      }
    }
  }
}

// v1.13.15 preload 通道：监控窗口注入脚本（monitor-preload.js）页面加载即运行，上报 DOM 数据（绕过 executeJavaScript 失败）
// 与 pollDom（executeJavaScript）双通道并行：任一通道拿到数据都推前端，共享 domSeen 去重不会双发
ipcMain.on('monitor:data', (event, payload) => {
  try {
    const wid = event.sender.id;
    let accountId = null;
    for (const id of Object.keys(monitors)) {
      const m = monitors[id];
      if (m && m.win && !m.win.isDestroyed() && m.win.webContents.id === wid) { accountId = id; break; }
    }
    if (!accountId) return;
    const kind = payload && payload.kind;
    if (kind === 'ready') { pollDiag('preload ready 房间' + accountId + '（注入通道可用）'); return; }
    if (kind !== 'dom') return;
    // v1.15.39 单通道 URL 保险（原 pollDom 的 URL 检查搬过来）：小电视离开自己直播间（点进别人/跳其他页）→ 暂停处理（数据保留），回到自己直播间自动恢复
    try {
      const _acc = loadAccounts()[accountId];
      const _nm = _acc && _acc.name ? String(_acc.name).replace(/^@/, '') : '';
      if (_nm) {
        const _url = event.sender.getURL() || '';
        if (_url && !new RegExp('@' + _nm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/live', 'i').test(_url)) { pollDiag('preload return: url-leave'); return; }
      }
    } catch (e) {}
    handleMonitorDom(accountId, payload.data || {});
  } catch (e) {}
});

// preload 通道的 DOM 数据处理（复用 pollDom 的解析/去重/推送逻辑，风险走 classifyRiskInfo）
function handleMonitorDom(accountId, dom) {
  const mon = monitors[accountId];
  if (!mon || !mon.running) return;
  if (dom && dom.err) console.log('[监控] 房间', accountId, 'preload scan 报错:', dom.err);
  // v1.14.11 风险告警已停用（RISK_ALERTS_ENABLED=false）：限流提示/风险分类/疑似无流量全部跳过
  if (RISK_ALERTS_ENABLED) {
    // v1.13.30 限流/限制告警优先于 clearedFlag/ended：限流时观众页可能显示"not live"（ended）→ 先报限制原因再清零，否则限流提示被跳过
    if (dom.limit) {
      const key = 'limit';
      const prevL = (riskLastSent[accountId] || {})[key];
      if (!prevL || Date.now() - prevL > RISK_DEDUP_MS) {
        if (!riskLastSent[accountId]) riskLastSent[accountId] = {};
        riskLastSent[accountId][key] = Date.now();
        const risk = { key, cn: '平台限流提示', detail: '监控页检测到直播间限流/限制文案（' + (dom.limitText || '') + '）。请到手机端或直播后台查看具体提示。', advice: '立即查看平台具体提示；若因内容/互动被限流，按提示整改，必要时申诉。', severity: 'high', needVerify: false };
        sendToUI('tiktok:risk-warning', { accountId, risk, page: { text: (dom.rawText || '').slice(0, 500) } });
        console.log('[风险] 房间', accountId, '平台限流提示:', dom.limitText || '');
        try { fs.appendFileSync(path.join(app.getPath('userData'), '_risk_alerts.txt'), '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] 房间' + accountId + ' 平台限流提示: ' + (dom.limitText || '') + '\n'); } catch (e) {}
      }
    }
  }
  if (mon.clearedFlag) return; // 下播清零后暂停（直到 pollIm 检测房间重新在播）
  // 直播结束检测：连续 2 次（约 4s）→ 立即清零；v1.15.29 加 60 秒冷却（同一结束态不重复清零刷日志）
  if (dom.ended) {
    if (mon._endedLockUntil && Date.now() < mon._endedLockUntil) { /* 冷却中 */ }
    else {
      mon.endedStreak = (mon.endedStreak || 0) + 1;
      if (mon.endedStreak >= 1) {  // v1.15.37 1 次即确认（ended 只在无直播间头部时触发）
        mon.endedStreak = 0;
        mon._endedLockUntil = Date.now() + 60000;
        sendMonitorCleared(accountId, '直播间已下播（观众页确认）');
        stopStreamIfStreaming(accountId, '直播间已下播，已自动停止推流');
      }
    }
  } else {
    mon.endedStreak = 0;
    mon._endedLockUntil = 0;
  }
  // v1.14.11 风险分类已停用
  if (RISK_ALERTS_ENABLED) {
    // 风险分类（观众页平台文案：暂停/被禁等）→ 与 scanRisk 共享 riskLastSent 去重
    if (dom.rawText) {
      try {
        const risk = classifyRiskInfo({ title: '', url: '', text: dom.rawText });
        if (risk) {
          const prev = (riskLastSent[accountId] || {})[risk.key];
          if (!prev || Date.now() - prev > RISK_DEDUP_MS) {
            if (!riskLastSent[accountId]) riskLastSent[accountId] = {};
            riskLastSent[accountId][risk.key] = Date.now();
            sendToUI('tiktok:risk-warning', { accountId, risk, page: { text: dom.rawText.slice(0, 500) } });
            console.log('[风险] 房间', accountId, 'preload →', risk.cn);
            try { fs.appendFileSync(path.join(app.getPath('userData'), '_risk_alerts.txt'), '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] 房间' + accountId + ' preload ' + risk.cn + '\n'); } catch (e) {}
          }
        }
      } catch (e) {}
    }
  }
  // v1.13.29 礼物诊断日志（定位礼物行在页面文本中是否存在）
  if (dom.giftDiag) console.log('[监控] 房间', accountId, '礼物线索:', dom.giftDiag);
  // 互动解析（进场/评论/点赞/礼物/关注 + 在线/点赞总数）——共享 domSeen 去重（pollDom 同 DOM 不会双发）
  const events = parseDomEvents(accountId, dom);
  if (events.length) {
    mon.lastInteractAt = Date.now(); // v1.13.26 疑似无流量检测用：最后互动时间
    const items = events.map(imEventToFeedItem).filter(Boolean);
    // v1.15.17 在线事件单独推送（items 空但在线变化也要更新面板）；无在线事件推 null（前端不覆盖旧值）
    const onlineEv = events.find(e => e.method === 'WebcastRoomUserSeqMessage');
    if (items.length || onlineEv) {
      mon.clearedFlag = false;
      sendToUI('tiktok:im-events', { accountId, items, methods: events.map(e => e.method), online: onlineEv ? onlineEv.online : null });
      if (data.cmtDiag) console.log('[监控] 房间', accountId, 'cmtDiag:', data.cmtDiag);
      console.log('[监控] 房间', accountId, 'preload DOM互动:', items.length, '条', items.map(i => i.type + ':' + (i.user || '') + ':' + (i.text || '').slice(0, 30)).join(' | '));
      handleAutoInteract(accountId, events).catch(() => {});
    }
  }
  // v1.14.11 疑似无流量检测已停用
  if (RISK_ALERTS_ENABLED) {
    // v1.13.26 疑似无流量检测：手机端限流弹窗观众页不显示（监控是观众页，抓不到），但限流期观众进不来 → 在线 0 + 5 分钟无互动 → 提示去手机端看 Restrictions
    // v1.13.27 页面空白/加载失败（rawText 过短）不触发；lastInteractAt 已从监控启动计时
    const idleMs = 5 * 60 * 1000;
    const since = Date.now() - (mon.lastInteractAt || Date.now());
    const rawTxt = String(dom.rawText || '').trim();
    const onlineZero = (String(dom.online || '').trim() === '0') || (dom.online === undefined || dom.online === null || String(dom.online).trim() === '');
    if (rawTxt.length >= 50 && onlineZero && since > idleMs) {
      const idleKey = 'idle';
      const prevI = (riskLastSent[accountId] || {})[idleKey];
      if (!prevI || Date.now() - prevI > RISK_DEDUP_MS) {
        if (!riskLastSent[accountId]) riskLastSent[accountId] = {};
        riskLastSent[accountId][idleKey] = Date.now();
        const risk = { key: idleKey, cn: '直播间疑似无流量/可能被限流', detail: '监控中在线为 0 且 ' + Math.round(since / 60000) + ' 分钟无任何互动。限流提示在手机端（观众页不显示），请到手机端查看是否出现 Restrictions（如 Reproduced content）。', advice: '打开手机端查看限制提示与时间；若因复制内容被限流，下播调整素材后重开，避免继续推流浪费流量。', severity: 'mid', needVerify: false };
        sendToUI('tiktok:risk-warning', { accountId, risk, page: { text: '在线0 无互动 ' + Math.round(since / 60000) + '分钟' } });
        console.log('[风险] 房间', accountId, '疑似无流量/可能被限流（' + Math.round(since / 60000) + ' 分钟无互动）');
        try { fs.appendFileSync(path.join(app.getPath('userData'), '_risk_alerts.txt'), '[' + new Date().toLocaleString('zh-CN', { hour12: false }) + '] 房间' + accountId + ' 疑似无流量/可能被限流（' + Math.round(since / 60000) + ' 分钟无互动）\n'); } catch (e) {}
      }
    }
  }
}

function getCsrfToken(info) {
  try {
    const c = (info.cookies || []).find(x => x.name === 'passport_csrf_token' || x.name === 'tt_csrf_token' || x.name === 's_v_web_id');
    return c ? c.value : '';
  } catch (e) { return ''; }
}

// ---------- 实时监控 IPC ----------
// v1.13.24 实时动态浮窗（独立 frameless 窗口）创建/复用：监控在跑但浮窗被关 → 再次点「开启监控」重新弹出
function createMonitorUiWindow(accountId) {
  try {
    if (monitorUIs[accountId] && !monitorUIs[accountId].isDestroyed()) return monitorUIs[accountId];
    console.log('[监控] 房间', accountId, '创建实时动态浮窗');
    const uiWin = new BrowserWindow({
      width: 420, height: 760, show: true, frame: false, resizable: true, backgroundColor: '#eef0f5',
      webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false },
    });
    uiWin.setMenu(null);
    // v1.12.6 实时动态窗口靠屏幕右侧，与左侧小电视窗口错开
    try { const wa = screen.getPrimaryDisplay().workArea; uiWin.setPosition(wa.width - 440, Math.max(0, Math.round((wa.height - 760) / 2))); } catch (e) {}
    uiWin.loadURL('file://' + path.join(__dirname, 'index.html') + '?monitor=1&accountId=' + accountId);
    monitorUIs[accountId] = uiWin;
    // v1.15.22 浮窗加载诊断：成功/失败/崩溃都记入 run.log（用户反馈"浮窗打不开"但创建日志正常 → 需确认是否加载失败/黑屏）
    uiWin.webContents.on('did-finish-load', () => console.log('[监控] 房间', accountId, '实时动态浮窗加载完成'));
    uiWin.webContents.on('did-fail-load', (e, code, desc) => console.log('[监控] 房间', accountId, '实时动态浮窗加载失败:', code, desc));
    uiWin.webContents.on('render-process-gone', (e, det) => console.log('[监控] 房间', accountId, '实时动态浮窗渲染进程异常:', det && det.reason));
    uiWin.on('closed', () => {
      if (monitorUIs[accountId] === uiWin) delete monitorUIs[accountId];
      // v1.15.25 右上角 × 掉实时动态浮窗 = 停止监控（用户要求：简单高效，× 掉就代表停止监控；再点开启 = 全新启动必然弹窗）
      if (monitors[accountId] && monitors[accountId].running) stopMonitor(accountId);
    });
    return uiWin;
  } catch (e) { console.log('[监控] 独立窗口创建失败:', e.message); return null; }
}

async function startMonitor(accountId, accountName) {
  try {
    console.log('[监控] 房间', accountId, '启动监控 步骤1 检查账号');
    // v1.15.36 官方房间确认前全暂停（绑定房间）：未确认 roomId 前 clearedFlag=true → 所有数据 0，房间确认后才开始记录
    if (monitors[accountId]) monitors[accountId].clearedFlag = true;
    if (monitors[accountId] && monitors[accountId].running) {
      // v1.13.24 监控在跑但实时动态浮窗被关/未创建 → 重新弹出（原来只返回 already，用户以为"打不开"）
      console.log('[监控] 房间', accountId, '监控已在跑，重新弹出实时动态浮窗');
      var oldUi = createMonitorUiWindow(accountId);
      if (!oldUi) setTimeout(() => createMonitorUiWindow(accountId), 1000);
      return { success: true, already: true, ...monitorStateOf(accountId) };
    }
    const data = loadAccounts();
    const info = data[accountId];
    if (!info || !info.cookies || !info.cookies.length) {
      return { success: false, error: '该房间未保存 Cookie，请先登录账号' };
    }
    // v1.13.0 数据源窗口隐藏：监控开启时不再弹出「直播画面」小电视窗口（用户要看直播间 → 实时动态面板「打开直播间」观众视角）
    console.log('[监控] 房间', accountId, '步骤2 创建数据源窗口');
    const win = createAccountWindow(accountId, {
      title: '直播数据源 · 房间' + accountId + (accountName ? ' @' + accountName : ''),
      // v1.15.56 数据源窗口拉宽到桌面端尺寸（380 宽被 TikTok 当移动端渲染：无"观众·N"在线标签、评论区结构不同 → 在线/进场/评论全读不到）；show:false 隐藏不影响用户
      width: 1280, height: 900, show: false,
      // v1.13.15 preload 注入采集（页面加载即运行，绕过 executeJavaScript 失败；与 pollDom 双通道）
      preload: path.join(__dirname, 'monitor-preload.js'),
    });
    await injectSavedCookies(accountId, win.webContents.session);
    // v1.12.30 小电视改回观众页（直播画面视角，用户要看直播间内容）；数据从该页 DOM 获取（在线/点赞/公屏评论/进场/礼物）
    console.log('[监控] 房间', accountId, '步骤3 注入Cookie完成，异步加载观众页');
    // v1.15.23 页面加载不等待（fire-and-forget）：浮窗立即弹出，页面/DOM 数据后台就绪（原来 await 20 秒 → 用户以为浮窗打不开）
    win.loadURL('https://www.tiktok.com/@' + encodeURIComponent(String(accountName || '').replace(/^@/, '')) + '/live', { userAgent: UA })
      .catch(e => console.error('[监控] 页面加载:', e.message));
    // v1.15.52 数据源窗口加载监控：加载完成日志 + preload 报错捕获 + 15s 超时强制重载（观众页偶发卡住→preload 无数据→在线/进场/评论全 0）
    // v1.15.54 preload 失效兜底：主进程 executeJavaScript 每 2s 直接读 body 文本 → 复用 parseDomEvents（preload 死也抓在线/进场/评论）
    try {
      win.webContents.on('did-finish-load', () => {
        // v1.15.60 评论区在纯隐藏窗口不渲染（show:false → TikTok 评论区懒加载/虚拟滚动不触发）→ 透明 + 移出屏幕显示：渲染正常、用户看不见、评论区可读
        try { if (!win.isDestroyed()) { win.setOpacity(0); win.setPosition(-10000, -10000); win.setSkipTaskbar(true); win.showInactive(); } } catch (e) { console.error('[监控] 透明显示:', e.message); }
        console.log('[监控] 房间', accountId, '观众页加载完成，等待 DOM 数据');
        if (!win.__ejTimer) {
          win.__ejTimer = setInterval(async () => {
            try {
              if (win.isDestroyed() || !monitors[accountId] || !monitors[accountId].running) { clearInterval(win.__ejTimer); win.__ejTimer = null; return; }
              // v1.15.59 递归收集所有可读 frame（iframe 嵌套/深层评论区）+ 顶层文本合并解析（评论区可能在深层 frame）
              const info = await win.webContents.executeJavaScript('(function(){ function collect(doc,out){ var t=(doc.body&&doc.body.innerText)||""; if(t) out.push(t); var fs=doc.querySelectorAll("iframe"); for(var i=0;i<fs.length;i++){ try{ var d=fs[i].contentDocument; if(d&&d.body) collect(d,out); }catch(e){} } } var all=[]; collect(document,all); var full=all.join(String.fromCharCode(10)); return {url:location.href,title:document.title,len:full.length,txt:full}; })()');
              if (info && typeof info === 'object' && monitors[accountId]) {
                const sig = String((info.url || '') + '|' + (info.title || '') + '|' + (info.len || 0));
                if (sig !== monitors[accountId].__lastDump) {
                  monitors[accountId].__lastDump = sig;
                  console.log('[监控] 房间', accountId, 'ej页面:', info.url, '|', info.title, '| len', info.len, '|', String(info.txt || '').replace(/\s+/g, ' ').slice(0, 200));
                }
              }
              const t = (info && info.txt) || '';
              if (t && typeof t === 'string' && t.length > 20) {
                const lines = t.split('\n');
                const chatItems = [];
                for (const ln of lines) {
                  const s = (ln || '').trim();
                  if (!s || s.length < 2 || s.length > 80) continue;
                  if (/已加入|进入了直播间|加入了直播间|进入了|加入了/.test(s)) { if (chatItems.length < 100) chatItems.push({ t: s, k: 'enter' }); }
                  else if (chatItems.length < 100) chatItems.push({ t: s, k: 'chat' });
                }
                let online = '';
                const om = t.match(/观众[·\s:：]*(\d{1,7})/);
                if (om) online = om[1];
                const dom = { online, likes: '', chatItems, ended: '', rawText: t.slice(0, 8000) };
                const events = parseDomEvents(accountId, dom);
                if (events.length) {
                  monitors[accountId].lastInteractAt = Date.now();
                  const items = events.map(imEventToFeedItem).filter(Boolean);
                  const onlineEv = events.find(e => e.method === 'WebcastRoomUserSeqMessage');
                  if (items.length || onlineEv) {
                    sendToUI('tiktok:im-events', { accountId, items, methods: events.map(e => e.method), online: onlineEv ? onlineEv.online : null });
                    console.log('[监控] 房间', accountId, 'ej兜底 DOM互动:', items.length, '条', items.map(i => i.type + ':' + (i.user || '') + ':' + (i.text || '').slice(0, 30)).join(' | '));
                  }
                }
              }
            } catch (e) {}
          }, 2000);
        }
      });
      win.webContents.on('console-message', (e, levelOrDetails, messageOrLine, line, sourceId) => {
        try {
          let msg = '';
          if (levelOrDetails && typeof levelOrDetails === 'object') msg = String((levelOrDetails && levelOrDetails.message) || '');
          else msg = String(messageOrLine || '');
          if (msg && msg.length < 250 && /MP-LOADED|error|exception|monitor-preload|cmtDiag|SyntaxError|ReferenceError|TypeError|Unable to load preload/i.test(msg)) console.log('[监控] 房间', accountId, '数据源页 console:', msg);
        } catch (e2) {}
      });
      setTimeout(() => {
        try {
          if (win.isDestroyed() || !monitors[accountId] || !monitors[accountId].running) return;
          if (win.webContents.isLoading()) { console.log('[监控] 房间', accountId, '观众页 15s 未加载完，强制重载'); win.webContents.reload(); }
        } catch (e2) {}
      }, 15000);
    } catch (e) {}

    // v1.15.24 修复重复启动：mon 立即创建（浮窗加载时 monitors 已存在 → 前端 monitorStatus 返回 running → 不会自动二次 startMonitor）
    // v1.13.27 lastInteractAt 从监控启动时开始计时（否则未定义→0→"5分钟无互动"误判为立即触发）
    const mon = { win, roomId: '', cursor: '', running: true, clearedFlag: false, lastInteractAt: Date.now(), onlineCount: 0 };
    monitors[accountId] = mon;

    // v1.15.23 浮窗先弹（不等页面加载/登录态/roomId）
    console.log('[监控] 房间', accountId, '步骤4 创建实时动态浮窗');
    var uiWin = createMonitorUiWindow(accountId);
    if (!uiWin) setTimeout(() => createMonitorUiWindow(accountId), 1000);

    // 后台收敛：登录态检查（6s 兜底）+ 当前直播间 roomId（Node https 直连，与页面无关）
    // v1.15.23 移到浮窗创建之后：浮窗先弹，登录态/roomId 后台收敛（startMonitor promise 稍晚 resolve，浮窗不阻塞）
    const roomIdP = getRoomIdViaApi(accountId, accountName);
    let logged = false;
    for (let i = 0; i < 12; i++) {
      try {
        const cks = await win.webContents.session.cookies.get({});
        if (cks.some(c => c.name === 'sessionid' || c.name === 'sid_tt')) { logged = true; break; }
      } catch (e) {}
      await sleep(500);
    }
    if (!logged) sendToUI('tiktok:monitor-state', { accountId, running: true, warning: '登录态未就绪，监控可能取不到数据' });

    // 获取当前直播间 roomId（主播视角，Node https 直连，无需签名）——与登录态检查并行，结果在此收敛
    let roomId = await roomIdP;
    if (roomId) { mon.roomId = roomId; mon.clearedFlag = false; } // v1.15.36 房间确认 → 解除暂停开始记录（未开播 roomId 空 → 保持全暂停 0 数据）

    const csrf = getCsrfToken(info);

    const pollIm = async () => {
      try {
        if (!mon.running) return;
        // v1.15.29 房间为空（未在播）→ 低频探测恢复（每 5 轮 ≈3.3 分钟），避免每轮重查导致"已切换/已恢复/已下播"状态反复横跳刷屏
        if (!mon.roomId && (mon._probeN || 0) % 5 !== 0) { return; }
        mon._probeN = (mon._probeN || 0) + 1;
        // 每次轮询前重取当前直播间——重新开播/重新获取推流码后 roomId 会变，自动跟随
        // v1.12.10 软件推流中优先跟随推流直播间（观众互动发生在该房间）；未推流时用 api-live 查账号当前直播间
        const newRoom = (streamProcesses[accountId] && streamRooms[accountId])
          ? streamRooms[accountId]
          : await getRoomIdViaApi(accountId, accountName);
        if (newRoom && newRoom !== mon.roomId) {
          const oldRoom = mon.roomId;
          mon.roomId = newRoom;
          mon.cursor = '';
          // v1.15.32 房间号变化 → 暂停记录（数据保留）：clearedFlag=true，等 IM 拉取新房间成功后再恢复记录（数据不清空，只加不减）
          mon.clearedFlag = true;
          // v1.9.5 直播间切换 → 重置互动面板增量基准（点赞/礼物计数跨房间不复用）
          if (domPanelLast[accountId]) domPanelLast[accountId] = { gifts: 0, comments: 0, likes: 0 };
          // v1.13.8 直播间切换 → 同时重置 DOM 去重（新场次互动不被旧场次文本吞掉）
          if (domSeen[accountId]) domSeen[accountId] = { set: new Set(), list: [] };
          sendToUI('tiktok:monitor-state', { accountId, running: true, roomId: newRoom });
          console.log('[监控] 房间', accountId, '直播间切换:', oldRoom, '→', newRoom);
          // v1.9.6 直播间切换 → 旧房间数据清零（数据跟随直播间走）
          sendMonitorCleared(accountId, '直播间已切换');
          // v1.9.6 单端开播：软件推流中直播间被替换 → 自动停止推流（手机端开播则软件端被挤掉）
          // v1.12.3：软件推流中不因房间切换停流（软件推流为主；"手机被挤"由推流成功后主动关手机直播间实现）
          if (!streamProcesses[accountId]) stopStreamIfStreaming(accountId, '检测到直播间被替换，已自动停止推流（单端开播）');
          // v1.9.0 新直播间就绪 → 冷启动欢迎语（roomId 变化视为新开播，重新触发）
          const ast = autoSendState[accountId];
          if (ast) ast.coldStarted = false;
          triggerColdStart(accountId);
        } else if (!newRoom) {
          // v1.9.6 直播间下播：连续 2 轮确认（约 1 分钟）才清零，避免瞬时 API 抖动误清
          // v1.12.3 修复：软件推流中不判"下播"（create 房间 status=1 准备态会被误判停流）
          if (streamProcesses[accountId]) { mon.emptyStreak = 0; }
          else {
            mon.emptyStreak = (mon.emptyStreak || 0) + 1;
            if (mon.emptyStreak >= 2) {
              mon.emptyStreak = 0;
              mon.roomId = ''; // v1.13.8 未在播 → 清 roomId，停止旧房间拉流
              sendMonitorCleared(accountId, '直播间已下播');
              stopStreamIfStreaming(accountId, '直播间已下播，已自动停止推流');
            }
          }
        } else {
          mon.emptyStreak = 0;
          // v1.9.6 低频校验直播间真实状态 + v1.15.3 在线人数更新（room/info user_count）
          // v1.15.6 每轮查询（原 %2 ≈ 80 秒 → %1 ≈ 40 秒），在线人数反应更快
          mon.statusCheckN = (mon.statusCheckN || 0) + 1;
          if (mon.statusCheckN % 1 === 0 && mon.roomId) {
            const st = await getRoomStatusViaApi(accountId, mon.roomId);
            // v1.12.3：status=1（房间准备态）不算结束；软件推流中不因状态变化停流
            if (st === 2 || (st === 1 && streamProcesses[accountId])) { mon.statusEndStreak = 0; }
            else if (st !== 2 && st !== 1) {
              mon.statusEndStreak = (mon.statusEndStreak || 0) + 1;
              if (mon.statusEndStreak >= 2) {
                mon.statusEndStreak = 0;
                mon.roomId = ''; // v1.13.8 房间已结束 → 清 roomId
                sendMonitorCleared(accountId, '直播间已结束');
                stopStreamIfStreaming(accountId, '直播间已结束，已自动停止推流');
              }
            } else { mon.statusEndStreak = 0; }
          }
        }
        if (!mon.roomId) return;
        const r = await imFetchViaApi(accountId, mon.roomId, mon.cursor);
        if (r.ok) {          // v1.12.8 首轮/直播间切换后首轮：只建立 cursor，丢弃返回的历史消息
          // v1.15.36 IM 通道诊断：返回消息数（观众页有评论但面板 0 时查这行定位通道是否通）
          console.log('[监控] 房间', accountId, 'IM fetch ok: msgs=' + (r.messages || []).length + ' cursor=' + String(r.cursor || '').slice(0, 12));
          // v1.13.8 下播暂停恢复：IM 通道确认房间重新在播（fetch 成功）→ 解除暂停，前端清空旧场次重新记录
          if (mon.clearedFlag) {
            mon.clearedFlag = false;
            sendToUI('tiktok:monitor-cleared', { accountId, reason: '直播间已恢复，重新记录实时数据' });
          }
          // （IM 接口在 cursor 为空时会返回直播间历史消息，含上轮直播的礼物/点赞 → 刚开播出现"玫瑰"假数据）
          // v1.13.16 首轮一次性：不再用 !mon.cursor 判断（im/fetch 可能长期返回空 cursor → 永远首轮 → 消息全被丢弃）
          const firstPoll = !mon.firstPollOnce;
          if (firstPoll) mon.firstPollOnce = true;
          mon.cursor = r.cursor || mon.cursor;
          // v1.15.33 首轮也推送：历史评论/进场补计（用户要求评论总数与观众端一致）；首轮不触发自动互动（防历史消息刷回复）
          const events = (r.messages || []).map(parseImMessage).filter(e => e && (e.method === 'WebcastChatMessage' || e.method === 'WebcastMemberMessage'));
          const items = events.map(imEventToFeedItem).filter(Boolean);
          // v1.15.13 在线只信观众页 DOM（person-count 实时加减）：room/info user_count 平台统计有延迟（观众走了还报 1）会覆盖实时 0，不再作为在线来源
          const onlineEv = null;
          if (items.length || (onlineEv && onlineEv.online)) {
            mon.clearedFlag = false; // v1.13.3 有新互动数据 → 解除下播清零去重
            sendToUI('tiktok:im-events', {
              accountId, items,
              methods: events.map(e => e.method),
              online: onlineEv ? onlineEv.online : null, // v1.15.17 无在线事件推 null，前端不覆盖 DOM 实时在线
            });
            if (items.length) console.log('[监控] 房间', accountId, (firstPoll ? 'IM首轮(历史补计)' : 'IM事件'), items.length, '条', items.map(i => i.type + ':' + (i.user || '') + ':' + (i.text || '').slice(0, 30)).join(' | '));
            // v1.9.0 自动互动（感谢/欢迎/智能回复），内部有节流，不阻塞轮询；首轮历史不触发（防历史消息刷自动回复）
            if (!firstPoll) handleAutoInteract(accountId, events).catch(() => {});
          }
        } else {
          // v1.13.2 房间已结束（30003）/无活跃房间（10013）→ 实时数据立即清零（不等多轮确认）
          // v1.13.8 同时清 roomId：避免 im/fetch 继续用旧房间拉取 TikTok 推荐流消息（"推荐的主播进入了直播间"假数据）
          if (r && (r.code === 30003 || r.code === 10013)) {
            mon.roomId = '';
            sendMonitorCleared(accountId, '直播间已结束（IM通道确认）');
            stopStreamIfStreaming(accountId, '直播间已结束，已自动停止推流');
          } else {
            console.log('[监控] 房间', accountId, 'im/fetch:', r.error || ('code=' + r.code));
          }
        }
      } catch (e) { console.log('[监控] 房间', accountId, 'IM轮询:', e.message); }
    };

    const scanRisk = async () => {
      try {
        if (!mon.running) return;
        const raw = await Promise.race([
          win.webContents.executeJavaScript(RISK_SCAN_SCRIPT),
          new Promise(r => setTimeout(() => r('{"title":"","url":"","text":""}'), 6000)),
        ]);
        const page = JSON.parse(raw);
        const risk = classifyRiskInfo(page);
        if (risk) {
          const prev = (riskLastSent[accountId] || {})[risk.key];
          if (!prev || Date.now() - prev > RISK_DEDUP_MS) {
            if (!riskLastSent[accountId]) riskLastSent[accountId] = {};
            riskLastSent[accountId][risk.key] = Date.now();
            sendToUI('tiktok:risk-warning', { accountId, risk, page });
            console.log('[风险] 房间', accountId, '→', risk.cn);
          }
        }
      } catch (e) { console.log('[监控] 房间', accountId, '风险扫描:', e.message); }
    };

    // v1.9.2 互动数据以 DOM 扫描为主（页面自带签名拉流），im/fetch API 降为低频补充
    // v1.9.4 修复：pollDom 需要 accountId，setInterval/setTimeout 必须闭包传参（之前一直 pollDom(undefined)→no-mon）
    mon.imTimer = setInterval(() => pollDom(accountId), DOM_POLL_MS);
    mon.imFetchTimer = setInterval(pollIm, IM_POLL_MS * 4);
    // v1.14.11 风险告警停用：不再启动风险扫描定时器
    if (RISK_ALERTS_ENABLED) {
      mon.riskTimer = setInterval(scanRisk, RISK_POLL_MS);
    }
    // v1.13.0 移除小电视截取（tvTimer）：监控窗口隐藏，不再每 3s 截屏推送 monitor-frame（用户要看直播间画面 → 打开直播间按钮）
    // v1.14.13 数据源窗口渲染进程崩溃保护：崩溃时重载页面（不让窗口直接关闭丢 DOM 通道）；reload 失败窗口 closed 时由 closed 兜底自动重建
    win.webContents.on('render-process-gone', (e, details) => {
      console.log('[监控] 房间', accountId, '数据源渲染进程异常:', details && details.reason, '→ 自动重载页面');
      try { win.webContents.reload(); } catch (e2) {}
    });
    // v1.14.15 观众页加载失败（网络/登录墙/重定向）自动重载：防止窗口开着但页面空转（executeJavaScript/preload 都拿不到数据）
    win.webContents.on('did-fail-load', (e, errCode, errDesc, url) => {
      if (mon.running && errCode !== -3) {
        console.log('[监控] 房间', accountId, '观众页加载失败（', errCode, errDesc, '），3 秒后自动重载…');
        setTimeout(() => { try { if (!win.isDestroyed() && mon.running) win.webContents.reload(); } catch (e2) {} }, 3000);
      }
    });
    win.on('closed', () => {
      if (monitors[accountId] === mon) {
        clearInterval(mon.imTimer); clearInterval(mon.imFetchTimer); clearInterval(mon.riskTimer); clearInterval(mon.tvTimer);
        delete monitors[accountId];
        // v1.14.15 数据源窗口（隐藏，用户关不掉）意外关闭：不再连带关闭实时动态浮窗——浮窗继续显示 pollIm/IM 通道数据（独立于 DOM 通道），只重建数据源窗口恢复 DOM 通道
        // （此前 v1.14.14 意外关闭时连浮窗一起关 → 新电脑数据源窗口反复加载失败 → 浮窗闪退）
        if (mon.running) {
          console.log('[监控] 房间', accountId, '数据源窗口意外关闭，5 秒后自动重建…（实时动态浮窗保留，IM 数据不断）');
          setTimeout(() => {
            startMonitor(accountId, accountName).then(r => {
              if (!r || !r.success) console.log('[监控] 房间', accountId, '自动重建失败:', r && r.error);
            });
          }, 5000);
        } else {
          // 用户主动停止监控（monitor:stop 已置 running=false）：才关闭浮窗
          try { if (monitorUIs[accountId] && !monitorUIs[accountId].isDestroyed()) monitorUIs[accountId].close(); } catch (e) {}
          delete monitorUIs[accountId];
        }
        sendToUI('tiktok:monitor-state', { accountId, running: false });
      }
    });
    setTimeout(() => pollDom(accountId), 2000);
    if (RISK_ALERTS_ENABLED) setTimeout(scanRisk, 3000);

    sendToUI('tiktok:monitor-state', { accountId, running: true, roomId });
    // v1.9.0 冷启动：直播就绪后自动发欢迎语（不阻塞）
    if (roomId) triggerColdStart(accountId);
    return { success: true, running: true, roomId };
  } catch (e) {
    console.error('[监控] 房间', accountId, e.message);
    return { success: false, error: e.message };
  }
}

// v1.14.13 monitor:start → startMonitor（抽函数供数据源窗口意外关闭后自动重建复用）
ipcMain.handle('monitor:start', async (event, { accountId, accountName }) => startMonitor(accountId, accountName));

// v1.15.3 抽 stopMonitor：监控停止统一入口（用户手动停止 / 手机下播自动停止共用）
function stopMonitor(accountId) {
  const mon = monitors[accountId];
  if (mon) {
    mon.running = false;
    clearInterval(mon.imTimer); clearInterval(mon.imFetchTimer); clearInterval(mon.riskTimer); clearInterval(mon.tvTimer);
    try { if (mon.win && !mon.win.isDestroyed()) mon.win.close(); } catch (e) {}
    try { if (monitorUIs[accountId] && !monitorUIs[accountId].isDestroyed()) monitorUIs[accountId].close(); } catch (e) {}
    delete monitorUIs[accountId];
    delete monitors[accountId];
  }
  // v1.10.0 停止监控 → 前端实时数据立即清零
  sendToUI('tiktok:monitor-cleared', { accountId, reason: '监控已停止，数据已清零' });
  sendToUI('tiktok:monitor-state', { accountId, running: false });
}

ipcMain.handle('monitor:stop', async (event, { accountId }) => {
  stopMonitor(accountId);
  return { success: true, running: false };
});

ipcMain.handle('monitor:status', async (event, { accountId }) => monitorStateOf(accountId));

// v1.13.0 独立监控窗口聚焦：只聚焦「实时动态」监控窗口（不再弹出数据源/小电视窗口）
ipcMain.handle('monitor:focusUI', async (event, { accountId }) => {
  const w = monitorUIs[accountId];
  if (w && !w.isDestroyed()) { w.show(); w.focus(); return { success: true }; }
  return { success: false, error: '独立监控窗口未创建，请先开启监控' };
});

// v1.11.0 独立监控窗口：置顶切换（不被其他窗口盖住）
ipcMain.handle('monitor:pin', async (event, { accountId, on }) => {
  const w = monitorUIs[accountId];
  if (w && !w.isDestroyed()) { w.setAlwaysOnTop(!!on); return { success: true, pinned: !!on }; }
  return { success: false };
});

// ============================================================
// v1.9.0 自动互动引擎：发评论 + 自动感谢/欢迎 + 冷启动欢迎语 + 智能回复
// 发评论通道：监控窗口 DOM 注入（官方通道思路——主播控制台自带评论区，
// 直接操作评论区输入框模拟输入+回车/点发送，无需签名接口）
// ============================================================
const AUTO_SEND_MIN_GAP_MS = 25 * 1000;   // 自动发评论最小间隔（防刷屏/防封，抖歪同款 MIN_GAP_MS）
const autoSendState = {};  // accountId -> { lastAutoTs, lastEnterTs, coldStarted, coldTimer }
// v1.14.11 僵尸清理：ENTER_WELCOME_GAP_MS / INTERACT_COOLDOWNS / perUserActionAt / inActionCooldown 已删除
// （进场欢迎早已关闭、点赞/礼物自动回复 v1.14.11 已关闭 → 这些冷却逻辑无任何调用点）

// 互动模板（按语言；用户已有语言选项全部覆盖，简版英语/中文 + 多语言感谢欢迎）
const INTERACT_TEMPLATES = {
  // v1.13.25 模板：like=感谢点赞 / mention=@提及感谢；enter/follow 保留但不再自动触发（主播不主动发言，只在 点赞/礼物/@ 时回）
  '英语(美区)': { gift: 'Thank you @{user} for the gift! ❤️', follow: 'Thanks for the follow @{user}! ❤️', enter: 'Welcome to the live @{user}! ❤️', like: 'Thanks for the likes @{user}! ❤️', mention: 'Thanks for the shoutout @{user}! ❤️', fallback: 'Thanks for watching! ❤️' },
  '英语(英区)': { gift: 'Thank you @{user} for the gift! ❤️', follow: 'Thanks for following @{user}! ❤️', enter: 'Welcome to the stream @{user}! ❤️', like: 'Thanks for the likes @{user}! ❤️', mention: 'Thanks for the shoutout @{user}! ❤️', fallback: 'Thanks for watching! ❤️' },
  '中文': { gift: '感谢 @{user} 送出的礼物！', follow: '感谢 @{user} 的关注！', enter: '欢迎 @{user} 来到直播间！', like: '感谢 @{user} 的点赞！', mention: '感谢 @{user} 的互动！', fallback: '感谢观看！' },
  '日语': { gift: '@{user} さん、ギフトありがとうございます！', follow: '@{user} さん、フォローありがとうございます！', enter: '@{user} さん、いらっしゃい！', like: '@{user} さん、いいねありがとうございます！', mention: '@{user} さん、ありがとうございます！', fallback: 'ご視聴ありがとうございます！' },
  '韩语': { gift: '@{user} 님, 선물 감사합니다!', follow: '@{user} 님, 팔로우 감사합니다!', enter: '@{user} 님, 환영합니다!', like: '@{user} 님, 좋아요 감사합니다!', mention: '@{user} 님, 감사합니다!', fallback: '시청해 주셔서 감사합니다!' },
  '西班牙语': { gift: '¡Gracias @{user} por el regalo! ❤️', follow: '¡Gracias por seguir @{user}! ❤️', enter: '¡Bienvenido al directo @{user}! ❤️', like: '¡Gracias por los likes @{user}! ❤️', mention: '¡Gracias por la mención @{user}! ❤️', fallback: '¡Gracias por ver! ❤️' },
  '葡萄牙语': { gift: 'Obrigado @{user} pelo presente! ❤️', follow: 'Obrigado por seguir @{user}! ❤️', enter: 'Bem-vindo à live @{user}! ❤️', like: 'Obrigado pelos likes @{user}! ❤️', mention: 'Obrigado pela menção @{user}! ❤️', fallback: 'Obrigado por assistir! ❤️' },
};

// v1.14.11 僵尸清理：autoReplySuggest 函数已删除（智能自动猜回复 v1.13.25 起不再触发、零调用点）；
// INTERACT_REPLY_LANGS 多语言回复数据保留（数据非代码，未来恢复智能回复可直接复用）
const INTERACT_REPLY_LANGS = {
  '英语(美区)': {
    price: ['Thanks for asking! DM me and I can share the details 💬', 'Price is on the link in my bio — check it out! 🔗', 'Great question! Tap the link in bio for pricing 🙌'],
    link: ['The link is in my bio — click it and it will take you right there 🔗', 'Yes! You can find it in the link in my bio ✨', 'DM me and I will send you the link right away 💬'],
    shipping: ['We ship worldwide! Details are in the link in bio 📦', 'Usually 5–7 days to most countries! 🌍', 'Shipping info is on the link in my bio, check it out 🚚'],
    praise: ['So happy you love it! Thank you for watching 💖', 'You made my day! Stay tuned for more 🥰', 'Thank you! More exciting stuff is coming soon ✨'],
    size: ['It comes in several sizes — see the link in bio for the size chart 📐', 'Good question! Sizes are listed in the link in my bio 👍'],
    general: ['Thanks for the comment! Feel free to ask me anything 🙌', 'Love having you here! Follow for more updates ✨', 'Great to see you in the live! Stay tuned 🎉'],
  },
  '英语(英区)': {
    price: ['Thanks for asking! Drop me a DM and I can share the details 💬', 'The price is on the link in my bio — have a look! 🔗', 'Great question! Tap the link in bio for pricing 🙌'],
    link: ['The link is in my bio — click it and you will find it 🔗', 'Yes! It is on the link in my bio ✨', 'DM me and I will send you the link right away 💬'],
    shipping: ['We ship worldwide! Details are in the link in bio 📦', 'Usually 5–7 days to most countries! 🌍', 'Shipping info is on the link in my bio, check it out 🚚'],
    praise: ['So glad you love it! Thank you for watching 💖', 'You have made my day! Stay tuned for more 🥰', 'Thank you! More exciting stuff is on the way ✨'],
    size: ['It comes in several sizes — see the link in bio for the size chart 📐', 'Good question! Sizes are listed in the link in my bio 👍'],
    general: ['Thanks for the comment! Feel free to ask me anything 🙌', 'Love having you here! Follow for more updates ✨', 'Great to see you in the live! Stay tuned 🎉'],
  },
  '中文': {
    price: ['感谢提问！私信我告诉你详情 💬', '价格在简介链接里，点进去就能看到 🔗', '好问题！点简介链接查看价格 🙌'],
    link: ['链接在简介里，点进去就能找到 🔗', '有的！简介链接就是它 ✨', '私信我，马上把链接发给你 💬'],
    shipping: ['全球发货！详情见简介链接 📦', '一般 5–7 天到大部分国家 🌍', '物流信息在简介链接里 🚚'],
    praise: ['太开心你喜欢！感谢观看 💖', '你让我今天超开心！记得蹲后续 🥰', '谢谢！更多精彩马上来 ✨'],
    size: ['有好几个尺码，简介链接里有尺码表 📐', '好问题！尺码在简介链接里 👍'],
    general: ['谢谢评论！有问题随时问我 🙌', '欢迎常来！点个关注不迷路 ✨', '看到你真开心，继续蹲直播 🎉'],
  },
  '日语': {
    price: ['ご質問ありがとうございます！DMで詳細をお伝えします 💬', '価格はプロフィールのリンクにあります 🔗', 'いい質問ですね！プロフィールのリンクをご覧ください 🙌'],
    link: ['リンクはプロフィールにあります 🔗', 'はい！プロフィールのリンクにあります ✨', 'DMでリンクをお送りします 💬'],
    shipping: ['世界中に発送します！詳細はプロフィールのリンクへ 📦', '通常5〜7日で到着します 🌍', '発送情報はプロフィールのリンクにあります 🚚'],
    praise: ['気に入ってくれて嬉しいです！ありがとうございます 💖', '最高の一日になりました！お楽しみに 🥰', 'ありがとうございます！これからもお楽しみに ✨'],
    size: ['サイズ展開あり、プロフィールのリンクにサイズ表があります 📐', 'いい質問！サイズはプロフィールのリンクに 👍'],
    general: ['コメントありがとうございます！何でも聞いてください 🙌', 'ご覧いただきありがとうございます！フォローよろしく ✨', 'ライブに来てくれて嬉しいです！お楽しみに 🎉'],
  },
  '韩语': {
    price: ['질문 감사합니다! DM으로 알려드릴게요 💬', '가격은 프로필 링크에 있어요 🔗', '좋은 질문! 프로필 링크를 확인해 주세요 🙌'],
    link: ['링크는 프로필에 있어요 🔗', '네! 프로필 링크에 있어요 ✨', 'DM으로 바로 보내드릴게요 💬'],
    shipping: ['전 세계 배송! 자세한 건 프로필 링크에요 📦', '보통 5~7일이면 도착해요 🌍', '배송 정보는 프로필 링크에 있어요 🚚'],
    praise: ['좋아해 주셔서 감사합니다! 봐주셔서 감사해요 💖', '오늘 하루가 행복해졌어요! 계속 봐주세요 🥰', '감사합니다! 더 재미있는 것들이 곧 나와요 ✨'],
    size: ['여러 사이즈로 나와요 — 프로필 링크에 사이즈표 있어요 📐', '좋은 질문! 사이즈는 프로필 링크에 있어요 👍'],
    general: ['댓글 감사합니다! 무엇이든 물어보세요 🙌', '와주셔서 감사합니다! 팔로우 해주세요 ✨', '라이브에 와주셔서 반가워요! 계속 봐주세요 🎉'],
  },
  '西班牙语': {
    price: ['¡Gracias por preguntar! Escríbeme y te cuento los detalles 💬', 'El precio está en el enlace de mi perfil — ¡míralo! 🔗', '¡Buena pregunta! Toca el enlace del perfil para ver precios 🙌'],
    link: ['El enlace está en mi perfil — te lleva directo 🔗', '¡Sí! Lo encuentras en el enlace de mi perfil ✨', 'Mándame un mensaje y te envío el enlace 💬'],
    shipping: ['¡Enviamos a todo el mundo! Detalles en el enlace del perfil 📦', '¡Normalmente 5–7 días a la mayoría de países! 🌍', 'Info de envío en el enlace del perfil 🚚'],
    praise: ['¡Me alegra que te encante! Gracias por ver 💖', '¡Hiciste mi día! Quédate para más 🥰', '¡Gracias! Vienen más cosas emocionantes ✨'],
    size: ['Viene en varios tamaños — mira la tabla en el enlace del perfil 📐', '¡Buena pregunta! Las tallas están en el enlace del perfil 👍'],
    general: ['¡Gracias por el comentario! Pregúntame lo que quieras 🙌', '¡Me encanta que estés aquí! Sigue para más ✨', '¡Qué bueno verte en el directo! Quédate 🎉'],
  },
  '葡萄牙语': {
    price: ['Obrigado por perguntar! Me chama no DM que eu te conto 💬', 'O preço está no link da bio — dá uma olhada! 🔗', 'Ótima pergunta! Toca no link da bio para ver preços 🙌'],
    link: ['O link está na bio — clica que te leva direto 🔗', 'Sim! Você encontra no link da bio ✨', 'Me chama no DM que eu te mando o link 💬'],
    shipping: ['Enviamos para o mundo todo! Detalhes no link da bio 📦', 'Normalmente 5–7 dias para a maioria dos países! 🌍', 'Info de envio no link da bio 🚚'],
    praise: ['Que bom que você amou! Obrigado por assistir 💖', 'Você fez o meu dia! Fica ligado para mais 🥰', 'Obrigado! Coisas incríveis vêm por aí ✨'],
    size: ['Vem em vários tamanhos — veja a tabela no link da bio 📐', 'Boa pergunta! Os tamanhos estão no link da bio 👍'],
    general: ['Obrigado pelo comentário! Pode perguntar qualquer coisa 🙌', 'Adoro ter você aqui! Segue para mais ✨', 'Que bom te ver na live! Fica de olho 🎉'],
  },
};

// TikTok直播式发评论注入脚本（覆盖主播控制台 room-chat-input-field 评论区）
function buildSendCommentExpression(text) {
  const msg = JSON.stringify(String(text == null ? '' : text).slice(0, 200));
  return `(async () => {
    const msg = ${msg};
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    const visible = el => { if (!el) return false; try { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; } catch (e) { return false; } };
    const editable = el => { if (!el || !el.getAttribute) return false; const a = el.getAttribute('contenteditable'); return a === '' || a === 'true' || a === 'plaintext-only'; };
    const setValue = (el, val) => {
      if (editable(el)) {
        el.focus();
        try { document.execCommand('selectAll', false, null); } catch (e) {}
        try { document.execCommand('insertText', false, val); } catch (e) {}
      } else {
        const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement : window.HTMLInputElement;
        const desc = proto ? Object.getOwnPropertyDescriptor(proto.prototype, 'value') : null;
        if (desc && desc.set) desc.set.call(el, val);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      }
    };
    const pressEnter = el => {
      const opt = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true };
      try { el.dispatchEvent(new KeyboardEvent('keydown', opt)); el.dispatchEvent(new KeyboardEvent('keypress', opt)); el.dispatchEvent(new KeyboardEvent('keyup', opt)); } catch (e) {}
    };
    const findInput = () => {
      const sels = [
        '[data-e2e="room-chat-input-field"]',
        '[data-e2e="comment-input"]',
        '[contenteditable][data-e2e*="comment" i]',
        'textarea[data-e2e*="comment" i]',
        'input[type="text"]',
        '[contenteditable="plaintext-only"]',
        '[contenteditable]:not([contenteditable="false"])'
      ];
      let list = [];
      sels.forEach(s => { try { document.querySelectorAll(s).forEach(e => list.push(e)); } catch (e) {} });
      return list.find(visible);
    };
    let input = findInput();
    if (!input) {
      try {
        const h = document.querySelector('[data-e2e="room-chat-input-field"]') || document.querySelector('[contenteditable][data-e2e*="comment" i]');
        if (h) h.focus();
      } catch (e) {}
      await sleep(600);
      input = findInput();
    }
    if (!input) return JSON.stringify({ ok: false, reason: 'no-input', url: location.href });
    try { setValue(input, msg); } catch (e) { return JSON.stringify({ ok: false, reason: 'set-fail:' + e.message }); }
    await sleep(300);
    const cur = editable(input) ? (input.textContent || '') : (input.value || '');
    if (cur !== msg) { try { setValue(input, msg); } catch (e) {} }
    pressEnter(input);
    await sleep(500);
    const btn = document.querySelector('[data-e2e="comment-post" i], [data-e2e="comment_send" i], [data-e2e="live_comment_post" i], [data-e2e="send-comment" i]');
    if (btn) { try { btn.click(); } catch (e) {} return JSON.stringify({ ok: true, mode: 'click' }); }
    return JSON.stringify({ ok: true, mode: 'enter' });
  })()`;
}

// 在监控窗口注入发评论
async function sendLiveComment(accountId, text) {
  const mon = monitors[accountId];
  if (!mon || !mon.win || mon.win.isDestroyed()) return { ok: false, reason: 'monitor-not-running' };
  try {
    const raw = await mon.win.webContents.executeJavaScript(buildSendCommentExpression(text), true);
    let j = {};
    try { j = JSON.parse(raw); } catch (e) { j = { raw: String(raw).slice(0, 200) }; }
    return { ok: !!j.ok, mode: j.mode || '', reason: j.reason || '' };
  } catch (e) { return { ok: false, reason: e.message }; }
}

function getAutoConfig(accountId) {
  try {
    const info = loadAccounts()[accountId];
    return (info && info.autoInteract) || { enabled: false, lang: '英语(美区)', coldStart: false, welcomeMsg: '' };
  } catch (e) { return { enabled: false, lang: '英语(美区)', coldStart: false, welcomeMsg: '' }; }
}

// 自动互动：IM 事件 → 感谢（v1.13.25 只在 点赞/礼物/@提及/自定义关键词 时回复；进场/关注不再主动发言）
async function handleAutoInteract(accountId, events) {
  // v1.15.8 恢复自动互动（仅 @提及 + 关键词手动配置回复）；点赞/关注/礼物自动回复保持关闭（平台风控机器人行为）
  try {
    const cfg = getAutoConfig(accountId);
    if (!cfg.enabled || !events || !events.length) return;
    const st = autoSendState[accountId] || (autoSendState[accountId] = { lastAutoTs: 0, lastEnterTs: 0, coldStarted: false, coldTimer: null });
    const now = Date.now();
    if (now - st.lastAutoTs < AUTO_SEND_MIN_GAP_MS) return;
    let text = '';
    const t = INTERACT_TEMPLATES[cfg.lang] || INTERACT_TEMPLATES['英语(美区)'];
    for (const ev of events) {
      const method = ev && ev.method;
      const uid = ev.nickname || '';
      // v1.14.11 点赞/礼物自动回复已关闭（用户要求：不再对点赞、刷礼物自动发言，避免话术密集；仅保留 @提及 与自定义关键词回复）
      if (method === 'WebcastGiftMessage' || method === 'WebcastLikeMessage') continue;
      if (method === 'WebcastChatMessage') {
        // v1.13.25 评论只在：自定义关键词命中 或 评论含 @（提及主播）时回复；普通评论/自动猜回复不再触发（话术不密集）
        const c = String(ev.content || '').toLowerCase();
        const rules = (cfg.replyRules || []).filter(r => r && r.keyword && r.reply);
        let hit = null;
        for (const r of rules) { if (c.includes(String(r.keyword).toLowerCase())) { hit = r.reply; break; } }
        if (hit) text = hit;
        else if (c.indexOf('@') >= 0) text = (t.mention || t.fallback).replace(/\{user\}/g, uid || '');
      } else {
        continue;
      }
      if (text) break;
    }
    if (!text) return;
    st.lastAutoTs = Date.now();
    const r = await sendLiveComment(accountId, text);
    const who = (events[0] && events[0].nickname) || '';
    console.log('[自动互动] 房间', accountId, r.ok ? '已发送' : ('发送失败 ' + (r.reason || '')), '→', text);
    sendToUI('tiktok:progress', { accountId, text: '自动互动' + (r.ok ? '已发送「' + text + '」' : '发送失败:' + (r.reason || '')) });
  } catch (e) { console.log('[自动互动] 房间', accountId, '异常:', e.message); }
}

// 冷启动：开播连接就绪后随机发 3 条欢迎语，间隔 25s+，重连（同一直播间）不重复
function shuffleArray(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
async function triggerColdStart(accountId) {
  // v1.15.8 冷启动恢复：手动开关控制（cfg.coldStart），用户自己决定是否开播自动发欢迎语
  try {
    const cfg = getAutoConfig(accountId);
    if (!cfg.coldStart) return;
    const st = autoSendState[accountId] || (autoSendState[accountId] = { lastAutoTs: 0, lastEnterTs: 0, coldStarted: false, coldTimer: null });
    if (st.coldStarted) return; // 重连不重复触发
    st.coldStarted = true;
    let sentences = String(cfg.welcomeMsg || '').split(/[。.]/).map(s => s.trim()).filter(s => s.length > 0 && s.length <= 80);
    if (!sentences.length) sentences = [String(cfg.welcomeMsg || 'Welcome to the live!').slice(0, 80)];
    const picked = shuffleArray(sentences).slice(0, 3);
    sendToUI('tiktok:progress', { accountId, text: '冷启动: 开播就绪，将发送 ' + picked.length + ' 条欢迎语（间隔25s+）' });
    for (let i = 0; i < picked.length; i++) {
      await sleep(AUTO_SEND_MIN_GAP_MS + Math.floor(Math.random() * 5000));
      if (!monitors[accountId]) return; // 监控已停则中止
      const r = await sendLiveComment(accountId, picked[i]);
      console.log('[冷启动] 房间', accountId, (i + 1) + '/' + picked.length, r.ok ? 'OK' : ('失败 ' + (r.reason || '')));
      sendToUI('tiktok:progress', { accountId, text: '冷启动欢迎语 ' + (i + 1) + '/' + picked.length + (r.ok ? ' 已发送' : ' 发送失败:' + (r.reason || '')) });
    }
  } catch (e) { console.log('[冷启动] 房间', accountId, '异常:', e.message); }
}

ipcMain.handle('monitor:sendComment', async (event, { accountId, text }) => {
  const msg = String(text || '').trim();
  if (!msg) return { ok: false, reason: 'empty' };
  const r = await sendLiveComment(accountId, msg);
  if (r.ok) console.log('[手动发评论] 房间', accountId, '→', msg);
  return r;
});

// v1.9.0 账号自动互动配置同步（前端改动 → accounts.json，主进程自动互动读它）
ipcMain.handle('account:saveConfig', (event, { accountId, autoInteract }) => {
  try {
    const data = loadAccounts();
    if (data[accountId]) {
      data[accountId].autoInteract = autoInteract || {};
      saveAccounts(data);
      return { success: true };
    }
    return { success: false, error: '账号不存在' };
  } catch (e) { return { success: false, error: e.message }; }
});
