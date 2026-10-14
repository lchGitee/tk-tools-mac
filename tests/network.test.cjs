const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { EventEmitter, once } = require('node:events');
const net = require('node:net');
const path = require('node:path');
const { createOutputProgressTracker } = require('../src/stream-progress');
const { MediaEgress } = require('../src/media-egress');
const main = fs.readFileSync(path.join(__dirname, '../src/main.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../src/index.html'), 'utf8');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function functionSource(source, name) {
  const match = source.match(new RegExp('(?:async )?function ' + name + '\\([^\\n]*\\)[^\\n]*\\{[\\s\\S]*?\\n}'));
  assert.ok(match, name);
  return match[0];
}
function proxyHarness(nodes = [{ id: 1, name: 'test', link: 'node-A' }]) {
  const events = [], probed = [];
  const session = { async setProxy(config) { events.push('proxy:' + (config.proxyRules || 'direct')); await delay(2); }, async closeAllConnections() { events.push('connections-closed'); } };
  const state = { nodes, active: 0, maxActive: 0 };
  class Runtime {
    constructor() { this.running = false; this.proc = { child: { pid: 700 } }; }
    isRunning() { return this.running; }
    endpoint() { return { host: '127.0.0.1', port: 52123 }; }
    async start(link) { events.push('start:' + link); await delay(8); this.activeLink = link; this.running = true; state.active++; state.maxActive = Math.max(state.maxActive, state.active); return this.endpoint(); }
    async stop() { events.push('stop'); await delay(8); if (this.running) state.active--; this.running = false; }
  }
  const context = vm.createContext({
    readNodesFile: () => state.nodes, XRAY_PROXY_PORT: 10888, xrayRuntime: null, proxyShutdownPending: false,
    accountWindows: {}, process: { env: {} }, app: { getPath: () => '/unused' }, session: { defaultSession: session }, XrayRuntime: Runtime,
    net: { connect(options) { probed.push(options.port); const socket = new EventEmitter(); socket.destroy = () => {}; socket.setTimeout = () => {}; queueMicrotask(() => socket.emit('error', new Error('not listening'))); return socket; } },
    console: { log() {}, error() {} }, URL,
  });
  vm.runInContext(main.slice(main.indexOf('let _builtinProxyOn ='), main.indexOf('// v1.14.17 代理出口实测')) + '\n' + main.slice(main.indexOf('async function applySessionProxy'), main.indexOf('// v1.14.5 一键导出诊断包')) + '\n' + functionSource(main, 'detectHttpProxy'), context);
  const api = vm.runInContext('({ syncBuiltinProxy, refreshEffectiveProxy, detectHttpProxy, loadAccountPage, getProxy: () => _effectiveProxy })', context);
  return { api, context, state, events, probed, session };
}

test('端口被占用后的实际端口同时用于页面和媒体出口，仍为 SOCKS5', async () => {
  const h = proxyHarness();
  await h.api.syncBuiltinProxy();
  assert.equal(h.api.getProxy(), 'socks5://127.0.0.1:52123');
  const proxy = await h.api.detectHttpProxy();
  assert.equal(proxy.port, 52123);
  assert.equal(proxy.type, 'socks5');
  assert.equal(h.probed.length, 0);
});
test('配置节点但常驻进程未运行时，不借用其他程序的固定端口', async () => {
  const h = proxyHarness();
  await h.api.refreshEffectiveProxy();
  assert.equal(h.api.getProxy(), null);
  assert.equal(h.probed.length, 0);
  await assert.rejects(h.api.detectHttpProxy(), /未运行/);
});
test('节点初始化串行、相同配置复用、编辑后先停止再启动、删除后停止', async () => {
  const h = proxyHarness();
  await Promise.all([h.api.syncBuiltinProxy(), h.api.syncBuiltinProxy()]);
  assert.equal(h.events.filter(v => v.startsWith('start:')).length, 1);
  h.state.nodes = [{ id: 1, name: 'test', link: 'node-B' }];
  await h.api.syncBuiltinProxy();
  assert.ok(h.events.indexOf('stop') < h.events.indexOf('start:node-B'));
  assert.equal(h.state.maxActive, 1);
  h.state.nodes = [];
  await h.api.syncBuiltinProxy();
  assert.equal(h.state.active, 0);
  assert.equal(h.api.getProxy(), null);
});
test('页面加载等待代理设置完成；代理设置失败会返回错误', async () => {
  const h = proxyHarness();
  await h.api.loadAccountPage({ webContents: { session: h.session }, loadURL() { h.events.push('load'); } }, 'https://example.com/');
  assert.ok(h.events.indexOf('connections-closed') < h.events.indexOf('load'));
  const fail = proxyHarness();
  fail.session.setProxy = async () => { throw new Error('proxy setup failed'); };
  await assert.rejects(fail.api.loadAccountPage({ webContents: { session: fail.session }, loadURL() { assert.fail('must not load'); } }, 'https://example.com'), /proxy setup failed/);
});
test('退出应用等待自己的代理清理完成，不重复执行清理', async () => {
  const callbacks = {}, events = [];
  const context = vm.createContext({
    app: { on(name, callback) { callbacks[name] = callback; }, quit() { events.push('quit'); } },
    proxySync: Promise.resolve(), streamProcesses: { '1': {} },
    async stopStream() { events.push('stream-stopped'); },
    xrayRuntime: { async stop() { await delay(8); events.push('proxy-stopped'); } }, console,
  });
  vm.runInContext(main.slice(main.indexOf('let proxyShutdownComplete'), main.indexOf("app.on('window-all-closed'")), context);
  callbacks['before-quit']({ preventDefault() { events.push('prevent'); } });
  callbacks['before-quit']({ preventDefault() {} });
  assert.ok(!events.includes('quit'));
  await delay(20);
  assert.deepEqual(events, ['prevent', 'stream-stopped', 'proxy-stopped', 'quit']);
});
test('只有完整、非零的视频输出进度才能确认开始输出，分片或零进度不能误报', () => {
  const started = [];
  const tracker = createOutputProgressTracker(value => started.push(value));
  tracker('frame=0\ntotal_size=0\nprogress=continue\n');
  tracker('frame=1\ntotal_size=N/A\nprogress=continue\n');
  assert.equal(started.length, 0);
  tracker('frame=4\ntotal_size=12');
  tracker('00\nprogress=cont');
  assert.equal(started.length, 0);
  tracker('inue\nframe=5\ntotal_size=2400\nprogress=end\n');
  assert.deepEqual(started, [{ frame: 4, bytes: 1200 }]);
});
function rendererHarness() {
  const callbacks = {}, account = { id: 1, streaming: false, connecting: true, streamKey: 'retained', status: 'connected' };
  let rendered = 0, frames = 0;
  const tkAPI = {
    onStreamLog(callback) { callbacks.log = callback; }, onStreamError(callback) { callbacks.error = callback; }, onStreamStopped(callback) { callbacks.stopped = callback; },
  };
  const context = vm.createContext({ window: { tkAPI }, state: { accounts: [account], currentRoute: 'mobile' }, addLog() {}, showToast() {}, saveState() {}, render() { rendered++; }, startFramePushing() { frames++; }, stopFramePushing() {}, console });
  vm.runInContext(functionSource(html, 'bindStreamEvents'), context);
  context.bindStreamEvents();
  return { callbacks, account, context, tkAPI, renders: () => rendered, frames: () => frames };
}
test('连接阶段不显示直播中；重试恢复画布输入；失败和主动停止都能刷新状态', () => {
  const h = rendererHarness();
  h.account.retrying = true;
  h.callbacks.log({ accountId: 1, log: '[推流] 进程已创建，正在连接并等待视频输出' });
  assert.equal(h.account.streaming, false);
  assert.equal(h.account.connecting, true);
  assert.equal(h.frames(), 1);
  h.callbacks.log({ accountId: 1, log: '[推流] 推流已启动（FFmpeg 已输出音视频数据）' });
  assert.equal(h.account.streaming, true);
  assert.equal(h.account.connecting, false);
  h.callbacks.stopped({ accountId: 1, code: 3753488571, error: 'handshake failed' });
  assert.equal(h.account.streaming, false);
  assert.equal(h.account.streamKey, 'retained');
  assert.ok(h.renders() > 0);
  h.callbacks.stopped({ accountId: 1, code: 0, user: true });
  h.callbacks.stopped({ accountId: 1, code: 0, autoDown: true });
  assert.equal(h.account.streamKey, '');
});
test('FFmpeg 在启动响应到达前快速退出时，响应不会把界面重新变成连接中', async () => {
  const h = rendererHarness();
  Object.assign(h.account, { rtmpUrl: 'rtmp://example.com/app', streamKey: 'key' });
  h.tkAPI.checkFFmpeg = async () => ({ available: true });
  h.tkAPI.startStream = async () => { h.callbacks.stopped({ accountId: 1, code: 1, error: 'startup failed' }); return { success: true, connecting: true }; };
  Object.assign(h.context, { isElectron: true, getScene: () => ({ layers: [] }) });
  vm.runInContext(functionSource(html, 'startRealStream'), h.context);
  assert.equal(await h.context.startRealStream(h.account), false);
  assert.equal(h.account.connecting, false);
});
async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port;
}
function closeServer(server) { return new Promise(resolve => server.close(resolve)); }
test('SOCKS5 拒绝 CONNECT 会保留具体返回码', async () => {
  const proxy = net.createServer(socket => {
    let stage = 0;
    socket.on('data', () => {
      if (stage++ === 0) socket.write(Buffer.from([5, 0]));
      else socket.end(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0]));
    });
  });
  const port = await listen(proxy);
  const egress = new MediaEgress({ proxy: { host: '127.0.0.1', port, type: 'socks5' } });
  try { await assert.rejects(egress._connectUpstream('example.com', 1935, 'rtmp:'), /code=2/); }
  finally { await egress.close(); await closeServer(proxy); }
});
test('分片的 SOCKS5 域名回复正确转发；活跃连接下关闭隧道不会挂起', async () => {
  const proxy = net.createServer(socket => {
    let stage = 0;
    socket.on('data', chunk => {
      if (stage === 0) { stage = 1; socket.write(Buffer.from([5, 0])); }
      else if (stage === 1) {
        stage = 2;
        socket.write(Buffer.from([5, 0, 0, 3]));
        setTimeout(() => socket.write(Buffer.concat([Buffer.from([5]), Buffer.from('proxy'), Buffer.from([0, 0]), Buffer.from('WELCOME')])), 8);
      } else socket.write(chunk);
    });
  });
  const port = await listen(proxy);
  const egress = new MediaEgress({ proxy: { host: '127.0.0.1', port, type: 'socks5' } });
  const out = await egress.start('rtmp://example.com/app/key');
  const client = net.connect(out.port, '127.0.0.1');
  try {
    const [welcome] = await once(client, 'data');
    assert.equal(welcome.toString(), 'WELCOME');
    client.write('FRAME');
    const [frame] = await once(client, 'data');
    assert.equal(frame.toString(), 'FRAME');
    await Promise.race([egress.close(), delay(1000).then(() => { throw new Error('close timed out'); })]);
  } finally { client.destroy(); await egress.close(); await closeServer(proxy); }
});

test('启动时以主进程节点为准，更新同 ID 的旧链接并清除已删除节点', async () => {
  const begin = html.indexOf('(function syncNodesFromMainOnBoot()');
  const end = html.indexOf('})();', begin) + 5;
  for (const nodes of [[{ id: 1, name: 'current', link: 'vless://current' }], []]) {
    const state = { nodes: [{ id: 1, name: 'stale', url: 'vless://stale' }, { id: 2, name: 'removed', url: 'old' }], nextNodeId: 3 };
    const context = vm.createContext({ state, isElectron: true, window: { tkAPI: { getNodes: async () => ({ nodes }) } }, saveState() {}, render() {}, console });
    vm.runInContext(html.slice(begin, end), context);
    await delay(1);
    assert.equal(state.nodes.length, nodes.length);
    if (nodes.length) assert.equal(state.nodes[0].url, 'vless://current');
  }
});
