// ============================================================
// media-egress.js —— 照搬抖歪（MediaEgress 本机隧道转发）
// FFmpeg 推流到本机 rtmp://127.0.0.1:port/，本机 TCP 服务透传转发到
// TikTok RTMP 服务器（正确 app/playpath，解决直推 not_allowed）
// v1.12.50：支持 HTTP CONNECT 代理隧道（走 v2rayN HTTP 端口 10809）
//           + rtmps TLS 包装（照搬抖歪 secureTunnel）
// ============================================================
const net = require('net');
const tls = require('tls');

class MediaEgress {
  constructor({ proxy, onLog = () => {} } = {}) {
    this.sockets = new Set();
    this.tasks = new Set();
    this.abortController = new AbortController();
    this.closed = false;
    this.server = null;
    this.error = '';
    this.output = null;
    this.proxy = proxy || null;   // { host, port } | null（HTTP CONNECT 代理）
    this.onLog = onLog;
  }

  attach(socket) {
    this.sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => this.sockets.delete(socket));
    return socket;
  }

  // 建立到 TikTok RTMP 服务器的连接（直连 / HTTP CONNECT / SOCKS5 代理隧道）
  _connectUpstream(hostname, port, protocol) {
    this.onLog('连接上游 ' + hostname + ':' + port + '，出口=' + (this.proxy ? this.proxy.type + '://' + this.proxy.host + ':' + this.proxy.port : '直连'));
    const ready = (sock) => {
      if (/^rtmps/i.test(protocol)) {
        const secure = tls.connect({ socket: sock, servername: hostname, rejectUnauthorized: false });
        secure.once('error', error => sock.destroy(error));
        secure.once('secureConnect', () => sock.emit('_egress_ready', secure));
      } else sock.emit('_egress_ready', sock);
    };
    const establish = () => {
      if (this.proxy && this.proxy.host && this.proxy.port) {
        if ((this.proxy.type || 'http') === 'socks5') {
          // SOCKS5 CONNECT（v2rayN 默认 socks5://127.0.0.1:10808；内置 xray 10888）
          const sock = net.connect(Number(this.proxy.port), this.proxy.host);
          sock.on('connect', () => {
            let stage = 0, buf = Buffer.alloc(0);
            const onData = (c) => {
              buf = Buffer.concat([buf, c]);
              if (stage === 0 && buf.length >= 2) {
                // 握手响应 [05, 00]=无认证
                if (buf[0] !== 0x05 || buf[1] !== 0x00) { sock.destroy(new Error('SOCKS5 认证协商失败，method=' + buf[1])); return; }
                stage = 1; buf = Buffer.alloc(0);
                const hn = Buffer.from(hostname, 'utf8');
                if (hn.length > 255) { sock.destroy(new Error('上游域名过长')); return; }
                const req = Buffer.concat([
                  Buffer.from([0x05, 0x01, 0x00, 0x03, hn.length]), hn,
                  Buffer.from([(port >> 8) & 0xFF, port & 0xFF]),
                ]);
                sock.write(req);
              } else if (stage === 1 && buf.length >= 4) {
                const rep = buf[1];
                if (rep !== 0x00) { sock.destroy(new Error('SOCKS5 CONNECT 被拒绝，code=' + rep)); return; }
                const replySize = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : buf[3] === 3 && buf.length >= 5 ? 7 + buf[4] : 0;
                if (!replySize) { if (buf[3] === 3) return; sock.destroy(new Error('SOCKS5 返回地址类型无效')); return; }
                if (buf.length < replySize) return;
                sock.removeListener('data', onData);
                sock.pause();
                if (buf.length > replySize) sock.unshift(buf.subarray(replySize));
                ready(sock);
              }
            };
            sock.on('data', onData);
            // v1.13.14 修复：必须先发送 SOCKS5 握手请求（[05,01,00]=无认证），否则代理不响应 → 上游 12s 超时（"Cannot read RTMP handshake response"）
            sock.write(Buffer.from([0x05, 0x01, 0x00]));
          });
          return sock;
        }
        // HTTP CONNECT 隧道（照搬抖歪 tunnel.cjs connectTunnel）
        const sock = net.connect(Number(this.proxy.port), this.proxy.host);
        sock.on('connect', () => {
          const target = (hostname.indexOf(':') >= 0 && !/^\[/.test(hostname) ? '[' + hostname + ']' : hostname) + ':' + port;
          let req = 'CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\nProxy-Connection: Keep-Alive\r\n';
          if (this.proxy.username || this.proxy.password) {
            req += 'Proxy-Authorization: Basic ' + Buffer.from((this.proxy.username || '') + ':' + (this.proxy.password || '')).toString('base64') + '\r\n';
          }
          req += '\r\n';
          sock.write(req);
          let buf = '';
          const onData = (c) => {
            buf += c.toString('latin1');
            const idx = buf.indexOf('\r\n\r\n');
            if (idx >= 0) {
              sock.removeListener('data', onData);
              const statusLine = buf.slice(0, buf.indexOf('\r\n'));
              if (/^HTTP\/1\.[01]\s+200/.test(statusLine)) {
                // 隧道建立；若 rtmps 需要 TLS 包装
                sock.pause();
                const rest = Buffer.from(buf.slice(idx + 4), 'latin1');
                if (rest.length) sock.unshift(rest);
                ready(sock);
              } else {
                sock.destroy(new Error('HTTP CONNECT 被拒绝: ' + statusLine));
              }
            }
          };
          sock.on('data', onData);
        });
        return sock;
      }
      // 直连
      let s = net.connect(port, hostname);
      if (/^rtmps/i.test(protocol)) {
        s = tls.connect({ socket: s, servername: hostname, rejectUnauthorized: false });
        s.once('secureConnect', () => s.emit('_egress_ready', s));
      } else {
        s.once('connect', () => s.emit('_egress_ready', s));
      }
      return s;
    };
    return new Promise((resolve, reject) => {
      const sock = establish();
      let done = false;
      let timer;
      const fail = (error) => { if (!done) { done = true; clearTimeout(timer); reject(error); } };
      sock.once('_egress_ready', (up) => { if (!done) { done = true; clearTimeout(timer); this.onLog('上游连接已建立'); resolve(up); } });
      sock.once('error', fail);
      sock.once('close', () => fail(new Error('上游连接提前关闭')));
      // 12s 超时（照搬抖歪 tunnel 12000ms）
      timer = setTimeout(() => { if (!done) { fail(new Error('上游连接超时')); sock.destroy(); } }, 12000);
    });
  }

  // 启动本机转发服务：targetUrl = TikTok RTMP 完整 URL
  // 返回 { url: 本机输入地址, args: [app, playpath, server] }
  async start(targetUrl, { server, key } = {}) {
    if (this.closed || this.server) throw new Error('媒体转发已启动或已关闭');
    const u = new URL(targetUrl);
    const protocol = u.protocol; // rtmp: / rtmps:
    if (!/^rtmp|^rtmps/.test(protocol)) throw new Error('媒体目标协议无效: ' + protocol);
    if (u.username || u.password || u.hash || /[\s\\]/.test(targetUrl)) throw new Error('媒体目标无效');
    const hostname = u.hostname.replace(/^\[|\]$/g, '');
    const port = Number(u.port) || (protocol === 'rtmps:' ? 443 : 1935);
    const pathname = u.pathname || '';
    const lastSlash = pathname.lastIndexOf('/');
    if (lastSlash <= 0 || lastSlash >= pathname.length - 1) throw new Error('媒体目标路径无效: ' + pathname);

    // app = 路径第一段（如 stage）；playpath = 最后一段 + query
    let app = pathname.slice(1, lastSlash);
    let playpath = pathname.slice(lastSlash + 1) + u.search;
    if (server) {
      const su = new URL(server);
      // 抖歪：server 必须与 targetUrl 同 host/protocol/port（防止把流推错服务器）
      if (su.host !== u.host || su.protocol !== u.protocol || su.port !== u.port) throw new Error('媒体目标不一致');
      app = su.pathname.slice(1).replace(/\/+$/, '') + su.search;
      if (key != null) playpath = key;
    }
    if (!app || !playpath) throw new Error('媒体目标 app/playpath 无效');

    const target = server || protocol + '//' + u.host + '/' + app;

    // 本机 TCP 服务：收到连接 → 透传到 TikTok RTMP 服务器（代理隧道）
    this.server = net.createServer((sock) => {
      this.attach(sock);
      sock.pause();
      if (this.closed || this.abortController.signal.aborted) { sock.destroy(); return; }
      // 抖歪：最多 4 个并发上游连接（防止 FFmpeg 重连风暴）
      if (this.sockets.size > 4) { sock.destroy(); return; }
      this._connectUpstream(hostname, port, protocol).then((upstream) => {
        if (this.closed || this.abortController.signal.aborted) { sock.destroy(); try { upstream.destroy(); } catch (e) {} return; }
        this.attach(upstream);
        let sent = 0, received = 0;
        sock.on('data', chunk => { sent += chunk.length; });
        upstream.on('data', chunk => { received += chunk.length; });
        upstream.once('error', error => { this.error = error.message; this.onLog('上游错误: ' + error.message); });
        upstream.once('close', () => {
          const detail = '上游连接关闭，发送=' + sent + ' 字节，接收=' + received + ' 字节';
          if (!this.closed && !this.error) this.error = detail;
          this.onLog(detail);
        });
        sock.on('close', () => upstream.destroy());
        sock.on('error', () => upstream.destroy());
        upstream.on('close', () => sock.destroy());
        upstream.on('error', () => sock.destroy());
        sock.pipe(upstream);
        upstream.pipe(sock);
        upstream.resume();
        sock.resume();
      }).catch((e) => {
        this.error = e.message;
        this.onLog('上游连接失败: ' + e.message);
        sock.destroy();
      });
    });
    this.server.on('error', (e) => { this.error = e.message; });
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', resolve);
    });
    const localPort = this.server.address().port;
    this.output = {
      // 抖歪原样：本机路径 /relay/stream；args 带 -rtmp_app/-rtmp_playpath/-rtmp_tcurl（FFmpeg 用 -rtmp_tcurl 把 RTMP 握手 tcUrl 设为真实服务器，否则 tcUrl=127.0.0.1 被 TikTok 拒流）
      url: 'rtmp://127.0.0.1:' + localPort + '/relay/stream',
      args: ['-rtmp_app', app, '-rtmp_playpath', playpath, '-rtmp_tcurl', target],
      port: localPort,
    };
    return this.output;
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    this.abortController.abort();
    // 先断开活跃连接，server.close 才能完成退出。
    for (const s of [...this.sockets]) { try { s.destroy(); } catch (e) {} }
    this.sockets.clear();
    if (this.server) {
      await new Promise((resolve) => { try { this.server.close(() => resolve()); } catch (e) { resolve(); } });
      this.server = null;
    }
  }
}

module.exports = { MediaEgress };
