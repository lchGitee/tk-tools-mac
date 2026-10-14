const test = require('node:test');
const assert = require('node:assert/strict');
const { machineCode, audioDevice, runtimePath, getMachineCode } = require('../src/mac-platform');
test('Mac 机器码只取硬件 UUID，系统升级和主机改名不影响授权', () => {
  const uuid = '01234567-89ab-cdef-0123-456789abcdef';
  const a = machineCode('"IOPlatformUUID" = "' + uuid + '"\nHost=old;OS=14');
  const b = machineCode('"IOPlatformUUID" = "' + uuid.toUpperCase() + '"\nHost=new;OS=15');
  assert.equal(a, b);
  assert.match(a, /^[A-F0-9]{32}$/);
  assert.notEqual(a, machineCode('"IOPlatformUUID" = "11234567-89ab-cdef-0123-456789abcdef"'));
  assert.throws(() => machineCode('UUID missing'));
  assert.throws(() => machineCode('"IOPlatformUUID" = "0000"'));
});
test('音频索引不与 AVFoundation 视频索引混淆，索引 0 可用', () => {
  assert.equal(audioDevice('[AVFoundation] AVFoundation video devices:\n[AVFoundation] [0] Camera\n[AVFoundation] AVFoundation audio devices:\n[AVFoundation] [0] Microphone'), '0');
  assert.equal(audioDevice('AVFoundation video devices:\n[0] Camera'), null);
  assert.equal(audioDevice('AVFoundation audio devices:\n[AVFoundation] [2] USB Mic'), '2');
});
test('开发运行工具与 Windows 二进制分离', () => {
  assert.match(runtimePath('ffmpeg'), /\.runtime-mac\/bin\/ffmpeg$/);
});
test('当前 Mac 重复读取硬件标识保持稳定', { skip: process.platform !== 'darwin' }, () => {
  assert.equal(getMachineCode(), getMachineCode());
});
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const net = require('node:net');
const { XrayProcess } = require('../src/xray-runtime');
test('准备后的 FFmpeg 可以实际编码，Xray 可以启动本地 SOCKS5', { skip: !fs.existsSync(runtimePath('xray')) || !fs.existsSync(runtimePath('ffmpeg')) }, async () => {
  execFileSync(runtimePath('ffmpeg'), ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'testsrc=size=160x120:rate=15', '-t', '1', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-f', 'null', '-'], { timeout: 15000 });
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const proc = new XrayProcess({ executable: runtimePath('xray'), logDir: require('node:os').tmpdir() });
  try {
    await proc.startWithNode('socks5://127.0.0.1:9', port);
    await new Promise((resolve, reject) => {
      const socket = net.connect(port, '127.0.0.1');
      socket.on('connect', () => socket.write(Buffer.from([5, 1, 0])));
      socket.on('data', data => { try { assert.deepEqual([...data], [5, 0]); resolve(); } catch (e) { reject(e); } finally { socket.destroy(); } });
      socket.on('error', reject);
      socket.setTimeout(3000, () => { socket.destroy(); reject(new Error('SOCKS5 握手超时')); });
    });
  } finally { await proc.stop(); }
});
