const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

function runtimePath(name) {
  // 安装包的工具位于 Resources，开发工具与业务源码分开存放。
  const base = __dirname.includes('app.asar')
    ? path.join(process.resourcesPath, 'mac-runtime')
    : path.join(__dirname, '..', '.runtime-mac');
  return path.join(base, 'bin', name);
}
function machineCode(output) {
  const match = output.match(/"IOPlatformUUID"\s*=\s*"([0-9a-f-]+)"/i);
  if (!match || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(match[1])) {
    throw new Error('无法读取 Mac 硬件标识，不能生成机器码');
  }
  // 不使用系统版本或主机名，避免升级系统、改名导致授权失效。
  return crypto.createHash('sha256').update('TK|darwin|' + match[1].toUpperCase()).digest('hex').slice(0, 32).toUpperCase();
}
function getMachineCode() {
  return machineCode(execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8', timeout: 6000 }));
}
function audioDevice(output) {
  const audio = output.split('AVFoundation audio devices:')[1];
  const match = audio && audio.match(/\]\s*\[(\d+)\]\s+[^\r\n]+/);
  return match ? match[1] : null;
}
function obsPath() {
  const candidates = ['/Applications/OBS.app', path.join(require('node:os').homedir(), 'Applications', 'OBS.app')];
  return candidates.map(p => path.join(p, 'Contents', 'MacOS', 'OBS')).find(p => fs.existsSync(p)) || candidates[0] + '/Contents/MacOS/OBS';
}
function obsPassword() {
  const config = path.join(require('node:os').homedir(), 'Library', 'Application Support', 'obs-studio', 'plugin_config', 'obs-websocket', 'config.json');
  if (!fs.existsSync(config)) return '';
  return JSON.parse(fs.readFileSync(config, 'utf8')).server_password || '';
}
module.exports = { runtimePath, machineCode, getMachineCode, audioDevice, obsPath, obsPassword };
