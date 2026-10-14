const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const manifest = require('./windows-runtime.json');
if (process.platform !== 'win32') {
  console.error('Windows 工具准备脚本需在 Windows 上运行。');
  process.exit(1);
}
const cache = path.join(root, '.runtime-cache');
fs.mkdirSync(cache, { recursive: true });
function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    throw new Error(result.error ? result.error.message : `${command} 退出码 ${result.status}`);
  }
}
async function sha256(file) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
async function main() {
  // 私有 Release 使用 gh 的本机登录，不把 GitHub Token 写入源码或命令参数。
  run('gh', ['release', 'download', manifest.tag,
    '--pattern', manifest.asset, '--dir', cache, '--clobber']);
  const zip = path.join(cache, manifest.asset);
  if (await sha256(zip) !== manifest.sha256) throw new Error('工具压缩包 SHA-256 不匹配，停止解压。');
  run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    path.join(__dirname, 'expand-windows-tools.ps1'), '-ArchivePath', zip,
    '-DestinationPath', path.join(root, 'src')]);
  for (const item of manifest.files) {
    const file = path.join(root, 'src', item.path);
    if (fs.statSync(file).size !== item.size || await sha256(file) !== item.sha256) {
      throw new Error(`工具文件校验失败: ${item.path}`);
    }
  }
  console.log(`Windows 工具准备完成，${manifest.files.length} 个文件校验通过。运行 npm run dev 开始开发。`);
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
