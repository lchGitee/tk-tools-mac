const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
function main() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('仅支持 Apple Silicon macOS');
  const runtime = path.join(root, '.runtime-mac');
  const manifest = JSON.parse(fs.readFileSync(path.join(runtime, 'manifest.json'), 'utf8'));
  for (const item of manifest) {
    const file = path.join(runtime, item.file);
    if (crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== item.sha256) throw new Error('运行工具摘要不匹配: ' + item.file);
  }
  const result = spawnSync(process.execPath, [require.resolve('electron-builder/cli.js'), '--config', 'electron-builder.json', '--mac', '--arm64', '--publish', 'never'], { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  process.exitCode = result.status === null ? 1 : result.status;
}
try { main(); } catch (error) { console.error(error.message + '\n请先运行 npm run setup:mac。'); process.exitCode = 1; }
