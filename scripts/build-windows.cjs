const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
for (const item of require('./windows-runtime.json').files) {
  const file = path.join(root, 'src', item.path);
  if (!fs.existsSync(file) || fs.statSync(file).size !== item.size) {
    console.error(`Windows 工具缺失或大小异常: ${item.path}。请先运行 npm run setup:windows。`);
    process.exit(1);
  }
}
// 只构建本地安装包，避免打包工具自动发布到 GitHub。
const result = spawnSync(process.execPath, [require.resolve('electron-builder/cli.js'),
  '--config', 'electron-builder.json', '--win', '--x64', '--publish', 'never'], {
  cwd: root, stdio: 'inherit',
  env: { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: 'false' },
});
if (result.error) console.error(result.error.message);
process.exitCode = result.error || result.status === null ? 1 : result.status;
