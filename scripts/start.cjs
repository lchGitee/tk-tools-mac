const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
if (process.platform !== 'win32') {
  console.error('本工程目前只支持 Windows 开发运行。');
  process.exit(1);
}
const envFile = path.join(root, '.env');
if (fs.existsSync(envFile)) process.loadEnvFile(envFile);
const env = { ...process.env };
// 避免上层工具设置该变量后，将 Electron 错当普通 Node 进程启动。
delete env.ELECTRON_RUN_AS_NODE;
const child = spawn(require('electron'), [path.join(root, 'src'), ...process.argv.slice(2)], {
  cwd: root, env, stdio: 'inherit',
});
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code === null ? 1 : code; });
