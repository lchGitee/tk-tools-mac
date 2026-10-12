const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
let failed = false;
const scripts = ['src', 'scripts'].flatMap(dir => fs.readdirSync(path.join(root, dir))
  .filter(name => /\.(js|cjs)$/.test(name)).map(name => path.join(root, dir, name)));
for (const file of scripts) {
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (check.error || check.status !== 0) {
    failed = true;
    console.error(check.error || check.stderr);
  }
}
// 页面脚本通过标准 JS 编译检查语法，不执行页面或发起平台请求。
const vm = require('node:vm');
for (const file of ['index.html', 'help.html']) {
  const html = fs.readFileSync(path.join(root, 'src', file), 'utf8');
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    try { new vm.Script(match[1], { filename: file }); }
    catch (error) { failed = true; console.error(error.message); }
  }
}
if (failed) process.exitCode = 1;
else console.log('业务脚本、开发脚本和 HTML 内联脚本语法检查通过。');
