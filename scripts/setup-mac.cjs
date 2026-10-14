const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dest = path.join(root, '.runtime-mac');
function run(file, args) { return execFileSync(file, args, { encoding: 'utf8' }).trim(); }
function setup() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('仅支持 Apple Silicon macOS');
  const brew = '/opt/homebrew/bin/brew';
  const sources = ['ffmpeg', 'xray'].map(name => path.join(run(brew, ['--prefix', name]), name === 'xray' ? 'libexec' : 'bin', name));
  for (const file of sources) fs.accessSync(file, fs.constants.X_OK);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(path.join(dest, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(dest, 'lib'), { recursive: true });
  const copied = new Map();
  const manifest = [];
  // 递归收集 Homebrew 动态库并改为包内相对路径，安装用户无需 Homebrew。
  function bundle(source, target) {
    const real = fs.realpathSync(source);
    if (copied.has(real)) return copied.get(real);
    if (!run('/usr/bin/lipo', ['-archs', real]).split(/\s+/).includes('arm64')) throw new Error('非 arm64 工具: ' + source);
    copied.set(real, target);
    fs.copyFileSync(real, target);
    fs.chmodSync(target, 0o755);
    const lines = run('/usr/bin/otool', ['-L', real]).split('\n').slice(1);
    const id = run('/usr/bin/otool', ['-D', real]).split('\n')[1];
    for (const line of lines) {
      const dep = line.trim().split(' (')[0];
      if (!dep || dep === id || dep.startsWith('/usr/lib/') || dep.startsWith('/System/Library/')) continue;
      if (!path.isAbsolute(dep)) throw new Error('不支持的动态库路径: ' + dep);
      const depReal = fs.realpathSync(dep);
      const hash = crypto.createHash('sha256').update(depReal).digest('hex').slice(0, 12);
      const depTarget = bundle(dep, path.join(dest, 'lib', hash + '-' + path.basename(depReal)));
      const relative = '@loader_path/' + path.relative(path.dirname(target), depTarget);
      run('/usr/bin/install_name_tool', ['-change', dep, relative, target]);
    }
    if (id) run('/usr/bin/install_name_tool', ['-id', '@loader_path/' + path.basename(target), target]);
    // 修改 Mach-O 后重新进行本地签名，正式分发由 electron-builder 使用证书签名。
    run('/usr/bin/codesign', ['--force', '--sign', '-', target]);
    manifest.push({ file: path.relative(dest, target), sha256: crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex') });
    return target;
  }
  sources.forEach(source => bundle(source, path.join(dest, 'bin', path.basename(source))));
  const notices = path.join(dest, 'licenses');
  fs.mkdirSync(notices, { recursive: true });
  const formulae = new Set();
  for (const source of copied.keys()) {
    const match = source.match(/\/Cellar\/([^/]+)\/([^/]+)\//);
    if (!match) continue;
    const prefix = source.slice(0, source.indexOf('/Cellar/')) + '/Cellar/' + match[1] + '/' + match[2];
    formulae.add(match[1]);
    const target = path.join(notices, match[1]);
    fs.mkdirSync(target, { recursive: true });
    for (const name of fs.readdirSync(prefix)) {
      if (/^(COPYING|LICENSE|NOTICE|AUTHORS)/i.test(name) && fs.statSync(path.join(prefix, name)).isFile()) fs.copyFileSync(path.join(prefix, name), path.join(target, name));
    }
  }
  fs.writeFileSync(path.join(notices, 'homebrew-formulae.json'), run(brew, ['info', '--json=v2', ...formulae]) + '\n');
  fs.writeFileSync(path.join(dest, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  run(path.join(dest, 'bin', 'ffmpeg'), ['-version']);
  run(path.join(dest, 'bin', 'xray'), ['version']);
  console.log('arm64 FFmpeg、Xray 及动态库准备完成。');
}
try { setup(); } catch (error) { console.error(error.message); process.exitCode = 1; }
