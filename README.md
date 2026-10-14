# tk-tools

TikTok 直播工作台 v1（1.0.2）的 Windows 开发工程。界面、Electron 主进程、IPC 和客户端模块来自提供的安装包；保留直播业务，授权改为绑定指定机器的离线数字签名。

## Windows 上开始开发

准备 Windows 10/11 64 位、Git、Node.js 22.19+（建议使用 Node 24 LTS）和 GitHub CLI（gh）。本仓库是私有仓库，请登录有访问权限的 GitHub 账号。

```powershell
gh auth login
gh auth setup-git
git clone <你的私有仓库地址>
cd tk-tools
npm ci
npm run setup:windows
Copy-Item .env.example .env
npm run dev
```

`npm ci` 安装锁定的 Node 依赖和 Electron 28.3.3。`setup:windows` 从本仓库的 `runtime-1.15.60` Release 下载原包内的 FFmpeg、OBS、Xray、curl，验证压缩包和逐文件 SHA-256，再解压到 `src`。首次准备需要联网，后续改源码后直接 `npm run dev`。

工具已准备时，普通启动可用 `npm start`；`npm run dev` 会同时打开开发者工具。修改主进程或 preload 后完全退出再启动。

如果签名请求需要服务凭据，编辑本机 `.env` 中的 `TK_SIGNER_API_KEY`，或者使用软件内的账号签名配置。仓库不包含原包内的签名服务 Key。环境变量仅在程序重新启动时读取。

## 工程结构

```text
src/
  main.js                主进程、账号会话、平台请求、推流和监控
  index.html             页面、样式、前端状态和画面编辑
  preload.js             tkAPI IPC 桥接
  monitor-preload.js     直播页面数据采集
  signer-client.js       外部签名服务客户端
  obs-engine.js          OBS WebSocket 控制
  media-egress.js        推流网络出口
  flv-sei.js             FLV/SEI 模块
  stream-capture.js      推流信息解析
  xray-runtime.js        节点解析与 Xray 进程管理
scripts/
  start.cjs              Windows 开发启动
  setup-windows.cjs      私有 Release 下载与完整性检查
  windows-runtime.json   工具版本和逐文件摘要
  check.cjs              静态语法检查
  restore-asar.py        可选的原包恢复工具，日常开发不需要
```

`src/package.json` 保留应用名称和入口，应用版本统一为首版 `1.0.0`；根 `package.json` 管理开发命令和依赖，依赖通过 `package-lock.json` 固定。

## 数据与授权

开发运行使用仓库内 `.local/` 保存 Electron userData，包括账号、节点、会话和日志，激活文件也位于 `.local/activation.lic`。这些文件以及 `.env`、原安装包、提取目录、工具二进制和 node_modules 均不进入 Git。

客户端只使用公钥验证离线授权，旧卡密白名单和旧激活文件不再接受。每次启动均验证签名与当前机器码。

## 检查

```powershell
npm run check
```

该命令只检查脚本语法，不启动平台登录或推流。本工程已经完成文件恢复、依赖锁定和静态检查；尚未完成 Windows GUI、登录、监控及真实推流验收。没有实现 TikTok 服务端或第三方签名服务。

Electron 版本按原 EXE 的运行时标识 28.3.3 固定；先建立行为基线，未在本次恢复中升级运行时。当前依赖存在 npm audit 报告的已知漏洞，更新依赖需要另外验证兼容性。

## 打包 Windows 安装程序

先完成 `npm ci` 和 `npm run setup:windows`，然后执行：

```powershell
npm run build:win
```

安装程序输出到 `dist/tk-tools-Setup-1.0.2-x64.exe`，免安装运行目录为 `dist/win-unpacked`。原生工具放到 `app.asar.unpacked/src`，业务代码打包进 ASAR。安装包没有配置代码签名证书。应用图标位于 `src/assets/app-icon.png`，Windows 多尺寸图标位于 `build/app.ico`，打包时自动写入主程序、安装程序和卸载程序。

打包脚本只生成本地产物，不自动发布。`.env`、开发账号数据和卡密明文不进入安装包。签名服务仍通过账号配置或进程环境变量提供凭据。

授权码包含指定机器码和数字签名，不再使用 `LICENSE_HASHES`。旧的 `.local/new-license.txt` 只属于旧版，不能用于 1.0.2。

## 原始材料

本地保留原安装包和恢复目录，但不提交到仓库。原安装包 SHA-256：

```text
1616b7e49af9b8d7986190d8ccc093b539562ae3b20c6b275bf8d088e5d557b1
```

运行组件来源与许可证说明见 `THIRD_PARTY_NOTICES.md`。

## 离线授权签发（仅供你自己使用）

这版已初始化一对 Ed25519 密钥。公钥位于 `src/license-public-key.pem`，随所有客户端分发；私钥位于 `.local/license-issuer/private-key.pem`，被 Git 忽略，也不会进入安装包。请单独备份私钥，换开发电脑时自行安全迁移，不能仅依赖 Git 克隆恢复。不能把私钥或签发工具连同私钥发给用户。

新工程首次初始化才执行 `npm run license:init`。已有密钥时会拒绝覆盖；不要为每个用户重新生成密钥。

每位用户都安装同一个 1.0.2 EXE，将激活页显示的 32 位机器码发给你。你运行：

```powershell
npm run license:issue -- --machine 用户的32位机器码
```

也可直接运行 `npm run license:issue`，按提示粘贴机器码。签发工具会显示授权码，并保存到 `.local/issued-licenses/机器码.txt`。把该文件中的整段 `TK1.…` 授权码发给用户，让用户粘贴到激活页。只需要机器码，不需要用户编号；当前均为永久授权，不管理到期或吊销。

同一授权码只能在指定机器码上通过校验。换机或机器码改变需重新签发，完全离线不能让旧机器的授权立即失效。普通卡密、旧激活文件、签名被修改、其他设备机器码、其他私钥签发的授权均被拒绝。

```powershell
npm run test:license
```

授权测试覆盖指定机器激活、其他机器拒绝、重启、文件跨机器复制、篡改、错误密钥、旧格式和写入失败。Windows 真实硬件机器码稳定性及 GUI 激活仍需 Windows 验证。
