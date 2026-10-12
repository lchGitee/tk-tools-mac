# tk-tools

TikTok 直播工作台 1.15.60 的 Windows 开发工程。界面、Electron 主进程、IPC 和客户端模块来自提供的安装包；保留原业务和卡密授权逻辑。

## Windows 上开始开发

准备 Windows 10/11 64 位、Git、Node.js 22.19+（建议使用 Node 24 LTS）和 GitHub CLI（gh）。本仓库是私有仓库，请登录有访问权限的 GitHub 账号。

```powershell
gh auth login
gh auth setup-git
git clone https://github.com/lchGitee/tk-tools.git
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

`src/package.json` 保留原应用名称、版本和入口；根 `package.json` 管理开发命令和依赖，依赖通过 `package-lock.json` 固定。

## 数据与授权

开发运行使用仓库内 `.local/` 保存 Electron userData，包括账号、节点、会话和日志，激活文件也位于 `.local/activation.lic`。这些文件以及 `.env`、原安装包、提取目录、工具二进制和 node_modules 均不进入 Git。

原卡密白名单和本地机器绑定逻辑保持原样。开发版仍需有效卡密；没有新增绕过授权的行为。

## 检查

```powershell
npm run check
```

该命令只检查脚本语法，不启动平台登录或推流。本工程已经完成文件恢复、依赖锁定和静态检查；尚未完成 Windows GUI、登录、监控及真实推流验收。没有实现 TikTok 服务端或第三方签名服务。

Electron 版本按原 EXE 的运行时标识 28.3.3 固定；先建立行为基线，未在本次恢复中升级运行时。当前依赖存在 npm audit 报告的已知漏洞，更新依赖需要另外验证兼容性。

当前提供开发运行工程；安装器和签名发布配置未恢复，不包含重新打包安装程序的命令。

## 原始材料

本地保留原安装包和恢复目录，但不提交到仓库。原安装包 SHA-256：

```text
1616b7e49af9b8d7986190d8ccc093b539562ae3b20c6b275bf8d088e5d557b1
```

运行组件来源与许可证说明见 `THIRD_PARTY_NOTICES.md`。
