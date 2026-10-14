# tk-tools-mac

TikTok 直播工作台 1.0.2 的 Apple Silicon macOS 工程，使用 Electron 28.3.3。仅支持 M 系列 Mac，不提供 Intel 包。基于 Windows 版源码移植，共用原有业务与离线数字签名授权。

## 开发

准备 macOS 15+ 的 M 系列 Mac、Node.js 22.19+、Homebrew 和 Xcode Command Line Tools。

```sh
npm ci
brew install ffmpeg xray
npm run setup:mac
cp .env.example .env
npm run dev
```

`setup:mac` 将本机 Homebrew 的 arm64 FFmpeg、Xray 和递归动态库复制到 `.runtime-mac/`，重写动态库引用并生成 SHA-256 清单。打包后用户无需安装 Homebrew。更新工具后需重新执行该命令；工具版本和 Homebrew 配方元数据保存在运行工具包中。

默认使用 FFmpeg 推流，暂沿用 libx264 CPU 编码。麦克风使用 AVFoundation，首次使用时需允许系统麦克风权限；视频已有音轨时沿用视频音轨。curl 使用 macOS 的 `/usr/bin/curl`。

可选 OBS 引擎需自行安装 Apple Silicon OBS 到 `/Applications/OBS.app` 或 `~/Applications/OBS.app`，在 OBS 的工具 → WebSocket 服务器设置中启用服务器，端口使用 4455。工作台读取 OBS 用户配置中的密码进行认证，不覆盖配置，结束推流后不关闭 OBS。OBS 需要的视频素材由工作台设置。

签名服务凭据通过 `.env` 中的 `TK_SIGNER_API_KEY` 或应用内账号配置提供，`.env` 不进入安装包。

## 打包

```sh
npm run check
npm run test:license
npm run test:network
npm run test:mac
npm run build:mac
```

输出为 `dist/tk-tools-mac-1.0.2-arm64.dmg` 和 ZIP。工具位于 `.app/Contents/Resources/mac-runtime`，代码位于 ASAR。打包脚本校验工具摘要，仅生成本地文件，不自动发布。

无 Developer ID 证书时可生成本地测试包。正式分发需要配置 electron-builder 的 Developer ID 签名和 Apple 公证环境变量；签名、公证凭据不能提交 Git。

## 数据与离线授权

开发数据位于 `.local/`；安装版数据、日志、账号会话和 `activation.lic` 位于 Electron userData（`~/Library/Application Support/tk-tools-mac/`）。激活文件不写入 `.app`，避免破坏签名。机器码基于 Mac 硬件 UUID，不包含系统版本和主机名。

客户端保留原公钥，可继续使用对应的签发私钥签发 Mac 机器码授权。私钥位于本机 `.local/license-issuer/private-key.pem`，不会随 Git 克隆恢复，需安全迁移；已有公钥时不要重新初始化。

```sh
npm run license:issue -- --machine 用户的32位机器码
```

每台 Mac 使用自己的授权码，Windows 授权码不能直接迁移使用。

## 验证边界

自动测试覆盖机器码、音频设备解析、离线授权、代理和推流状态。登录、监控、麦克风权限、OBS 与真实长时间推流仍需真实账号和素材验收。生成安装包不代表这些业务已通过验收。

历史 Windows 恢复脚本保留供追溯，Mac 开发使用上面的命令。第三方组件说明见 `THIRD_PARTY_NOTICES.md`。
