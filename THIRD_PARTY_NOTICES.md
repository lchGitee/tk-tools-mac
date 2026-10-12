# 来源与第三方组件

客户端业务源文件来自用户提供的 TikTok直播工作台 Setup 1.15.60.exe，包内 package.json 将客户端标记为 MIT。该元数据不替代第三方许可证，不代表 TikTok 官方发行或授权。

本次整理保留客户端授权逻辑；清除随包的外部签名服务凭据，改用用户自行提供的配置。原安装包、账号数据和服务凭据不进入 Git。

开发依赖 Electron、fluent-ffmpeg、obs-websocket-js、socks-proxy-agent、ws 的许可文本由 npm 包提供，请保留这些文本。原 Electron 版本识别自 EXE 中 Electron/28.3.3 字符串。

私有 Release 中的 Windows 工具包来自原安装包，包含 FFmpeg、OBS Studio、Xray 和 curl；随包存在的资源和许可文件保持原样。这些组件遵循各自许可，仓库未重新授予其版权或商业权利。

- Electron：https://github.com/electron/electron
- FFmpeg：https://ffmpeg.org/legal.html
- OBS Studio：https://github.com/obsproject/obs-studio
- Xray：https://github.com/XTLS/Xray-core
- curl：https://curl.se/docs/copyright.html

本仓库用于用户自己的私有开发。后续公开分发时，应另外核实完整许可证、源码提供义务及软件名称的使用范围；本次不生成公开发布包。
