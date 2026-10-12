// TikTok直播工作台 - 预加载脚本（安全桥接）
// v1.15.0 防御性解构：沙箱 preload 下个别模块（如 webUtils）可能不可用，
// 解构失败会导致整个 preload 崩溃 → tkAPI 全部丢失（界面正常但所有按钮失效、版本号不加载）。
const { contextBridge, ipcRenderer } = require('electron');
// v1.15.1 防御性解构：沙箱 preload 下个别模块（如 webUtils）可能不可用，
// 解构失败会导致整个 preload 崩溃 → tkAPI 全部丢失（界面正常但所有按钮失效、版本号不加载）。
let webUtils = null;
try { webUtils = require('electron').webUtils; } catch (e) { webUtils = null; }

contextBridge.exposeInMainWorld('tkAPI', {
  // 视频/图片文件真实路径（用于视频原声推流）
  getPathForFile: (file) => {
    try { return webUtils ? webUtils.getPathForFile(file) : ''; } catch (e) { return ''; }
  },
  // FFmpeg检测
  checkFFmpeg: () => ipcRenderer.invoke('ffmpeg:check'),

  // 默认素材查找（v1.14.10：不再写死桌面路径）
  listDefaultVideos: () => ipcRenderer.invoke('assets:listDefaults'),

  // 推流控制
  startStream: (data) => ipcRenderer.invoke('stream:start', data),
  pushFrame: (data) => ipcRenderer.invoke('stream:pushFrame', data),
  stopStream: (data) => ipcRenderer.invoke('stream:stop', data),

  // 推流事件监听
  onStreamLog: (callback) => ipcRenderer.on('stream:log', (e, data) => callback(data)),
  onStreamError: (callback) => ipcRenderer.on('stream:error', (e, data) => callback(data)),
  onStreamStopped: (callback) => ipcRenderer.on('stream:stopped', (e, data) => callback(data)),

  // 文件选择
  openFile: (filters) => ipcRenderer.invoke('dialog:openFile', { filters }),

  // ============ Cookie 登录（每房间独立） ============
  // 打开该账号的独立登录窗口（每次都是新窗口）
  openTikTokLogin: (data) => ipcRenderer.invoke('tiktok:openLogin', data),
  // 打开该账号的直播中心后台（每次都是新窗口；autoGoLive=true 时自动点击 Go LIVE）
  openProducerWindow: (data) => ipcRenderer.invoke('tiktok:openProducerWindow', data),
  // v1.6.1 API 通道：隐藏窗口直接创建直播间获取推流码（不依赖页面点击，成功自动关窗）
  getStreamKeyByApi: (data) => ipcRenderer.invoke('tiktok:getStreamKeyByApi', data),
  // v1.12.43 手机下播提醒：用户手动在手机端下播后确认（停止提醒）
  phoneDownConfirm: (data) => ipcRenderer.invoke('tiktok:phoneDownConfirm', data),
  // 打开该账号的直播间页面（每次都是新窗口，真实监控入口）
  openLiveWindow: (data) => ipcRenderer.invoke('tiktok:openLiveWindow', data),
  // 手动导入 Cookie（字符串或JSON）
  saveManualCookies: (data) => ipcRenderer.invoke('tiktok:saveManualCookies', data),
  // 导出已保存 Cookie
  exportCookies: (data) => ipcRenderer.invoke('tiktok:exportCookies', data),
  // 查询某账号登录态
  getAccountAuth: (data) => ipcRenderer.invoke('tiktok:getAccountAuth', data),
  // 清除某账号登录态
  clearLogin: (data) => ipcRenderer.invoke('tiktok:clearLogin', data),
  // 关闭某账号的所有窗口（删除账号时）
  closeAccountWindows: (data) => ipcRenderer.invoke('tiktok:closeAccountWindows', data),

  // 登录态变化事件（自动抓取 Cookie 成功后触发）
  onLoginStateChanged: (callback) => ipcRenderer.on('tiktok:loginStateChanged', (e, data) => callback(data)),
  // 推流码自动回填事件
  onStreamKeyFound: (callback) => ipcRenderer.on('tiktok:streamKeyFound', (e, data) => callback(data)),
  // 运行进度（登录/推流码流程百分比 → 日志区）
  onProgress: (callback) => ipcRenderer.on('tiktok:progress', (e, data) => callback(data)),

  // 节点真实测试（socks5 直连测速）
  testNode: (data) => ipcRenderer.invoke('node:test', data),
  // v1.13.11 节点保存（写 nodes.json → 重启后软件自起内置 xray 代理，不依赖桌面 v2）
  saveNodes: (data) => ipcRenderer.invoke('node:save', data),
  // v1.14.19 节点权威来源读取（重启后前端以此为准恢复节点列表）
  getNodes: () => ipcRenderer.invoke('node:list'),
  proxyStatus: () => ipcRenderer.invoke('node:proxyStatus'),
  // v1.14.0 卡密授权
  licenseCheck: () => ipcRenderer.invoke('license:check'),
  licenseActivate: (data) => ipcRenderer.invoke('license:activate', data),
  // v1.14.1 说明书
  openHelp: () => ipcRenderer.invoke('app:openHelp'),

  // 实时监控（打开直播间独立窗口入口，真实页面）
  startMonitor: (data) => ipcRenderer.invoke('monitor:start', data),
  stopMonitor: (data) => ipcRenderer.invoke('monitor:stop', data),
  monitorStatus: (data) => ipcRenderer.invoke('monitor:status', data),
  // v1.11.0 独立监控窗口：聚焦 / 置顶
  monitorFocusUI: (data) => ipcRenderer.invoke('monitor:focusUI', data),
  monitorPin: (data) => ipcRenderer.invoke('monitor:pin', data),
  // 实时互动事件（评论/进场/点赞/礼物/关注/在线）
  onImEvents: (callback) => ipcRenderer.on('tiktok:im-events', (e, data) => callback(data)),
  // 实时风险告警（封禁/礼物封禁/警告/限流等）
  onRiskWarning: (callback) => ipcRenderer.on('tiktok:risk-warning', (e, data) => callback(data)),
  // v1.12.43 手机下播提醒事件
  onPhoneDownRemind: (callback) => ipcRenderer.on('tiktok:phone-down-remind', (e, data) => callback(data)),
  // 监控运行状态
  onMonitorState: (callback) => ipcRenderer.on('tiktok:monitor-state', (e, data) => callback(data)),
  // v1.9.6 直播间下播/切换 → 实时数据自动清零
  onMonitorCleared: (callback) => ipcRenderer.on('tiktok:monitor-cleared', (e, data) => callback(data)),
  // v1.15.4 手机下播 → 前端清空界面推流码（存储已清，界面也要刷新）
  onStreamCleared: (callback) => ipcRenderer.on('tiktok:stream-cleared', (e, data) => callback(data)),
  // v1.10.0 直播画面小电视（监控窗口直播画面截图）
  onMonitorFrame: (callback) => ipcRenderer.on('tiktok:monitor-frame', (e, data) => callback(data)),
  // v1.9.0 手动发送评论（监控窗口 DOM 注入，官方通道通道）
  sendLiveComment: (data) => ipcRenderer.invoke('monitor:sendComment', data),
  // v1.9.0 自动互动配置同步（前端 → accounts.json）
  syncAutoConfig: (data) => ipcRenderer.invoke('account:saveConfig', data),
  // v1.12.34 签名服务：保存配置 / 检测连通 / 查询状态（软件内可见）
  signerSave: (data) => ipcRenderer.invoke('tiktok:signerSave', data),
  signerCheck: (data) => ipcRenderer.invoke('tiktok:signerCheck', data),
  signerStatus: (data) => ipcRenderer.invoke('tiktok:signerStatus', data),

  // 应用信息
  getVersion: () => ipcRenderer.invoke('app:version'),

  // v1.14.5 一键导出诊断包（日志+代理状态+节点打码+账号摘要 → 桌面 txt）
  exportDiagnostics: () => ipcRenderer.invoke('diagnostics:export'),

  // 环境检测
  isElectron: () => true,
});
