// monitor-preload.js — 监控数据窗口采集（v1.13.15）
// 页面加载时自动注入运行（webPreferences.preload），不依赖 executeJavaScript（观众页 executeJavaScript 持续失败）
// 职责：DOM 扫描（在线/点赞/聊天区/结束检测）→ ipcRenderer 推主进程
// im/fetch 由主进程 pollIm 负责（curl+代理后台轮询），preload 不做网络请求（避免跨域/签名复杂度）
const { ipcRenderer } = require('electron');
try { console.log('MP-LOADED v1.15.53'); } catch (e) {}
function post(kind, data) {
  try { ipcRenderer.send('monitor:data', { kind, data }); } catch (e) {}
}
// v1.15.49 评论 MutationObserver 增量监听（记录仪：页面新增一条消息就收集，scan 取队列推评论——轮询全扫一直漏，换增量）
try {
  window.__cmtQueue = window.__cmtQueue || [];
  window.__cmtSeen = window.__cmtSeen || {};
  if (!window.__cmtObs) {
    window.__cmtObs = new MutationObserver(function (muts) {
      try {
        for (const m of muts) {
          for (const n of m.addedNodes || []) {
            if (!n) continue;
            let t = '';
            if (n.nodeType === 3) t = (n.nodeValue || '').trim();
            else if (n.nodeType === 1) t = (n.innerText || n.textContent || '').trim();
            if (t && t.length > 1 && t.length <= 60 && window.__cmtQueue.length < 200) window.__cmtQueue.push(t);
          }
        }
      } catch (e) {}
    });
    window.__cmtObs.observe(document.body, { childList: true, subtree: true });
  }
} catch (e) {}
function scan() {
  try {
    if (!document || !document.body) return;
    const out = { online: '', likes: '', chatItems: [], ended: '', rawText: '' };
    // 页面文本（风险分类用：观众页显示"直播被暂停/主播被禁"等平台文案）
    out.rawText = ((document.body && document.body.innerText) || '').slice(0, 8000);
    const q = (s) => document.querySelector(s);
    // 在线人数 v1.15.40：观众列表标题"观众·N"实时优先（观众进出立即变，借鉴点赞"读头部实时值"思路）；person-count 平台统计有延迟 → 兜底
    const pc = q('[data-e2e="person-count"]') || q('[data-e2e="person-count" i]');
    let onlineTxt = '';
    try {
      const bodyT = ((document.body && document.body.innerText) || '');
      const vm = bodyT.match(/观众\s*[·:]\s*(\d+)/) || bodyT.match(/观众\s+(\d+)/);
      if (vm) onlineTxt = vm[1];
    } catch (e) {}
    out.online = onlineTxt || (pc ? (pc.innerText || '').trim() : '');
    // 点赞总数（观众页头部）
    const lk = q('[data-e2e="room-header-like-count"]') || q('[data-e2e="room-header-like-count" i]');
    out.likes = lk ? (lk.innerText || '').trim() : '';
    // 聊天区元素级抓取（复刻评论区：按 DOM 标记分类进场/评论/点赞/礼物/关注）
    // v1.15.45 优先观众面板（public-screen-container）：评论/进场/关注/礼物全在观众面板评论区，live-chat-container 可能是空壳
    const chatEl = q('[data-e2e="public-screen-container"]') || q('[data-e2e="chat-list"]') || q('[data-e2e="live-chat-container"]') || q('[data-e2e="public-screen-live-chat-slot"]');
    const items = [];
    const seen = {};
    if (chatEl) {
      const kids = chatEl.querySelectorAll('div');
      // items/seen 在块外定义（评论专项在块外也要用）
      for (const el of kids) { try {
        let txt = (el.innerText || '').trim();
        if (!txt || txt.length > 120 || seen[txt]) continue;
        // v1.13.25 礼物消息元素常为多行文本（序号\n昵称\n送出了玫瑰×N）→ 含礼物特征的保留，不被多行过滤跳过
        // v1.15.40 关注/进场/点赞也常为多行（"trnhyntrinh255 第1\n已关注主播"）→ 互动词同样保留（关注漏抓根因）
        // v1.15.41 评论"昵称\n内容"也常超 20 字符 → 多行只跳过长段落系统文案（>60 字符），评论/互动全保留
        if (txt.indexOf('\n') >= 0 && txt.length > 60 && !/送出了礼物|赠送了|送出了|赠送|sent a gift|sent you|🎁|已关注主播|关注了主播|已加入|进入了直播间|赞了直播|点赞了直播/.test(txt)) continue;
        seen[txt] = 1;
        const e2e = (((el.getAttribute && el.getAttribute('data-e2e')) || '') + ' ' + ((el.className && el.className.toString()) || '')).toLowerCase();
        let k = 'unknown';
        // v1.14.13 平台固定文案排除：公约/规则/欢迎提示（含"充值和赠送礼物"等措辞）绝不能当礼物/进场/评论
        const isPlatformCopy = /年满\s*\d+\s*周岁|创作者必须|观众必须|请务必遵守|社区自律公约|欢迎使用 TikTok 直播|欢迎使用TikTok直播|充值|充值和|开启直播才能/i.test(txt);
        if (isPlatformCopy) continue;
        // v1.13.22 强特征文本优先分类：TikTok 事件元素常无对应 data-e2e 标记（"X 第1 已关注主播"→follow、"💠15 X 送出了香水"→gift）
        if (/已关注主播|关注了主播|followed/.test(txt)) k = 'follow';
        else if (/送出了礼物|赠送了|送出了|sent a gift|sent you/.test(txt)) k = 'gift';
        // v1.15.45 进场：昵称必须含字母/数字（纯 emoji = TikTok 推荐观众/表情回复，不计进场；表情+字母真人能进）
        else if (/[A-Za-z0-9]/.test(txt) && /已加入|进入了直播间/.test(txt)) k = 'enter';
        else if (/赞了直播|点赞了直播/.test(txt)) k = 'like';
        else if (/[A-Za-z0-9]/.test(txt) && /member|enter|join|audience|viewer/.test(e2e)) k = 'enter';
        else if (/chat|comment|message|reply/.test(e2e)) k = 'chat';
        else if (/like/.test(e2e)) k = 'like';
        else if (/gift|diamond|present/.test(e2e)) k = 'gift';
        else if (/follow|social/.test(e2e)) k = 'follow';
        // 文本特征兜底（无强特征也无 e2e 标记）
        if (k === 'unknown') {
          if (/送出了礼物|赠送了|送出了|赠送|sent a gift|sent you|🎁/.test(txt)) k = 'gift';
          else if (/赞了直播|点赞了直播/.test(txt)) k = 'like';
          else if (/[A-Za-z0-9]/.test(txt) && /已加入|进入了直播间|joined the/.test(txt)) k = 'enter';
          else if (/已关注|关注了|followed/.test(txt)) k = 'follow';
        }
        // v1.14.13 进场假数据排除：系统推荐流/自己账号不当事件（观众页"推荐的主播进入了直播间"、账号自身进场）
        if (k === 'enter' && /推荐的主播|推荐的主播进入了直播间|^(genemo58374070|vivianer549|tysonhoa1293)\b/.test(txt)) continue;
        // v1.13.18 进场文本清洗：TikTok 页面噪声（"观众·1"在线标签、"最新"Latest、"第1"标记、数字前缀）混入进场昵称 → 剥掉
        if (k === 'enter') {
          txt = txt.replace(/^(观众[·\s]*\d*|最新|第\s*\d+|\d+\s*)+/g, '').replace(/\s+/g, ' ').trim();
        }
        if (k !== 'unknown' && txt && items.length < 60) items.push({ t: txt, k });
        } catch (e) {} // v1.15.55 单个元素遍历报错不阻断 scan（全页轮询兜底必须跑）
      }
      // v1.13.28 礼物专项补漏：礼物消息元素常不是 div（span/其他标签），上面 div 主循环抓不到 → 全标签扫含送礼文本的节点
      try {
        const allEls = chatEl.querySelectorAll('*');
        for (const el2 of allEls) {
          const t2 = (el2.innerText || '').trim();
          if (!t2 || t2.length > 120 || seen[t2]) continue;
          // v1.14.13 平台公约/规则文案排除（"充值和赠送礼物…请务必遵守"含赠送词，绝不能当礼物）
          if (/年满\s*\d+\s*周岁|创作者必须|观众必须|请务必遵守|社区自律公约|充值|充值和|欢迎使用/.test(t2)) continue;
          if (/送出了礼物|赠送了|送出了|赠送|sent a gift|sent you/.test(t2)) {
            seen[t2] = 1;
            if (items.length < 60) items.push({ t: t2, k: 'gift' });
          }
        }
      } catch (e) {}
      // v1.13.29 礼物兜底：chatEl 内无礼物时，扫全页（礼物可能渲染在聊天容器外/不同容器）
      try {
        const hasGift = items.some(it => it.k === 'gift');
        if (!hasGift) {
          const scope = [document.body];
          for (const sc of scope) {
            const els = sc.querySelectorAll('*');
            for (const el3 of els) {
              const t3 = (el3.textContent || '').trim().replace(/\s+/g, ' ');
              if (!t3 || t3.length > 120 || seen[t3]) continue;
              // v1.14.13 平台公约/规则文案排除 + 真礼物行白名单形态（昵称+送礼词+礼物名，且非长段落文本）
              if (/年满\s*\d+\s*周岁|创作者必须|观众必须|请务必遵守|社区自律公约|充值|充值和|欢迎使用/.test(t3)) continue;
              if (t3.length > 60 && !/送出了礼物|sent a gift|sent you/.test(t3)) continue;
              if (/送出了礼物|赠送了|送出了|赠送|sent a gift|sent you/.test(t3)) {
                seen[t3] = 1;
                if (items.length < 60) items.push({ t: t3, k: 'gift' });
              }
            }
          }
        }
      } catch (e) {}
    }
    // v1.15.50 评论终极保底（=最初能接到消息的宽松逻辑）：全页 body.innerText 切行，非互动词即评论（虚高接受，能接到消息就行）
    try {
      if (!window.__cmtSeen) window.__cmtSeen = {};
      const bodyT = ((document.body && document.body.innerText) || '');
      const lines = bodyT.split('\n');
      let cmtPushed = 0;
      for (const ln of lines) {
        const s = ln.trim();
        if (!s || s.length < 2 || s.length > 60 || window.__cmtSeen[s]) continue;
        // 互动词（进场/关注/点赞/礼物/分享）不计评论
        if (/已加入|进入了|加入了|已关注|关注了|赞了直播|点赞了直播|分享了|送出了礼物|赠送了|送出了|sent a gift|sent you|joined|followed|liked|shared|entered/i.test(s)) continue;
        // 导航/结构/规则文本排除（"为保障社区体验…"系统提示算评论，用户点名）
        if (/^LIVE\s|^TikTok\s|^观众\s*$|^观众[·\s]*\d+\s*$|^最新\s*$|^第\s*\d+\s*$|^\d+\s*$|^输入|^评论关闭|^欢迎使用|^创作者必须|^观众必须|^请务必遵守|^社区自律公约|^为保障社区体验|^有观众即将刷到|^开播连接就绪|^手动发送|^手动开关|^重连不重复|^自动回复|^智能回复|^感谢观看|^欢迎来到|^Welcome|^Thanks|年满\s*\d+\s*周岁|充值和/.test(s)) continue;
        window.__cmtSeen[s] = 1;
        if (items.length < 60) { items.push({ t: s, k: 'chat' }); cmtPushed++; }
      }
      // v1.15.51 评论诊断：body 文本量/行数/推送数/前几行 → 定位评论抓不到在哪一环
      out.cmtDiag = 'bodyT:' + bodyT.length + ' lines:' + lines.length + ' pushed:' + cmtPushed + ' head:' + lines.slice(0, 4).join('|').replace(/\s+/g, ' ').slice(0, 80);
    } catch (e) { out.cmtDiag = 'err:' + (e && e.message); }
    out.chatItems = items;
    // 直播结束检测
    const bodyText = (document.body && document.body.innerText) || '';
    if (/直播已结束|此直播已结束|此直播已停止|直播已下播|LIVE HAS ENDED|This live has ended|The live has ended|The user is not live now|The user is offline|has ended this live/i.test(bodyText)) out.ended = '1';
    else if (/直播已结束|此直播已结束|LIVE HAS ENDED|This live has ended|The user is not live now/i.test((document.title || '') + ' ' + (location.href || ''))) out.ended = '1';
    // v1.13.24 平台限流/限制提示检测（观众页出现限流文案 → 主进程风险告警）
    // v1.14.11 风险告警已停用（RISK_ALERTS_ENABLED=false），此检测跳过，不再输出 limit 字段
    if (false) {
      // v1.13.30 野路子：手机端弹窗观众端不可见，但页面隐藏数据/React 状态/outerHTML 可能含限制标记 → 扫完整 HTML（前 200KB）
      let limitSrc = bodyText + ' ' + (document.title || '') + ' ' + (location.href || '');
      try { limitSrc += ' ' + (document.documentElement ? document.documentElement.outerHTML.slice(0, 200000) : ''); } catch (e) {}
      const limitM = limitSrc.match(/限流|被限制|流量限制|直播已被限制|直播已暂停|直播被暂停|异常流量|流量异常|检测到异常|visibility restricted|not eligible for recommendation|restricted in search results|unoriginal or reproduced|reproduced content|LIVE visibility restricted|has been restricted|live is limited|live has been restricted|restricted visibility/i);
      if (limitM) { out.limit = '1'; out.limitText = limitM[0]; }
    }
    // v1.13.29 礼物诊断：页面文本中送礼词附近片段（定位礼物行在不在监控可见文本里）
    // v1.14.13 排除平台公约文案（"…充值和赠送礼物…请务必遵守…"被误当礼物线索刷屏）
    try {
      const scopeTxt = ((document.body && document.body.innerText) || '').slice(0, 12000);
      const dm = scopeTxt.replace(/年满\s*\d+\s*周岁[^。]*?。|创作者必须[^。]*?。|观众必须[^。]*?。|请务必遵守[^。]*?。|社区自律公约[^。]*?。/g, ' ').match(/.{0,40}(?:送出了礼物|赠送了|送出了|赠送|sent a gift|sent you).{0,40}/i);
      out.giftDiag = dm ? dm[0].replace(/\s+/g, ' ').trim() : '';
    } catch (e) {}
    post('dom', out);
  } catch (e) {
    try { post('dom', { err: e.message }); } catch (e2) {}
  }
}
function start() {
  if (window.__monitorStarted) return;
  window.__monitorStarted = 1;
  scan();
  // 每 2s 扫描一次（点赞/评论高频场景减少遗漏）
  setInterval(scan, 2000);
  // MutationObserver 触发（DOM 变化时也立即扫，防 setInterval 节流丢事件）
  // v1.13.23 800ms 节流：点赞动画等高频 DOM 变化不再每帧 scan（否则 like 事件毫秒级刷屏卡监控）
  try {
    let lastMoScan = 0;
    const mo = new MutationObserver(() => {
      const now = Date.now();
      if (now - lastMoScan < 800) return;
      lastMoScan = now;
      try { scan(); } catch (e) {}
    });
    mo.observe(document.documentElement || document.body, { childList: true, subtree: true });
  } catch (e) {}
  // 就绪后上报一次"预载完成"（主进程据此判断 preload 通道可用）
  post('ready', { ts: Date.now() });
}
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  setTimeout(start, 1500);
} else {
  window.addEventListener('DOMContentLoaded', () => setTimeout(start, 1500));
  window.addEventListener('load', () => setTimeout(start, 800));
}
// 兜底：页面 10s 后仍未 start（事件丢失）
setTimeout(() => { try { if (!window.__monitorStarted) { window.__monitorStarted = 1; start(); } } catch (e) {} }, 10000);
