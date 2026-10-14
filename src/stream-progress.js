'use strict';

// 按完整进度块确认首次视频输出，兼容 stdout 数据分片。
function createOutputProgressTracker(onStarted) {
  let buffer = '', frame = 0, bytes = 0, started = false;
  return (chunk) => {
    buffer += chunk.toString();
    let end;
    while ((end = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, end).trim();
      buffer = buffer.slice(end + 1);
      const separator = line.indexOf('=');
      if (separator === -1) continue;
      const key = line.slice(0, separator), value = line.slice(separator + 1);
      if (key === 'frame') frame = Number(value) || 0;
      if (key === 'total_size') bytes = Number(value) || 0;
      if (key === 'progress' && !started && frame > 0 && bytes > 0) {
        started = true;
        onStarted({ frame, bytes });
      }
    }
  };
}

module.exports = { createOutputProgressTracker };
