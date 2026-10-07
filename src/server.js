'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const { PORT, HOST, PUBLIC_DIR, ROOT } = require('./config');
const { seedSettings, db, recordJob } = require('./db');
const routes = require('./routes');
const jobs = require('./jobs');

seedSettings();

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// 基础安全响应头（不引入额外依赖）
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// 本地前端库（离线可用，避免依赖公网 CDN）
const vendorMap = {
  '/vendor/vue.global.prod.js': path.join(ROOT, 'node_modules', 'vue', 'dist', 'vue.global.prod.js'),
  '/vendor/echarts.min.js': path.join(ROOT, 'node_modules', 'echarts', 'dist', 'echarts.min.js')
};
for (const [url, file] of Object.entries(vendorMap)) {
  app.get(url, (req, res) => {
    if (!fs.existsSync(file)) return res.status(404).type('text/plain').send('vendor file missing: ' + path.basename(file));
    res.type('application/javascript').sendFile(file);
  });
}

app.use('/api', routes);
// 静态资源不做强缓存（每次用 ETag/Last-Modified 校验），否则前端改版后回访用户仍看到旧界面
app.use(express.static(PUBLIC_DIR, { index: 'index.html', etag: true, lastModified: true, maxAge: 0 }));

app.get('/healthz', (req, res) => {
  res.json({ ok: true, devices: db.prepare('SELECT COUNT(*) AS c FROM devices').get().c });
});

// API 错误统一处理。必须注册在所有路由之后：Express 的错误中间件只接管它"之前"注册的处理函数，
// 放到前面会让后注册的路由（如 /healthz）的异常绕过去，落到 Express 默认处理器上。
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  // 带 status/statusCode 的错误按原码返回（express/body-parser 的错误也带 statusCode），其余未预期的统一 500
  const code = Number(err.status || err.statusCode);
  const status = code >= 400 && code < 600 ? code : 500;
  // 4xx 是可预期的业务错误，前端自己会提示，不写日志；5xx 是未预期的故障，必须留痕。
  // 这里是全站唯一的错误汇聚点（业务错误都由 httpError 抛上来），不记就等于线上故障完全不可见。
  if (status >= 500) console.error(`[adh-device-hub] ${req.method} ${req.originalUrl} -> ${status}\n`, err);
  else if (process.env.DEBUG) console.error(err);
  res.status(status).json({ error: err.message || '服务内部错误' });
});

jobs.restart();

const server = app.listen(PORT, HOST, () => {
  console.log(`[adh-device-hub] 已启动: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`[adh-device-hub] 数据目录: ${require('./config').DATA_DIR}`);
});

process.on('SIGINT', () => { jobs.stop(); server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { jobs.stop(); server.close(() => process.exit(0)); });

// 进程级兜底：systemd 的 Restart=always 能把服务拉起来，但"半夜崩过一次"必须留下痕迹，
// 否则界面上完全看不出重启过（只能去 journalctl 翻 Node 的默认堆栈）。
// 未捕获异常后进程状态已不可信，记完就退出，交给 systemd 重启。
function fatal(kind, err) {
  const detail = err && err.stack ? err.stack : String(err);
  console.error(`[adh-device-hub] ${kind}\n`, detail);
  try {
    recordJob('process', 'failed', `${kind}：${(err && err.message) || String(err)}`);
  } catch (_) { /* 库不可用时只能靠上面的 console */ }
  process.exit(1);
}

process.on('uncaughtException', (err) => fatal('未捕获异常，进程退出', err));
process.on('unhandledRejection', (reason) => fatal('未处理的 Promise 拒绝，进程退出', reason));
