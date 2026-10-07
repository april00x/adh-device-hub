'use strict';

/**
 * 拦截流量分析监听器（sinkhole）：AdGuard 把被拦截域名解析到本机后客户端会来连，
 * 本模块就在客户端实际连接的端口上就地监听，被动收包、抽取请求内容、返回固定应答。
 *
 * 三条约束由代码保证，没有旁路：不代理回源；不执行客户端输入；返回内容固定（只有常量应答）。
 * 协议识别不依赖端口，所有连接都要先嗅探首包再分派。
 *
 * 交接机制（改动前先读）：
 *   - 明文 HTTP：首包 unshift 回真实 socket 再 emit('connection', socket)；
 *     resume() 必须在 emit 之后，否则 unshift 回去的字节会被当成无人消费的 data 丢掉。
 *   - TLS：不能把真实 socket 直接交给 TLS 层，否则 unshift 进去的首包会丢、握手报 wrong version number；
 *     需先用 Duplex 包一层再交给 http2 安全服务器，allowHTTP1 让它同时处理 h2 与 h1。
 *   - 上下文关联：TLS 走 Duplex 后 TLSSocket 上没有 remoteAddress，必须自己把 ctx 挂在 Duplex 上，
 *     握手完成时从 tlsSocket._handle._parentWrap.stream 取回来；取不到就退化为最小上下文。
 */

const net = require('net');
const http = require('http');
const http2 = require('http2');
const { Duplex } = require('stream');
const { db, allSettings, recordJob } = require('./db');
const { buildResolvers } = require('./ingest');
const sinkparse = require('./sinkparse');
const sinkcerts = require('./sinkcerts');

/* ------------------------------ 状态 ------------------------------ */

const state = {
  running: false,
  startedAt: null,
  lastFlushAt: null,
  listeners: [],            // [{ port, server, error }]
  inflight: 0,              // 当前正在处理的连接数
  droppedRows: 0,           // 因写入限流被丢弃的明细行数
  totalEvents: 0,           // 进程启动以来观察到的事件数（含被合并的次数）
  lastError: null
};

let cfg = null;             // 启动时快照的配置
let agg = new Map();        // 去重窗口内的聚合缓冲
let flushTimer = null;
let sweepTimer = null;
let httpServer = null;      // 明文 HTTP/1.1
let secureServer = null;    // TLS 终止入口（h2 + h1）
let resolver = null;        // 设备归属解析器（带缓存）
let resolverAt = 0;
let resolverErrAt = 0;      // 上次重建失败的时间，用于给日志节流
let newRowWindow = [];      // "每秒新增行数"限流的滑动窗口

/* ------------------------------ 工具 ------------------------------ */

function isOn(v) { return String(v === undefined || v === null ? '0' : v) === '1'; }

/** IPv4-mapped IPv6（::ffff:192.168.1.5）还原成 IPv4，否则归属时间线匹配不上 */
function normIp(ip) {
  const s = String(ip || '');
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

function log(...args) { console.log('[sinkhole]', ...args); }

/* ------------------------------ 归属解析 ------------------------------ */

/**
 * 复用“合并日志”那套 IP 归属时间线，保证两个页面口径一致；重建时间线开销太大，带 30 秒缓存。
 */
function resolveDevice(clientIp, ts) {
  if (!clientIp) return { deviceId: null, label: null };
  if (!resolver || Date.now() - resolverAt > 30000) {
    try {
      resolver = buildResolvers();
      resolverAt = Date.now();
    } catch (e) {
      // 重建失败是系统性故障：页面上所有连接都会变成"未归属"，必须留痕，
      // 否则只表现为"什么都没归属上"，看不出是解析坏了。
      // resolver 仍为空时这条路径每次连接都会重试，所以日志按 30 秒节流。
      if (Date.now() - resolverErrAt > 30000) {
        resolverErrAt = Date.now();
        log('归属解析重建失败，连接将全部记为未归属：', e.message);
      }
      return { deviceId: null, label: null };
    }
  }
  try {
    return resolver.resolve(clientIp, ts);
  } catch (e) {
    // 与上面重建失败是两种原因、同一种症状（连接全变"未归属"），同样要留痕、共用同一个节流
    if (Date.now() - resolverErrAt > 30000) {
      resolverErrAt = Date.now();
      log('归属解析失败，连接将记为未归属：', e.message);
    }
    return { deviceId: null, label: null };
  }
}

/* ------------------------------ 记录与落库 ------------------------------ */

const SQL_INSERT = `INSERT OR IGNORE INTO sink_events
  (ts, last_ts, hits, client_ip, client_port, device_id, device_name, proto, lport, host, method, path, query,
   http_ver, ua, referer, headers_json, body_bytes, body_preview, content_type, content_encoding, charset,
   body_kind, body_fields, tls_version, tls_cipher, tls_client_ciphers,
   ja3, ja4, alpn, tls_note, decrypted, outcome, duration_ms, created_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;

const SQL_FIND_ID = `SELECT id FROM sink_events
  WHERE ts = ? AND client_ip IS ? AND lport IS ? AND host IS ? AND method IS ? AND path IS ?`;

const SQL_UPDATE = `UPDATE sink_events
  SET hits = ?, last_ts = ?, duration_ms = COALESCE(?, duration_ms), outcome = ?,
      decrypted = MAX(decrypted, ?),
      tls_note = COALESCE(?, tls_note),
      tls_cipher = COALESCE(?, tls_cipher),
      tls_client_ciphers = COALESCE(?, tls_client_ciphers),
      ja3 = COALESCE(?, ja3),
      ja4 = COALESCE(?, ja4),
      headers_json = COALESCE(?, headers_json),
      body_bytes = COALESCE(?, body_bytes),
      body_preview = COALESCE(?, body_preview),
      content_type = COALESCE(?, content_type),
      content_encoding = COALESCE(?, content_encoding),
      charset = COALESCE(?, charset),
      body_kind = COALESCE(?, body_kind),
      body_fields = COALESCE(?, body_fields)
  WHERE id = ?`;

/**
 * 把一次连接/请求记入内存聚合缓冲。
 * 同一（客户端, 端口, 主机, 方法, 路径）在窗口内只占一条记录并累加 hits，写库由 flush() 批量完成。
 */
function record(evt) {
  if (!cfg || !cfg.enabled) return;
  const ts = evt.ts || Date.now();
  const key = [evt.clientIp, evt.lport, evt.host || '', evt.method || '', evt.path || ''].join('|');
  state.totalEvents += 1;

  const hit = agg.get(key);
  if (hit) {
    hit.hits += 1;
    hit.lastTs = ts;
    hit.dirty = true;
    if (evt.durationMs != null && (hit.durationMs == null || evt.durationMs > hit.durationMs)) hit.durationMs = evt.durationMs;
    if (evt.outcome) hit.outcome = evt.outcome;
    if (evt.decrypted) hit.decrypted = 1;
    if (evt.tlsNote && !hit.tlsNote) hit.tlsNote = evt.tlsNote;
    if (evt.tlsCipher && !hit.tlsCipher) hit.tlsCipher = evt.tlsCipher;
    if (evt.tlsClientCiphers != null && hit.tlsClientCiphers == null) hit.tlsClientCiphers = evt.tlsClientCiphers;
    if (evt.ja3 && !hit.ja3) hit.ja3 = evt.ja3;
    if (evt.ja4 && !hit.ja4) hit.ja4 = evt.ja4;
    if (evt.headersJson && !hit.headersJson) hit.headersJson = evt.headersJson;
    if (evt.bodyBytes != null && hit.bodyBytes == null) hit.bodyBytes = evt.bodyBytes;
    if (evt.bodyPreview && !hit.bodyPreview) hit.bodyPreview = evt.bodyPreview;
    if (evt.contentType && !hit.contentType) hit.contentType = evt.contentType;
    if (evt.contentEncoding && !hit.contentEncoding) hit.contentEncoding = evt.contentEncoding;
    if (evt.charset && !hit.charset) hit.charset = evt.charset;
    if (evt.bodyKind && !hit.bodyKind) hit.bodyKind = evt.bodyKind;
    if (evt.bodyFields && !hit.bodyFields) hit.bodyFields = evt.bodyFields;
    return;
  }

  if (!newRowAllowed()) {
    // 超过"每秒新增行数"上限：只计数不入库，避免异常流量写满磁盘
    state.droppedRows += 1;
    return;
  }

  const { deviceId, label } = resolveDevice(evt.clientIp, ts);
  agg.set(key, {
    dbId: null, dirty: true,
    ts, lastTs: ts, hits: 1,
    clientIp: evt.clientIp || null, clientPort: evt.clientPort || null,
    deviceId, deviceName: label,
    proto: evt.proto || null, lport: evt.lport || null,
    host: evt.host || null, method: evt.method || null, path: evt.path || null, query: evt.query || null,
    httpVer: evt.httpVer || null, ua: evt.ua || null, referer: evt.referer || null,
    headersJson: evt.headersJson || null,
    bodyBytes: evt.bodyBytes == null ? null : evt.bodyBytes,
    bodyPreview: evt.bodyPreview || null,
    contentType: evt.contentType || null, contentEncoding: evt.contentEncoding || null,
    charset: evt.charset || null, bodyKind: evt.bodyKind || null, bodyFields: evt.bodyFields || null,
    tlsVersion: evt.tlsVersion || null, tlsCipher: evt.tlsCipher || null,
    tlsClientCiphers: evt.tlsClientCiphers == null ? null : evt.tlsClientCiphers,
    ja3: evt.ja3 || null, ja4: evt.ja4 || null, alpn: evt.alpn || null,
    tlsNote: evt.tlsNote || null, decrypted: evt.decrypted ? 1 : 0,
    outcome: evt.outcome || null, durationMs: evt.durationMs == null ? null : evt.durationMs,
    createdAt: new Date().toISOString()
  });
}

/** 写入限流只作用于"新增明细行"；窗口内累加既有行不受影响 */
function newRowAllowed() {
  const max = Math.max(1, Number(cfg.maxRowsPerSec) || 50);
  const now = Date.now();
  while (newRowWindow.length && now - newRowWindow[0] > 1000) newRowWindow.shift();
  if (newRowWindow.length >= max) return false;
  newRowWindow.push(now);
  return true;
}

/** 把聚合缓冲批量写库 */
function flush() {
  state.lastFlushAt = Date.now();
  if (!agg.size) return { inserted: 0, updated: 0, failed: 0 };
  const ins = db.prepare(SQL_INSERT);
  const find = db.prepare(SQL_FIND_ID);
  const upd = db.prepare(SQL_UPDATE);
  let inserted = 0, updated = 0;

  // 内存状态只在事务成功提交后才落回，否则回滚后下一轮会去 UPDATE 不存在的行，事件被静默丢掉。
  const pending = [];

  const tx = db.transaction((entries) => {
    for (const r of entries) {
      if (r.dbId) {
        if (!r.dirty) continue;
        upd.run(r.hits, r.lastTs, r.durationMs, r.outcome, r.decrypted, r.tlsNote,
          r.tlsCipher, r.tlsClientCiphers, r.ja3, r.ja4,
          r.headersJson, r.bodyBytes, r.bodyPreview,
          r.contentType, r.contentEncoding, r.charset, r.bodyKind, r.bodyFields, r.dbId);
        pending.push({ r, dbId: r.dbId });
        updated++;
      } else {
        const info = ins.run(
          r.ts, r.lastTs, r.hits, r.clientIp, r.clientPort, r.deviceId, r.deviceName, r.proto, r.lport,
          r.host, r.method, r.path, r.query, r.httpVer, r.ua, r.referer, r.headersJson,
          r.bodyBytes, r.bodyPreview,
          r.contentType, r.contentEncoding, r.charset, r.bodyKind, r.bodyFields,
          r.tlsVersion, r.tlsCipher, r.tlsClientCiphers, r.ja3, r.ja4,
          r.alpn, r.tlsNote, r.decrypted, r.outcome, r.durationMs, r.createdAt
        );
        let id = null;
        if (info.changes) {
          id = info.lastInsertRowid;
          inserted++;
        } else {
          // 唯一索引兜底冲突：找回既有行 id，之后走 UPDATE，避免重复插入
          const row = find.get(r.ts, r.clientIp, r.lport, r.host, r.method, r.path);
          id = row ? row.id : null;
        }
        pending.push({ r, dbId: id });
      }
    }
  });

  try {
    tx([...agg.values()]);
    for (const p of pending) { p.r.dbId = p.dbId; p.r.dirty = false; }
  } catch (e) {
    // 临时失败（如 database is locked）：内存保持 dirty，下一轮自动重试，不丢数据
    state.lastError = e.message;
    log(`落库失败，将在下一轮重试（涉及 ${pending.length} 条）：${e.message}`);
    return { inserted: 0, updated: 0, failed: pending.length };
  }
  return { inserted, updated, failed: 0 };
}

/** 清理长时间未再命中的聚合项：下次同一 key 会重新开一条明细行 */
function sweep() {
  const ttl = Math.max(10, Number(cfg.dedupWindowSec) || 60) * 1000;
  const now = Date.now();
  for (const [k, r] of agg) {
    if (now - r.lastTs > ttl) agg.delete(k);
  }
  // 内存兜底：异常流量下聚合表也不能无限增长
  if (agg.size > 5000) {
    const sorted = [...agg.entries()].sort((a, b) => a[1].lastTs - b[1].lastTs);
    for (let i = 0; i < sorted.length - 4000; i++) agg.delete(sorted[i][0]);
  }
}

/* ------------------------------ 应答 ------------------------------ */

const PAGE_HTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>该域名已被拦截</title></head><body style="font-family:sans-serif;padding:40px;color:#333">
<h2>该域名已被拦截</h2>
<p>本机不是该域名的真实服务器，本次请求已被拦截，不会得到任何内容。</p>
</body></html>`;

/**
 * 按 sink_response 返回固定应答。固定指只有这几种常量响应，不回源。
 * 返回 outcome 标记，便于页面上区分"我们是怎么回的"。
 * h1 与 h2 的兼容响应对象都支持 writeHead/end，所以这里不需要分支。
 */
function respondHttp(res) {
  switch (cfg.response) {
    case 'page': {
      const body = Buffer.from(PAGE_HTML);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length });
      res.end(body);
      return 'page';
    }
    case 'close':
      try { res.destroy(); } catch (e) { /* ignore */ }
      return 'closed';
    default:
      res.writeHead(204);
      res.end();
      return 'empty';
  }
}

/* ------------------------------ 请求处理 ------------------------------ */

/** 明文与解密后的请求走同一条链路（http2 兼容层把伪头部也规范化进了 headers） */
function onRequest(req, res, ctx) {
  // 计数用于兜底：只完成了 TLS 握手、始终没发来可解析请求的连接也要留痕（见 secureConnection 的 close 处理）
  ctx.reqCount = (ctx.reqCount || 0) + 1;
  // 计时与去重都按请求而不是按连接：keep-alive 下一条连接会跑多个请求，
  // 用连接级的标记会把第二个请求当成重复而漏记。
  const started = Date.now();
  let done = false;
  let outcome = 'empty';

  const h = sinkparse.pickHeaders(req.headers, { captureAll: cfg.captureHeaders });
  const { path, query } = sinkparse.splitPath(req.url);
  const limit = cfg.captureBody ? cfg.bodyPreviewBytes : 0;
  // 压缩正文必须拿到相对完整的压缩流才能解压，所以原始字节按更宽的上限收集；
  // 落库体积仍由 limit 控制（解压之后再按 limit 截断）。
  const rawLimit = limit ? sinkparse.rawCaptureLimit(limit) : 0;
  // 客户端声明了但没传完时，正文是残缺的（chunked 上传没有这个头，值为 0 不参与判断）
  const declared = Number(req.headers['content-length']) || 0;
  const chunks = [];
  let captured = 0;
  let got = 0;

  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(t);
    // 先应答再落库：应答必须及时，落库只是记账
    try { outcome = respondHttp(res); } catch (e) { outcome = 'error'; try { res.destroy(); } catch (_) { /* ignore */ } }
    ctx.recorded = true;      // 连接级标记：这次已经解出过明文，别再补一条"仅 SNI"
    // 预览串与结构化字段共用一次解压解码，避免两遍解析得出不一致的结果
    const body = captured
      ? sinkparse.analyzeBody(Buffer.concat(chunks), limit, req.headers, got > captured || declared > got)
      : null;
    record({
      ts: started, clientIp: ctx.clientIp, clientPort: ctx.clientPort, lport: ctx.lport,
      proto: ctx.proto, host: h.host || ctx.sni || null,
      method: req.method || null, path, query,
      httpVer: 'HTTP/' + req.httpVersion,
      ua: h.ua || null, referer: h.referer || null, headersJson: h.all,
      // 口径统一为"实际收到的字节数"：一旦正文没读完，body_bytes 与 body_preview 就会矛盾。
      bodyBytes: got || null,
      bodyPreview: body ? body.preview : null,
      contentType: body ? body.contentType : null,
      contentEncoding: body ? body.contentEncoding : null,
      charset: body ? body.charset : null,
      bodyKind: body ? body.kind : null,
      bodyFields: body ? body.fields : null,
      tlsVersion: ctx.tlsVersion || null, tlsCipher: ctx.tlsCipher || null,
      tlsClientCiphers: ctx.tlsClientCiphers == null ? null : ctx.tlsClientCiphers,
      ja3: ctx.ja3 || null, ja4: ctx.ja4 || null,
      alpn: ctx.alpn || null,
      tlsNote: ctx.tlsNote || null, decrypted: ctx.decrypted ? 1 : 0,
      outcome, durationMs: Date.now() - started
    });
  };

  req.on('data', (c) => {
    got += c.length;
    if (rawLimit && captured < rawLimit) {
      const take = Math.min(rawLimit - captured, c.length);
      chunks.push(c.subarray(0, take));
      captured += take;
    }
  });
  req.on('error', () => {});
  req.on('aborted', finish);
  req.on('end', finish);
  // 正文迟迟不来时不能一直等：到点先应答并落库，正文标记为已截断。
  // 但必须等正文读完再应答，提前应答会让 Node 关掉连接，keep-alive 的客户端会收到 socket hang up。
  const t = setTimeout(finish, cfg.bodyWaitMs);
  if (t.unref) t.unref();
  req.on('close', () => { clearTimeout(t); finish(); });
}

/* ------------------------------ 交接 ------------------------------ */

/**
 * 明文 HTTP：首包 unshift 回真实 socket 再交给 http.Server。
 * 必须用真实 socket（http.Server 要调 socket.setTimeout / setNoDelay，纯 Duplex 没有）；resume 必须在 emit 之后。
 */
function handoffPlain(socket, buf, ctx) {
  socket.pause();
  if (buf && buf.length) socket.unshift(buf);
  httpServer.emit('connection', socket);
  socket.resume();
}

/**
 * 构造 TLS 需要的 Duplex 适配器。
 * 不能直接把 socket 交给 TLS 层：TLS 会接管原生 handle，unshift 进去的首包会丢、握手报 wrong version number。
 */
function wrapDuplex(socket, buf, ctx) {
  const d = new Duplex({
    read() { /* 数据由下面 socket 的 data 事件推送 */ },
    write(chunk, enc, cb) { socket.write(chunk, enc, cb); }
  });
  d.__sinkCtx = ctx;
  socket.on('data', (c) => d.push(c));
  socket.on('end', () => d.push(null));
  socket.on('close', () => d.destroy());
  socket.on('error', (e) => d.destroy(e));
  d.on('data', () => { /* 保持流动 */ });
  d.on('error', () => { try { socket.destroy(); } catch (e) { /* ignore */ } });
  if (buf && buf.length) d.push(buf);
  return d;
}

/**
 * TLS 走 Duplex 后 TLSSocket 上没有 remoteAddress，ctx 只能从 _handle._parentWrap.stream 取回来；
 * 取不到就退化为最小上下文（仍会落库，只是没有 client_ip 与设备归属）。
 */
function ctxFromTlsSocket(socket) {
  try {
    const h = socket && socket._handle;
    const w = h && h._parentWrap;
    const d = w && w.stream;
    if (d && d.__sinkCtx) return d.__sinkCtx;
  } catch (e) { /* 取决于 Node 内部结构，取不到就退化 */ }
  return { clientIp: null, clientPort: null, lport: null, startedAt: Date.now(), recorded: false, decrypted: 1, proto: 'https' };
}

/* ------------------------------ 分派 ------------------------------ */

function onRawConnection(socket, lport) {
  state.inflight += 1;
  const ctx = {
    clientIp: normIp(socket.remoteAddress),
    clientPort: socket.remotePort || null,
    lport,
    startedAt: Date.now(),
    recorded: false,
    decrypted: 0,
    sni: '', alpn: null, tlsVersion: null, tlsCipher: null, tlsClientCiphers: null,
    ja3: null, ja4: null, tlsNote: null, proto: null
  };
  socket.on('error', () => {});
  socket.on('close', () => { state.inflight = Math.max(0, state.inflight - 1); });

  let acc = null;
  let settled = false;
  const cleanup = () => {
    socket.removeListener('data', onData);
    clearTimeout(timer);
  };
  const settle = (kind) => {
    if (settled) return;
    settled = true;
    cleanup();
    dispatch(socket, acc || Buffer.alloc(0), kind, ctx);
  };
  const onData = (chunk) => {
    acc = acc ? Buffer.concat([acc, chunk]) : chunk;
    const p = sinkparse.probe(acc);
    if (p.kind === 'pending' && acc.length < sinkparse.MAX_HELLO_BYTES) return;
    settle(p.kind === 'pending' ? 'unknown' : p.kind);
  };
  // 大多数协议首包足够判定；3 秒还判不出来就当未知协议处理，别把连接挂死
  const timer = setTimeout(() => settle('unknown'), 3000);
  if (timer.unref) timer.unref();
  // 客户端提前断开时也要立刻判定并落库，否则这条连接会白等满 3 秒才被记下
  socket.on('close', () => settle('unknown'));
  socket.on('data', onData);
}

function dispatch(socket, buf, kind, ctx) {
  try {
    if (kind === 'http') {
      ctx.proto = 'http';
      socket.__sinkCtx = ctx;      // http.Server 用的是同一个 socket 对象，直接取得到
      handoffPlain(socket, buf, ctx);
      return;
    }

    if (kind === 'tls') {
      const hello = sinkparse.parseHello(buf);
      ctx.sni = hello.sni || '';
      ctx.alpn = hello.alpn.length ? hello.alpn.join(',') : null;
      // 记录层版本是兼容值（现代客户端一律填 0x0301 = TLS 1.0），不要拿它当版本显示；
      // 只用 supported_versions 声明的版本，否则留空；握手成功后这里会被真实版本覆盖。
      ctx.tlsVersion = hello.versions.length ? hello.versions[0] : null;
      // ClientHello 里客户端提供了多少个套件：仅 SNI 的行也有这个数，可当作弱指纹维度
      ctx.tlsClientCiphers = hello.cipherCount || null;
      // 客户端指纹：仅 SNI 的记录也能算出来，这是"同一个 App 换了域名"的关键线索
      ctx.ja3 = hello.ja3 || null;
      ctx.ja4 = hello.ja4 || null;

      if (cfg.tlsMode !== 'mitm') {
        // sni 模式：读到 ClientHello 即结束。不做任何握手，也就不需要客户端信任任何证书。
        ctx.proto = 'tls';
        ctx.tlsNote = 'sni 模式：只读取 SNI，不解密';
        recordTlsOnly(ctx, 'closed');
        socket.destroy();
        return;
      }

      // mitm 模式：终止 TLS 并解密。证书签发超预算时握手失败但 SNI 仍会记录，宁可不解密也不拖垮事件循环。
      ctx.proto = 'https';
      ctx.decrypted = 1;
      socket.pause();
      ensureSecureServer().emit('connection', wrapDuplex(socket, buf, ctx));
      socket.resume();
      return;
    }

    // 未知协议：只留一条带首包 hex 的记录，便于人工识别私有协议
    ctx.proto = 'tcp';
    record({
      ts: ctx.startedAt, clientIp: ctx.clientIp, clientPort: ctx.clientPort, lport: ctx.lport,
      proto: 'tcp', host: null, path: sinkparse.hexPreview(buf, cfg.tcpPreviewBytes),
      bodyBytes: buf.length || null, outcome: 'closed',
      durationMs: Date.now() - ctx.startedAt
    });
    socket.destroy();
  } catch (e) {
    state.lastError = e.message;
    log('分派失败', e.message);
    try { socket.destroy(); } catch (_) { /* ignore */ }
  }
}

/**
 * 没有 HTTP 请求可解析时的记录（只读到 SNI / 握手失败 / 握手成功但没发请求）。
 * proto 与 decrypted 跟随 ctx：握手成功的兜底记录是 https + 已解密，仅 SNI 的则是 tls + 未解密。
 */
function recordTlsOnly(ctx, outcome) {
  record({
    ts: ctx.startedAt, clientIp: ctx.clientIp, clientPort: ctx.clientPort, lport: ctx.lport,
    proto: ctx.proto || 'tls', host: ctx.sni || null, tlsVersion: ctx.tlsVersion, alpn: ctx.alpn,
    tlsCipher: ctx.tlsCipher, tlsClientCiphers: ctx.tlsClientCiphers,
    ja3: ctx.ja3, ja4: ctx.ja4,
    tlsNote: ctx.tlsNote, decrypted: ctx.decrypted ? 1 : 0, outcome,
    durationMs: Date.now() - ctx.startedAt
  });
}

/* ------------------------------ 生命周期 ------------------------------ */

function buildServers() {
  if (httpServer) return;

  // 明文 HTTP/1.1
  httpServer = http.createServer((req, res) => {
    const ctx = req.socket.__sinkCtx;
    if (!ctx) { try { res.destroy(); } catch (e) { /* ignore */ } return; }
    onRequest(req, res, ctx);
  });
  httpServer.on('clientError', (err, socket) => { try { socket.destroy(); } catch (e) { /* ignore */ } });
  httpServer.keepAliveTimeout = 5000;
  httpServer.headersTimeout = 10000;
}

/**
 * TLS 解密入口按需创建：只在 mitm 模式下才需要，提前创建会多生成一套 CA 私钥，
 * 并让弱机每次启动多一笔 RSA 密钥生成开销。
 */
function ensureSecureServer() {
  if (secureServer) return secureServer;
  const pems = sinkcerts.defaultPems(cfg.bindIp);
  secureServer = http2.createSecureServer({
    allowHTTP1: true,
    ALPNProtocols: ['h2', 'http/1.1'],
    SNICallback: (name, cb) => {
      // 返回 null 表示本次不签发（超出事件循环预算），握手失败但 SNI 已记录
      cb(null, sinkcerts.contextFor(name));
    },
    key: pems.key,
    cert: pems.cert
  });
  // 握手完成时把 ctx 从 Duplex 搬回 TLSSocket，请求处理阶段直接取用
  secureServer.on('secureConnection', (socket) => {
    socket.on('error', () => {});
    const c = ctxFromTlsSocket(socket);
    // 握手成功了，用协商出的真实版本覆盖 ClientHello 里声明的最高版本，避免展示误导
    try { c.tlsVersion = sinkparse.protocolName(socket.getProtocol()) || c.tlsVersion; } catch (e) { /* ignore */ }
    // 协商出的密码套件（这才是 tls_cipher 该填的东西；仅 SNI 的行没有协商结果，保持为空）
    try {
      const ci = socket.getCipher && socket.getCipher();
      if (ci) c.tlsCipher = String(ci.standardName || ci.name || '').slice(0, 64) || null;
    } catch (e) { /* ignore */ }
    // 兜底：握手成功但客户端没发来可解析请求时也要留痕，否则连接数与记录数对不上。
    socket.on('close', () => {
      if (c.reqCount || c.recorded) return;
      c.recorded = true;
      c.proto = 'https';        // TLS 确实被终止并解密了，只是没有请求可解析
      c.decrypted = 1;
      c.tlsNote = c.tlsNote || 'TLS 握手成功，但客户端未发送可解析的 HTTP 请求';
      recordTlsOnly(c, 'closed');
    });
    socket.__sinkCtx = c;
  });
  secureServer.on('request', (req, res) => {
    const ctx = req.socket && req.socket.__sinkCtx;
    if (!ctx) { try { res.destroy(); } catch (e) { /* ignore */ } return; }
    onRequest(req, res, ctx);
  });
  secureServer.on('tlsClientError', (err, socket) => {
    const ctx = socket ? ctxFromTlsSocket(socket) : null;
    if (ctx && !ctx.recorded) {
      ctx.recorded = true;
      ctx.proto = 'tls';
      ctx.decrypted = 0;
      // 握手失败：客户端证书固定（pinning）、或我们没签发成功。只留 SNI。
      ctx.tlsNote = ctx.tlsNote || ('TLS 握手失败：' + String(err.message || '').slice(0, 120));
      recordTlsOnly(ctx, 'error');
    }
    try { if (socket) socket.destroy(); } catch (e) { /* ignore */ }
  });
  secureServer.on('sessionError', () => {});
  secureServer.on('clientError', () => {});
  return secureServer;
}

function readConfig(s) {
  return {
    enabled: isOn(s.sink_enabled),
    bindIp: String(s.sink_bind_ip || '').trim(),
    httpPort: Number(s.sink_http_port) || 80,
    httpsPort: Number(s.sink_https_port) || 443,
    extraPorts: String(s.sink_extra_ports || '').split(',')
      .map((x) => Number(String(x).trim())).filter((x) => Number.isInteger(x) && x > 0 && x < 65536),
    tcpPreviewBytes: Math.max(8, Number(s.sink_tcp_preview_bytes) || 64),
    tlsMode: String(s.sink_tls_mode || 'sni') === 'mitm' ? 'mitm' : 'sni',
    response: ['empty', 'close', 'page'].includes(String(s.sink_response)) ? String(s.sink_response) : 'empty',
    captureHeaders: isOn(s.sink_capture_headers),
    captureBody: isOn(s.sink_capture_body),
    bodyPreviewBytes: Math.max(32, Number(s.sink_body_preview_bytes) || 512),
    bodyWaitMs: Math.min(10000, Math.max(100, Number(s.sink_body_wait_ms) || 1000)),
    dedupWindowSec: Math.max(5, Number(s.sink_dedup_window_sec) || 60),
    maxRowsPerSec: Math.max(1, Number(s.sink_max_rows_per_sec) || 50)
  };
}

function start() {
  if (state.running) return status();
  cfg = readConfig(allSettings());
  if (!cfg.enabled) { state.running = false; cfg = null; return status(); }

  buildServers();
  // 解密模式下提前把 TLS 入口建好：证书生成有问题就在这里失败，而不是等第一条连接进来才发现
  if (cfg.tlsMode === 'mitm') ensureSecureServer();
  // 留空 = 双栈：host 省略时 Node 监听 ::（含 IPv4 映射地址），IPv4 与 IPv6 都能进来。
  // 不能退化成 '0.0.0.0'：那是纯 IPv4 套接字，被拦的 IPv6 客户端会全部连不上（丢掉的都是 IPv6 流量）。
  const host = cfg.bindIp || '';
  const ports = [...new Set([cfg.httpPort, cfg.httpsPort, ...cfg.extraPorts])];

  for (const port of ports) {
    const server = net.createServer((socket) => onRawConnection(socket, port));
    server.on('error', (e) => {
      state.lastError = `端口 ${port} 监听失败：${e.message}`;
      log(state.lastError);
      const item = state.listeners.find((x) => x.port === port);
      if (item) item.error = e.message;
    });
    server.listen(port, host || undefined, () => log(host ? `监听 ${host}:${port}` : `监听 *:${port}（IPv4 + IPv6 双栈）`));
    state.listeners.push({ port, server, error: null });
  }

  agg = new Map();
  state.running = true;
  state.startedAt = new Date().toISOString();
  state.lastError = null;
  flushTimer = setInterval(() => { try { flush(); } catch (e) { log('flush 失败', e.message); } }, 5000);
  if (flushTimer.unref) flushTimer.unref();
  sweepTimer = setInterval(() => { try { sweep(); } catch (e) { /* ignore */ } }, 30000);
  if (sweepTimer.unref) sweepTimer.unref();

  // 启动成功与否都记一条任务记录：端口被占用是最常见的启动失败，需要能从界面上看到
  const bad = state.listeners.filter((x) => x.error);
  const ok = state.listeners.filter((x) => !x.error);
  try {
    recordJob('sinkhole', bad.length ? 'failed' : 'success',
      `拦截流量分析${bad.length ? '部分端口失败' : '已启动'}：${ok.map((x) => x.port).join('/') || '无'}`
      + `（${cfg.tlsMode === 'mitm' ? 'MITM 解密' : '仅抓 SNI'}）`
      + (bad.length ? `；失败端口 ${bad.map((x) => `${x.port}(${x.error})`).join(' ')}` : ''),
      { ports: state.listeners.map((x) => ({ port: x.port, error: x.error })), tls_mode: cfg.tlsMode });
  } catch (e) { /* 记录失败不影响监听 */ }
  return status();
}

function stop() {
  if (flushTimer) { clearInterval(flushTimer); flushTimer = null; }
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
  try { flush(); } catch (e) { /* ignore */ }
  for (const item of state.listeners) {
    try { item.server.close(); } catch (e) { /* ignore */ }
  }
  state.listeners = [];
  agg = new Map();
  resolver = null;
  secureServer = null;      // 连同已缓存的证书上下文一起释放；下次按模式需要时重建
  if (state.running) sinkcerts.reset();
  state.running = false;
  state.startedAt = null;
}

/** 设置变更后重启监听器（开关或端口变了才真的会重新监听） */
function restart() {
  if (state.running) stop();
  cfg = null;
  return start();
}

function status() {
  const rts = db.prepare('SELECT COUNT(*) AS c, COALESCE(SUM(hits), 0) AS h FROM sink_events').get();
  return {
    enabled: !!(cfg && cfg.enabled),
    running: state.running,
    tls_mode: cfg ? cfg.tlsMode : null,
    response: cfg ? cfg.response : null,
    bind_ip: cfg ? (cfg.bindIp || '0.0.0.0') : null,
    ports: state.listeners.map((x) => ({ port: x.port, error: x.error })),
    started_at: state.startedAt,
    last_flush_at: state.lastFlushAt,
    inflight: state.inflight,
    total_events: state.totalEvents,
    dropped_rows: state.droppedRows,
    agg_size: agg.size,
    rows: rts.c,
    hits: rts.h,
    last_error: state.lastError,
    capture: cfg ? { headers: cfg.captureHeaders, body: cfg.captureBody, body_bytes: cfg.bodyPreviewBytes } : null,
    certs: cfg && cfg.tlsMode === 'mitm' && state.running ? sinkcerts.caInfo() : null
  };
}

module.exports = { start, stop, restart, status, flush };
