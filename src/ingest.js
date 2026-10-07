'use strict';

const fs = require('fs');
const { db, settingGet, settingSet, recordJob } = require('./db');
const { ipOwnerTimeline, resolveOwnerAt, isRouterIp, routerIpList, addManualIp } = require('./devices');
const { DB_FILE } = require('./config');
const { httpError } = require('./httperr');

const FILTERED_RE = /^Filtered/i;

/** AdGuard 时间字符串（RFC3339Nano，纳秒） -> 毫秒时间戳，兼容 9 位小数 */
function parseTime(s) {
  if (!s) return NaN;
  let str = String(s).trim();
  str = str.replace(/(\.\d{3})\d+/, '$1');
  const t = Date.parse(str);
  return Number.isNaN(t) ? NaN : t;
}

function normalizeEntry(e) {
  if (!e) return null;
  const ts = parseTime(e.time || e.T);
  if (Number.isNaN(ts)) return null;
  const q = e.question || {};
  const domain = String(q.host || q.name || e.QH || '').trim();
  if (!domain) return null;
  const qtype = String(q.type || e.QT || '').trim();
  const clientIp = String(e.client || e.IP || e.client_ip || '').trim();
  const reason = e.reason || (e.Result && e.Result.Rules ? 'Filtered' : '') || '';
  const rule = e.rule || (e.Result && e.Result.Rules && e.Result.Rules[0] ? e.Result.Rules[0].Text || '' : '') || '';
  const status = e.status || '';
  const upstream = e.upstream || e.Upstream || '';
  let answer = '';
  if (Array.isArray(e.answer)) {
    answer = e.answer.slice(0, 5).map((a) => `${a.type || ''} ${a.value || ''}`.trim()).join('; ');
  } else if (typeof e.Answer === 'string') {
    answer = e.Answer;
  }
  let elapsedMs = parseFloat(e.elapsedMs);
  if (Number.isNaN(elapsedMs) && e.Elapsed !== undefined) elapsedMs = Number(e.Elapsed) / 1e6;
  if (Number.isNaN(elapsedMs)) elapsedMs = null;
  const blocked = FILTERED_RE.test(reason) || (!!rule && reason === '');
  return {
    ts, clientIp, domain, qtype, status, reason, rule,
    upstream, answer, elapsedMs, blocked: blocked ? 1 : 0
  };
}

function isIpLiteral(s) {
  const v = String(s || '');
  if (v.includes(':')) return true;                        // IPv6
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(v);                // IPv4
}

/** 生成"路由器本机地址"的 SQL 片段：本机流量必须与"无法归属的客户端"区分，否则会算成未归属、指标失真 */
function localClause(op) {
  const list = routerIpList();
  if (!list.length) return { sql: op === 'IN' ? '0' : '1', args: [] };
  return { sql: `client_ip ${op} (${list.map(() => '?').join(',')})`, args: list };
}

/** 设备显示名表达式：中文名 > 主机名 > 摄取时快照 > 设备#id，读取时实时取值（需把 query_log 别名为 q、devices 别名为 d） */
const DEVICE_LABEL = `COALESCE(NULLIF(d.name, ''), NULLIF(d.suggested_name, ''), q.device_name, '设备#' || q.device_id)`;

/** 构建"客户端 -> 设备"解析器：client 字段是源 IP 而非 MAC，用 IP 归属时间线折算成设备（兼容 client 返回客户端名称的情况） */
function buildResolvers() {
  const timeline = ipOwnerTimeline();
  const labels = new Map();
  const byName = new Map();
  for (const row of db.prepare('SELECT id, name, suggested_name, agh_synced_name FROM devices').all()) {
    labels.set(row.id, row.name || row.suggested_name || `设备#${row.id}`);
    for (const n of [row.name, row.suggested_name, row.agh_synced_name]) {
      const k = String(n || '').trim().toLowerCase();
      if (k && !byName.has(k)) byName.set(k, row.id);
    }
  }
  function resolve(clientStr, ts) {
    const s = String(clientStr || '').trim();
    if (!s) return { deviceId: null, label: null };
    if (isIpLiteral(s)) {
      const devId = resolveOwnerAt(timeline, s, ts);
      if (devId) return { deviceId: devId, label: labels.get(devId) || `设备#${devId}` };
      return { deviceId: null, label: isRouterIp(s) ? '路由器本机' : null };
    }
    const nameId = byName.get(s.toLowerCase());
    if (nameId) return { deviceId: nameId, label: labels.get(nameId) };
    return { deviceId: null, label: s };
  }
  return { resolve, ips: timeline.size };
}

/** 回溯修正：把已存在但因 IP 尚未观测到而未归属的记录，用最新时间线重新归属（查询日志与拦截事件一起修） */
function reResolveUnmapped({ maxRows = 20000 } = {}) {
  const unknown = localClause('NOT IN');
  const total = { fixed: 0, remaining: 0, scand: 0 };
  for (const table of ['query_log', 'sink_events']) {
    const pending = db.prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE device_id IS NULL AND ${unknown.sql}`)
      .get(...unknown.args).c;
    total.remaining += pending;
    if (!pending) continue;
    const { resolve } = buildResolvers();
    const rows = db.prepare(`SELECT id, ts, client_ip FROM ${table} WHERE device_id IS NULL AND ${unknown.sql} ORDER BY ts DESC LIMIT ?`)
      .all(...unknown.args, maxRows);
    const upd = db.prepare(`UPDATE ${table} SET device_id = ?, device_name = ? WHERE id = ?`);
    const labelCache = new Map();
    let fixed = 0;
    const tx = db.transaction(() => {
      for (const r of rows) {
        const { deviceId, label } = resolve(r.client_ip, r.ts);
        if (!deviceId) continue;
        let name = labelCache.get(deviceId);
        if (name === undefined) { name = label; labelCache.set(deviceId, name); }
        upd.run(deviceId, name, r.id);
        fixed++;
      }
    });
    tx();
    total.fixed += fixed;
    total.scand += rows.length;
    total.remaining -= fixed;
  }
  return total;
}

/** 增量摄取 AdGuard 查询日志到本地库，按 device_id 长期归并 */
async function ingestQueryLog(adg, { days = null, lookbackMin = null, maxPages = 300, pageSize = 1000 } = {}) {
  const startedAt = new Date().toISOString();
  const settings = { days: days ?? settingGet('backfill_days', 7), lookbackMin: lookbackMin ?? settingGet('ingest_lookback_min', 30) };
  const now = Date.now();
  const hardCutoff = now - settings.days * 86400 * 1000;
  const lastTs = settingGet('ingest.last_ts', 0) || 0;
  const incrementalCutoff = lastTs ? Math.max(hardCutoff, lastTs - settings.lookbackMin * 60 * 1000) : hardCutoff;

  const { resolve } = buildResolvers();
  const insert = db.prepare(`INSERT OR IGNORE INTO query_log
    (ts, client_ip, device_id, device_name, domain, qtype, status, reason, rule, upstream, answer, elapsed_ms, blocked)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);

  let inserted = 0, duplicates = 0, unresolved = 0, scanned = 0, pages = 0;
  let olderThan = null;
  let newestTs = lastTs;
  let reachedCutoff = false;
  let interrupted = null;      // 中途翻页失败的原因（此时已抓到部分数据）

  while (pages < maxPages) {
    const params = { limit: pageSize };
    if (olderThan) params.older_than = olderThan;
    let res;
    try {
      res = await adg.querylog(params);
    } catch (e) {
      if (pages === 0) throw e;
      interrupted = e;
      break;
    }
    const data = (res && res.data) || (Array.isArray(res) ? res : []);
    if (!data.length) break;
    pages++;
    scanned += data.length;

    const tx = db.transaction((rows) => {
      for (const raw of rows) {
        const e = normalizeEntry(raw);
        if (!e) continue;
        if (e.ts > newestTs) newestTs = e.ts;
        if (e.ts < incrementalCutoff) { reachedCutoff = true; continue; }
        const { deviceId, label } = resolve(e.clientIp, e.ts);
        // 唯一索引 + INSERT OR IGNORE 去重：命中去重时 changes 为 0，据此区分新增与重复跳过
        const info = insert.run(e.ts, e.clientIp, deviceId, label, e.domain, e.qtype, e.status, e.reason, e.rule, e.upstream, e.answer, e.elapsedMs, e.blocked);
        if (info.changes) inserted++; else duplicates++;
        // 只统计"客户端日志但无法归属到设备"的，本机(127.0.0.1/::1)不算未归属
        if (!deviceId && label !== '路由器本机') unresolved++;
      }
    });
    tx(data);

    // 让出事件循环：better-sqlite3 同步写库，不让出会把 HTTP 请求整体卡住
    await new Promise((resolve) => setImmediate(resolve));

    const last = data[data.length - 1];
    const lastTsRaw = last && (last.time || last.T);
    if (!lastTsRaw) break;
    if (reachedCutoff) break;
    // 官方分页约定：把本页的 oldest 作为下一页的 older_than；oldest 为空说明已到日志起点
    if (!res || !res.oldest) break;
    olderThan = res.oldest || lastTsRaw;
  }

  // 中途失败时不能用本轮的新时间戳推进游标：分页是从新往老翻的，一旦推进，
  // 中断点之后那段（更老、本轮没抓到）的日志会被下一轮的增量窗口直接跳过、永久丢失
  if (!interrupted && newestTs > lastTs) settingSet('ingest.last_ts', newestTs);
  const pruned = pruneQueryLog();
  // 只有本次确实出现了"无法归属"的新行，才需要跑全表回溯（避免空跑）
  const backfill = unresolved > 0 ? reResolveUnmapped() : { fixed: 0 };
  const unknown = localClause('NOT IN');
  const unmapped = db.prepare(`SELECT COUNT(*) AS c FROM query_log WHERE device_id IS NULL AND ${unknown.sql}`).get(...unknown.args).c;
  // 这里不清统计缓存：后台每 2 分钟就摄取一次，清了等于失效；新鲜度交给 60 秒 TTL
  const truncated = pages >= maxPages;
  const result = {
    inserted, duplicates, scanned, pages, pruned, truncated, unresolved,
    backfilled: backfill.fixed, unmappedTotal: unmapped,
    newest: newestTs ? new Date(newestTs).toISOString() : null
  };

  // 中途中断不能记成 success：数据只落了一部分，游标也没推进。
  // 抛给上层（jobs.guard）写进任务记录，消息里带上已落库的条数，便于判断缺了多少。
  if (interrupted) {
    throw new Error(
      `摄取中断于第 ${pages + 1} 页：${interrupted.message}`
      + `（本轮已落库 ${inserted} 条，游标未推进，下次会从断点继续抓）`
    );
  }

  recordJob('ingest', 'success',
    `新增 ${inserted} 条、重复跳过 ${duplicates} 条（扫描 ${scanned}），回溯归属 ${backfill.fixed} 条，本次未归属 ${unresolved} 条（库内累计 ${unmapped} 条），清理 ${pruned} 条`
    + (truncated ? `；注意：已达单次抓取上限（${maxPages} 页），更早的历史本轮未抓取` : ''),
    result, startedAt);
  return result;
}

function pruneQueryLog() {
  const days = Number(settingGet('log_retention_days', 30)) || 30;
  if (days <= 0) return 0;
  const cutoff = Date.now() - days * 86400 * 1000;
  return db.prepare('DELETE FROM query_log WHERE ts < ?').run(cutoff).changes;
}

function pruneIpHistory() {
  const days = Number(settingGet('ip_history_retention_days', 90)) || 0;
  if (days <= 0) return 0;
  const cutoff = new Date(Date.now() - days * 86400 * 1000).toISOString();
  return db.prepare('DELETE FROM device_ips WHERE last_seen < ? AND is_static = 0').run(cutoff).changes;
}

/** 拦截流量分析事件按自己的保留期清理（数据量通常大于 DNS 日志，所以独立配置） */
function pruneSinkEvents() {
  const days = Number(settingGet('sink_retention_days', 14)) || 0;
  if (days <= 0) return 0;
  const cutoff = Date.now() - days * 86400 * 1000;
  return db.prepare('DELETE FROM sink_events WHERE last_ts < ?').run(cutoff).changes;
}

/* ------------------------------ 统计 ------------------------------ */

function rangeToMs(range) {
  const map = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };
  return map[range] || map['24h'];
}

/* ------------------------- 统计缓存 ------------------------- */

/** 轻量 TTL 缓存：前端会反复拉同样的统计数字（切页加每 30 秒轮询），缓存后重复访问几乎瞬时完成 */
const statsCache = new Map();
// 统计缓存有效期 60 秒；用户主动操作（改名/指派等）会立即清缓存，见 routes.js 的写操作钩子
const STATS_TTL_MS = 60000;
function cached(key, ttlMs, fn) {
  const now = Date.now();
  const hit = statsCache.get(key);
  if (hit && now - hit.at < ttlMs) return hit.value;
  const value = fn();
  statsCache.set(key, { at: now, value });
  return value;
}

/** 有数据写入（摄取/采集/指派/清理）后调用，让统计立即反映最新结果 */
function invalidateStats() { statsCache.clear(); }

/** 按设备聚合（含设备名）。dashboard 的 topDevices 与 anomalies 共用，只算一次 */
function deviceAgg(range) {
  return cached(`devagg|${range}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    // 先只按 device_id 聚合（可走覆盖索引），避免在整表上做 JOIN
    const rows = db.prepare(`SELECT device_id, COUNT(1) AS total, SUM(blocked) AS blocked
      FROM query_log WHERE ts >= ? AND ts <= ? AND device_id IS NOT NULL
      GROUP BY device_id ORDER BY total DESC`).all(from, to);
    if (!rows.length) return [];
    const ids = rows.map((r) => r.device_id);
    const labels = new Map();
    const ph = ids.map(() => '?').join(',');
    for (const d of db.prepare(`SELECT id, COALESCE(NULLIF(name,''), NULLIF(suggested_name,''), '设备#' || id) AS label
        FROM devices WHERE id IN (${ph})`).all(...ids)) {
      labels.set(d.id, d.label);
    }
    return rows.map((r) => ({
      device_id: r.device_id,
      device_name: labels.get(r.device_id) || `设备#${r.device_id}`,
      total: r.total,
      blocked: r.blocked || 0
    }));
  });
}

/** 由设备聚合结果派生"异常画像"，避免再全窗口扫一遍 */
function buildAnomalies(rows, range) {
  const minutes = Math.max(1, rangeToMs(range) / 60000);
  const out = [];
  for (const r of rows) {
    const perMinute = r.total / minutes;
    const flags = [];
    if (r.total >= 1000 && r.blocked === 0) flags.push('零拦截');
    if (perMinute >= 5) flags.push(`频率 ${perMinute.toFixed(1)}/分钟`);
    if (!flags.length) continue;
    out.push({
      device_id: r.device_id, device_name: r.device_name, total: r.total, blocked: r.blocked,
      blocked_rate: r.total ? +(r.blocked / r.total * 100).toFixed(1) : 0,
      per_minute: +perMinute.toFixed(1), flags
    });
  }
  return out;
}

function overview(range = '24h', { root = false } = {}) {
  return cached(`ov|${range}|${root}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const localIn = localClause('IN');
    const localNotIn = localClause('NOT IN');
    // 一次扫描同时算出 总数/拦截/本机/未归属（原来是 5 次全窗口扫描）
    const agg = db.prepare(`SELECT
        COUNT(1) AS total,
        COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) AS blocked,
        COALESCE(SUM(CASE WHEN ${localIn.sql} THEN 1 ELSE 0 END), 0) AS local,
        COALESCE(SUM(CASE WHEN device_id IS NULL AND ${localNotIn.sql} THEN 1 ELSE 0 END), 0) AS unmapped
      FROM query_log WHERE ts >= ? AND ts <= ?`)
      .get(...localIn.args, ...localNotIn.args, from, to);
    const total = agg.total;
    const blocked = agg.blocked;
    const devices = db.prepare('SELECT COUNT(*) AS c FROM devices').get().c;
    const named = db.prepare("SELECT COUNT(*) AS c FROM devices WHERE name IS NOT NULL AND name <> ''").get().c;
    // AdGuard 的 /control/clients 不返回 uid（配置文件里才有），不能用 agh_uid 计数，故按 agh_synced_name 统计
    const matched = db.prepare('SELECT COUNT(*) AS c FROM devices WHERE agh_synced_name IS NOT NULL').get().c;
    const active24 = db.prepare('SELECT COUNT(*) AS c FROM devices WHERE last_seen >= ?').get(new Date(to - 86400e3).toISOString()).c;
    const bucket = range === '1h' ? 5 * 60e3 : (range === '24h' ? 3600e3 : 86400e3);
    const trend = db.prepare(`SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, COUNT(1) AS total, SUM(blocked) AS blocked
      FROM query_log WHERE ts >= ? AND ts <= ? GROUP BY bucket ORDER BY bucket`).all(bucket, bucket, from, to);
    const perDevice = deviceAgg(range);          // topDevices 与 anomalies 共用同一次聚合
    const topBlocked = topDomains({ range, blocked: true, limit: 15, root });
    const topAllowed = topDomains({ range, blocked: false, limit: 15, root });
    return {
      range, from, to, total, blocked,
      blocked_rate: total ? +(blocked / total * 100).toFixed(1) : 0,
      local: agg.local, unmapped: agg.unmapped, devices, named, matched, active24,
      // SQL 里的 bucket 已经是"对齐后的毫秒时间戳"，前端直接当时间用，不能再乘一次 bucket
      trend: trend.map((t) => ({ t: t.bucket, total: t.total, blocked: t.blocked || 0 })),
      topDevices: perDevice.slice(0, 10),
      // 拦截 Top 设备：复用同一次设备聚合，只换排序口径（被拦截次数降序，零拦截的不上榜）
      topBlockedDevices: perDevice.filter((r) => r.blocked > 0)
        .sort((a, b) => b.blocked - a.blocked || b.total - a.total).slice(0, 10),
      anomalies: buildAnomalies(perDevice, range),
      topBlocked, topAllowed,
      last_ingest: settingGet('ingest.last_ts', 0)
    };
  });
}

function deviceStats(range = '24h') {
  const to = Date.now();
  const from = to - rangeToMs(range);
  return db.prepare(`SELECT q.device_id AS device_id, MAX(${DEVICE_LABEL}) AS device_name, q.client_ip AS client_ip,
      COUNT(*) AS total, SUM(q.blocked) AS blocked, COUNT(DISTINCT q.domain) AS domains,
      MIN(q.ts) AS first_ts, MAX(q.ts) AS last_ts
    FROM query_log q LEFT JOIN devices d ON d.id = q.device_id
    WHERE q.ts >= ? AND q.ts <= ?
    GROUP BY q.device_id, q.client_ip ORDER BY total DESC`).all(from, to);
}

/** deviceId 过滤条件的统一构造：数字=某台设备；'local'=路由器本机；'__none__'/'none'=未归属（不含本机） */
function deviceFilter(deviceId) {
  const cond = [];
  const args = [];
  if (deviceId === 'local') {
    const w = localClause('IN');
    cond.push(w.sql); args.push(...w.args);
  } else if (deviceId === '__none__' || deviceId === 'none') {
    cond.push('device_id IS NULL');
    const w = localClause('NOT IN');
    cond.push(w.sql); args.push(...w.args);
  } else if (deviceId) {
    cond.push('device_id = ?');
    args.push(Number(deviceId));
  }
  return { cond, args };
}

// 常见二级公共后缀（用于"按主域名聚合"时的近似 eTLD 判断，不追求完备）
const SECOND_LEVEL = new Set([
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'com.hk', 'com.tw', 'com.au',
  'com.jp', 'co.jp', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.kr', 'com.sg', 'com.my',
  'com.br', 'com.mx', 'com.tr', 'com.vn', 'com.th', 'com.id', 'com.ph', 'com.pk',
  'com.eg', 'com.sa', 'com.ar', 'com.co', 'com.pe', 'com.ua', 'com.ru', 'co.nz',
  'co.in', 'co.za', 'net.uk'
]);

/** 取主域名（近似注册域）：a.b.example.com -> example.com；a.example.com.cn -> example.com.cn */
function rootDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return h;
  if (h.includes(':')) return h;                              // IPv6
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;           // IPv4
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  if (SECOND_LEVEL.has(last2)) return parts.slice(-3).join('.');
  return last2;
}

function topDomains(opts = {}) {
  const { range = '24h', blocked = null, deviceId = null, limit = 30, root = false } = opts;
  return cached(`top|${range}|${blocked}|${deviceId}|${limit}|${root}`, STATS_TTL_MS,
    () => computeTopDomains({ range, blocked, deviceId, limit, root }));
}

function computeTopDomains({ range, blocked, deviceId, limit, root }) {
  const to = Date.now();
  const from = to - rangeToMs(range);
  const cond = ['ts >= ?', 'ts <= ?'];
  const args = [from, to];
  if (blocked === true) cond.push('blocked = 1');
  if (blocked === false) cond.push('blocked = 0');
  const f = deviceFilter(deviceId);
  cond.push(...f.cond); args.push(...f.args);
  // 按主域名聚合时先多取一些明细，再在内存里合并（取近似值，够用且不引入额外依赖）
  const fetch = root ? Math.max(limit * 40, 1000) : limit;
  const rows = db.prepare(`SELECT domain, COUNT(*) AS c, SUM(blocked) AS blocked FROM query_log
    WHERE ${cond.join(' AND ')} GROUP BY domain ORDER BY c DESC LIMIT ?`).all(...args, fetch);
  if (!root) return rows;
  const agg = new Map();
  for (const r of rows) {
    const k = rootDomain(r.domain);
    const cur = agg.get(k) || { domain: k, c: 0, blocked: 0 };
    cur.c += r.c;
    cur.blocked += r.blocked || 0;
    agg.set(k, cur);
  }
  return [...agg.values()].sort((a, b) => b.c - a.c).slice(0, limit);
}

function listLogs({ deviceId = null, blocked = null, domain = '', clientIp = '', from = null, to = null, page = 1, size = 50 } = {}) {
  const cond = [];
  const args = [];
  const df = deviceFilter(deviceId);
  cond.push(...df.cond); args.push(...df.args);
  if (blocked === true) cond.push('blocked = 1');
  if (blocked === false) cond.push('blocked = 0');
  if (domain) { cond.push('domain LIKE ?'); args.push(`%${domain}%`); }
  if (clientIp) { cond.push('client_ip = ?'); args.push(clientIp); }
  if (from) { cond.push('ts >= ?'); args.push(Number(from)); }
  if (to) { cond.push('ts <= ?'); args.push(Number(to)); }
  const where = cond.length ? 'WHERE ' + cond.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS c FROM query_log ${where}`).get(...args).c;
  const p = Math.max(1, Number(page) || 1);
  const s = Math.min(500, Math.max(1, Number(size) || 50));
  const rows = db.prepare(`SELECT q.id, q.ts, q.client_ip, q.device_id, ${DEVICE_LABEL} AS device_name,
      q.domain, q.qtype, q.status, q.reason, q.rule, q.upstream, q.answer, q.elapsed_ms, q.blocked
    FROM query_log q LEFT JOIN devices d ON d.id = q.device_id
    ${where} ORDER BY q.ts DESC LIMIT ? OFFSET ?`).all(...args, s, (p - 1) * s);
  return { total, page: p, size: s, rows };
}

/* ------------------------- 未归属日志处理 ------------------------- */

/** 按客户端 IP 汇总"未能归属到设备"的日志（不含路由器本机），用于一键指派 */
function unmappedIps({ range = '24h', limit = 100 } = {}) {
  const to = Date.now();
  const from = to - rangeToMs(range);
  const notLocal = localClause('NOT IN');
  return db.prepare(`SELECT client_ip AS ip, COUNT(*) AS c, MIN(ts) AS first_ts, MAX(ts) AS last_ts,
      MIN(domain) AS sample_domain
    FROM query_log
    WHERE ts >= ? AND ts <= ? AND device_id IS NULL AND ${notLocal.sql}
    GROUP BY client_ip ORDER BY c DESC LIMIT ?`).all(from, to, ...notLocal.args, limit);
}

/** 把某个 IP 指派给设备：先写入 IP 归属，再把该 IP 的历史未归属日志一并改判 */
function assignIp(ip, deviceId) {
  const addr = String(ip || '').trim();
  if (!addr) throw httpError(400, 'IP 不能为空');
  addManualIp(deviceId, addr, {});
  const { resolve } = buildResolvers();      // 必须在写入 IP 之后重建，时间线才包含它
  const rows = db.prepare('SELECT id, ts FROM query_log WHERE device_id IS NULL AND client_ip = ?').all(addr);
  const upd = db.prepare('UPDATE query_log SET device_id = ?, device_name = ? WHERE id = ?');
  let reassigned = 0;
  const tx = db.transaction(() => {
    for (const r of rows) {
      const { deviceId: did, label } = resolve(addr, r.ts);
      if (!did) continue;
      upd.run(did, label, r.id);
      reassigned++;
    }
  });
  tx();
  recordJob('assign_ip', 'success', `将 ${addr} 指派给设备 #${deviceId}，回填 ${reassigned} 条日志`, { ip: addr, deviceId, reassigned });
  return { ip: addr, deviceId: Number(deviceId), reassigned };
}

/** 清理"未能归属"的历史日志（不含路由器本机）。这些行通常是 IPv6 临时地址已消失、无法回溯的残留 */
function pruneUnmapped() {
  const notLocal = localClause('NOT IN');
  const deleted = db.prepare(`DELETE FROM query_log WHERE device_id IS NULL AND ${notLocal.sql}`).run(...notLocal.args).changes;
  recordJob('prune_unmapped', 'success', `清理未归属日志 ${deleted} 条`, { deleted });
  return { deleted };
}

/** 导出日志（CSV 用），有行数上限避免内存爆掉 */
function exportLogs({ deviceId = null, blocked = null, domain = '', clientIp = '', from = null, to = null, limit = 50000 } = {}) {
  const cond = [];
  const args = [];
  const df = deviceFilter(deviceId);
  cond.push(...df.cond); args.push(...df.args);
  if (blocked === true) cond.push('blocked = 1');
  if (blocked === false) cond.push('blocked = 0');
  if (domain) { cond.push('domain LIKE ?'); args.push(`%${domain}%`); }
  if (clientIp) { cond.push('client_ip = ?'); args.push(clientIp); }
  if (from) { cond.push('ts >= ?'); args.push(Number(from)); }
  if (to) { cond.push('ts <= ?'); args.push(Number(to)); }
  const where = cond.length ? 'WHERE ' + cond.join(' AND ') : '';
  return db.prepare(`SELECT q.ts AS ts, q.client_ip AS client_ip, ${DEVICE_LABEL} AS device_name,
      q.domain AS domain, q.qtype AS qtype, q.status AS status, q.reason AS reason,
      q.rule AS rule, q.upstream AS upstream, q.blocked AS blocked
    FROM query_log q LEFT JOIN devices d ON d.id = q.device_id
    ${where} ORDER BY q.ts DESC LIMIT ?`).all(...args, limit);
}

/* ------------------------- 拦截流量分析（sinkhole）查询与统计 ------------------------- */

/** 与查询日志共用同一套设备归并口径（device_id 来自 IP 归属时间线）；hits 是去重窗口内合并的次数，统计一律用 SUM(hits) */

const SINK_SELECT = `q.id, q.ts, q.last_ts, q.hits, q.client_ip, q.client_port, q.device_id,
  ${DEVICE_LABEL} AS device_name, q.proto, q.lport, q.host, q.method, q.path, q.query, q.http_ver,
  q.ua, q.referer, q.headers_json, q.body_bytes, q.body_preview,
  q.content_type, q.content_encoding, q.charset, q.body_kind, q.body_fields,
  q.tls_version, q.tls_cipher,
  q.tls_client_ciphers, q.ja3, q.ja4, q.alpn, q.tls_note, q.decrypted, q.outcome, q.duration_ms`;

/** 把前端的筛选项折成 WHERE 片段（与 listLogs 的写法保持一致；from/to 优先于 range） */
function sinkWhere(opts = {}) {
  const {
    deviceId = null, host = '', proto = '', lport = null, decrypted = null,
    ua = '', queryStr = '', outcome = '', ja4 = '', bodyKind = '', body = '',
    from = null, to = null, range = null
  } = opts;
  const cond = [];
  const args = [];
  const df = deviceFilter(deviceId);
  cond.push(...df.cond); args.push(...df.args);
  if (host) { cond.push('host LIKE ?'); args.push(`%${host}%`); }
  if (ua) { cond.push('ua LIKE ?'); args.push(`%${ua}%`); }
  if (queryStr) { cond.push('query LIKE ?'); args.push(`%${queryStr}%`); }
  if (outcome) { cond.push('outcome = ?'); args.push(outcome); }
  if (ja4) { cond.push('ja4 = ?'); args.push(ja4); }
  if (proto) { cond.push('proto = ?'); args.push(proto); }
  if (lport) { cond.push('lport = ?'); args.push(Number(lport)); }
  if (bodyKind) { cond.push('body_kind = ?'); args.push(bodyKind); }
  // 正文搜索同时覆盖原文预览与抽出的字段：凭据常常只在字段里出现（例如 JSON 的 pwd）
  if (body) { cond.push('(body_preview LIKE ? OR body_fields LIKE ?)'); args.push(`%${body}%`, `%${body}%`); }
  if (decrypted === true) cond.push('decrypted = 1');
  if (decrypted === false) cond.push('decrypted = 0');
  const fromTs = from ? Number(from) : (range ? Date.now() - rangeToMs(range) : null);
  const toTs = to ? Number(to) : (range && !from ? Date.now() : null);
  if (fromTs) { cond.push('ts >= ?'); args.push(fromTs); }
  if (toTs) { cond.push('ts <= ?'); args.push(toTs); }
  return { sql: cond.length ? 'WHERE ' + cond.join(' AND ') : '', args };
}

/** 概览：总量、设备/域名覆盖、解密比例、趋势、协议分布 */
function sinkOverview(range = '24h') {
  return cached(`sinkov|${range}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const base = 'FROM sink_events WHERE ts >= ? AND ts <= ?';
    // 明文 HTTP 也属于"有内容"，只有 proto=tls/https 且未解密的才算"仅 SNI"，否则解密率会失真
    const tot = db.prepare(`SELECT COUNT(1) AS events, COALESCE(SUM(hits), 0) AS hits,
        COUNT(DISTINCT host) AS hosts,
        COALESCE(SUM(CASE WHEN device_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS mapped,
        COALESCE(SUM(CASE WHEN decrypted = 1 OR proto = 'http' THEN 1 ELSE 0 END), 0) AS with_content,
        COALESCE(SUM(CASE WHEN decrypted = 1 OR proto = 'http' THEN hits ELSE 0 END), 0) AS with_content_hits,
        COALESCE(SUM(CASE WHEN decrypted = 1 THEN 1 ELSE 0 END), 0) AS decrypted,
        COALESCE(SUM(CASE WHEN proto IN ('tls', 'https') AND decrypted = 0 THEN 1 ELSE 0 END), 0) AS sni_only
      ${base}`).get(from, to);
    const devices = db.prepare(`SELECT COUNT(DISTINCT device_id) AS c ${base} AND device_id IS NOT NULL`).get(from, to).c;
    // 桶宽跟随区间：1 小时看分钟，7/30 天看天，其余看小时
    const bucket = range === '1h' ? 60000 : (range === '7d' || range === '30d' ? 86400000 : 3600000);
    const trend = db.prepare(`SELECT CAST(ts / ? AS INTEGER) * ? AS bucket,
        COALESCE(SUM(hits), 0) AS c,
        COALESCE(SUM(CASE WHEN decrypted = 1 OR proto = 'http' THEN hits ELSE 0 END), 0) AS content
      ${base} GROUP BY bucket ORDER BY bucket`).all(bucket, bucket, from, to);
    const protos = db.prepare(`SELECT COALESCE(proto, '?') AS proto, COUNT(1) AS events,
        COALESCE(SUM(hits), 0) AS hits, COUNT(DISTINCT host) AS hosts
      ${base} GROUP BY proto ORDER BY hits DESC`).all(from, to);
    return { ...tot, devices, trend, protos, range };
  });
}

/** 按设备聚合（Top 设备） */
function sinkDeviceStats(range = '24h') {
  return cached(`sinkdev|${range}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const rows = db.prepare(`SELECT device_id, COUNT(1) AS events, COALESCE(SUM(hits), 0) AS hits,
        COUNT(DISTINCT host) AS hosts,
        COALESCE(SUM(CASE WHEN decrypted = 1 THEN 1 ELSE 0 END), 0) AS decrypted
      FROM sink_events WHERE ts >= ? AND ts <= ? AND device_id IS NOT NULL
      GROUP BY device_id ORDER BY hits DESC`).all(from, to);
    if (!rows.length) return [];
    const ids = rows.map((r) => r.device_id);
    const labels = new Map();
    const ph = ids.map(() => '?').join(',');
    for (const d of db.prepare(`SELECT id, COALESCE(NULLIF(name,''), NULLIF(suggested_name,''), '设备#' || id) AS label
        FROM devices WHERE id IN (${ph})`).all(...ids)) {
      labels.set(d.id, d.label);
    }
    return rows.map((r) => ({
      device_id: r.device_id,
      device_name: labels.get(r.device_id) || `设备#${r.device_id}`,
      events: r.events, hits: r.hits, hosts: r.hosts, decrypted: r.decrypted
    }));
  });
}

/** 按"被拦截后实际被访问的主机名"聚合 */
function sinkHostStats({ range = '24h', deviceId = null, proto = '', limit = 50 } = {}) {
  return cached(`sinkhost|${range}|${deviceId || ''}|${proto}|${limit}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const cond = ['ts >= ?', 'ts <= ?', 'host IS NOT NULL'];
    const args = [from, to];
    if (deviceId) { cond.push('device_id = ?'); args.push(Number(deviceId)); }
    if (proto) { cond.push('proto = ?'); args.push(proto); }
    return db.prepare(`SELECT host, COUNT(1) AS events, COALESCE(SUM(hits), 0) AS hits,
        COUNT(DISTINCT device_id) AS devices, COUNT(DISTINCT lport) AS ports,
        MAX(last_ts) AS last_ts
      FROM sink_events WHERE ${cond.join(' AND ')}
      GROUP BY host ORDER BY hits DESC LIMIT ?`).all(...args, Math.min(500, Math.max(1, Number(limit) || 50)));
  });
}

/** 按 User-Agent 聚合：同一 App 常把上报分散到多个域名，靠 UA 反而更容易看清"是谁在报" */
function sinkUaStats({ range = '24h', deviceId = null, proto = '', limit = 50 } = {}) {
  return cached(`sinkua|${range}|${deviceId || ''}|${proto}|${limit}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const cond = ['ts >= ?', 'ts <= ?', 'ua IS NOT NULL', "ua <> ''"];
    const args = [from, to];
    if (deviceId) { cond.push('device_id = ?'); args.push(Number(deviceId)); }
    if (proto) { cond.push('proto = ?'); args.push(proto); }
    return db.prepare(`SELECT ua, COUNT(1) AS events, COALESCE(SUM(hits), 0) AS hits,
        COUNT(DISTINCT device_id) AS devices, COUNT(DISTINCT host) AS hosts, MAX(last_ts) AS last_ts
      FROM sink_events WHERE ${cond.join(' AND ')}
      GROUP BY ua ORDER BY hits DESC LIMIT ?`).all(...args, Math.min(500, Math.max(1, Number(limit) || 50)));
  });
}

/** 按 JA4 指纹聚合：仅 SNI 的记录也能把"同一个 App 的多个域名"串起来 */
function sinkFpStats({ range = '24h', deviceId = null, proto = '', limit = 50 } = {}) {
  return cached(`sinkfp|${range}|${deviceId || ''}|${proto}|${limit}`, STATS_TTL_MS, () => {
    const to = Date.now();
    const from = to - rangeToMs(range);
    const cond = ['ts >= ?', 'ts <= ?', 'ja4 IS NOT NULL', "ja4 <> ''"];
    const args = [from, to];
    if (deviceId) { cond.push('device_id = ?'); args.push(Number(deviceId)); }
    if (proto) { cond.push('proto = ?'); args.push(proto); }
    return db.prepare(`SELECT ja4, MIN(ja3) AS ja3_sample, COUNT(1) AS events, COALESCE(SUM(hits), 0) AS hits,
        COUNT(DISTINCT device_id) AS devices, COUNT(DISTINCT host) AS hosts, MAX(last_ts) AS last_ts
      FROM sink_events WHERE ${cond.join(' AND ')}
      GROUP BY ja4 ORDER BY hits DESC LIMIT ?`).all(...args, Math.min(500, Math.max(1, Number(limit) || 50)));
  });
}

/** 明细列表（分页） */
function sinkListEvents(opts = {}) {
  const w = sinkWhere(opts);
  const total = db.prepare(`SELECT COUNT(*) AS c FROM sink_events q ${w.sql}`).get(...w.args).c;
  const p = Math.max(1, Number(opts.page) || 1);
  const s = Math.min(500, Math.max(1, Number(opts.size) || 50));
  const rows = db.prepare(`SELECT ${SINK_SELECT}
    FROM sink_events q LEFT JOIN devices d ON d.id = q.device_id
    ${w.sql} ORDER BY q.last_ts DESC LIMIT ? OFFSET ?`).all(...w.args, s, (p - 1) * s);
  return { total, page: p, size: s, rows };
}

/** 导出用（有行数上限，避免内存爆掉） */
function sinkExport(opts = {}) {
  const w = sinkWhere(opts);
  return db.prepare(`SELECT ${SINK_SELECT}
    FROM sink_events q LEFT JOIN devices d ON d.id = q.device_id
    ${w.sql} ORDER BY q.last_ts DESC LIMIT ?`).all(...w.args, Math.min(50000, Math.max(1, Number(opts.limit) || 50000)));
}

/** 按客户端 IP 汇总未能归属到设备的连接记录（不含路由器本机） */
function sinkUnmappedIps({ range = '24h', limit = 100 } = {}) {
  const to = Date.now();
  const from = to - rangeToMs(range);
  const notLocal = localClause('NOT IN');
  return db.prepare(`SELECT client_ip AS ip, COUNT(*) AS c, COALESCE(SUM(hits), 0) AS hits,
      MIN(ts) AS first_ts, MAX(last_ts) AS last_ts, MIN(host) AS sample_host
    FROM sink_events
    WHERE ts >= ? AND ts <= ? AND device_id IS NULL AND ${notLocal.sql}
    GROUP BY client_ip ORDER BY c DESC LIMIT ?`).all(from, to, ...notLocal.args, limit);
}

/** 把某个 IP 指派给设备，并回填它此前未归属的连接记录 */
function sinkAssignIp(ip, deviceId) {
  const addr = String(ip || '').trim();
  if (!addr) throw httpError(400, 'IP 不能为空');
  addManualIp(deviceId, addr, {});
  const { resolve } = buildResolvers();      // 必须在写入 IP 之后重建，时间线才包含它
  const rows = db.prepare('SELECT id, ts FROM sink_events WHERE device_id IS NULL AND client_ip = ?').all(addr);
  const upd = db.prepare('UPDATE sink_events SET device_id = ?, device_name = ? WHERE id = ?');
  let reassigned = 0;
  const tx = db.transaction(() => {
    for (const r of rows) {
      const { deviceId: did, label } = resolve(addr, r.ts);
      if (!did) continue;
      upd.run(did, label, r.id);
      reassigned++;
    }
  });
  tx();
  invalidateStats();
  recordJob('sink_assign_ip', 'success', `将 ${addr} 指派给设备 #${deviceId}，回填 ${reassigned} 条连接记录`, { ip: addr, deviceId, reassigned });
  return { ip: addr, deviceId: Number(deviceId), reassigned };
}

/** 清理未能归属的连接记录 */
function sinkPruneUnmapped() {
  const notLocal = localClause('NOT IN');
  const deleted = db.prepare(`DELETE FROM sink_events WHERE device_id IS NULL AND ${notLocal.sql}`).run(...notLocal.args).changes;
  invalidateStats();
  recordJob('sink_prune_unmapped', 'success', `清理未归属连接记录 ${deleted} 条`, { deleted });
  return { deleted };
}

/** 清空全部连接记录（用户主动操作，需二次确认） */
function sinkClear() {
  const deleted = db.prepare('DELETE FROM sink_events').run().changes;
  invalidateStats();
  recordJob('sink_clear', 'success', `清空连接记录 ${deleted} 条`, { deleted });
  return { deleted };
}

/* ------------------------- 异常画像 / 运维 ------------------------- */

/** 异常画像：复用 deviceAgg 的结果，不再单独全窗口扫描 */
function anomalies({ range = '24h' } = {}) {
  return buildAnomalies(deviceAgg(range), range);
}

/** 数据库体积与行数（供设置页展示）。全时段未归属统计要扫全表，故缓存 60 秒 */
function dbInfo() {
  return cached('dbinfo', 60000, () => {
    const size = fs.existsSync(DB_FILE) ? fs.statSync(DB_FILE).size : 0;
    const notLocal = localClause('NOT IN');
    return {
      fileMB: +(size / 1048576).toFixed(1),
      rows: db.prepare('SELECT COUNT(1) AS c FROM query_log').get().c,
      sink_rows: db.prepare('SELECT COUNT(1) AS c FROM sink_events').get().c,
      devices: db.prepare('SELECT COUNT(1) AS c FROM devices').get().c,
      unmapped: db.prepare(`SELECT COUNT(1) AS c FROM query_log WHERE device_id IS NULL AND ${notLocal.sql}`).get(...notLocal.args).c,
      retentionDays: Number(settingGet('log_retention_days', 30)) || 30,
      lastVacuum: settingGet('vacuum.last_ts', 0)
    };
  });
}

/** 回收 SQLite 空间（删除行后文件不会自动缩小）。VACUUM 需要独占访问，会短暂阻塞读写。 */
function vacuum() {
  const before = fs.existsSync(DB_FILE) ? fs.statSync(DB_FILE).size : 0;
  db.exec('VACUUM');
  const after = fs.existsSync(DB_FILE) ? fs.statSync(DB_FILE).size : 0;
  settingSet('vacuum.last_ts', Date.now());
  recordJob('vacuum', 'success',
    `数据库整理完成：${(before / 1048576).toFixed(1)} MB → ${(after / 1048576).toFixed(1)} MB`,
    { before, after });
  return { beforeMB: +(before / 1048576).toFixed(1), afterMB: +(after / 1048576).toFixed(1) };
}

module.exports = {
  ingestQueryLog, pruneQueryLog, pruneIpHistory, pruneSinkEvents, reResolveUnmapped, buildResolvers,
  overview, deviceStats, topDomains, listLogs, parseTime, normalizeEntry, invalidateStats,
  unmappedIps, assignIp, pruneUnmapped, exportLogs, anomalies, dbInfo, vacuum, rootDomain,
  sinkOverview, sinkDeviceStats, sinkHostStats, sinkUaStats, sinkFpStats, sinkListEvents, sinkExport,
  sinkUnmappedIps, sinkAssignIp, sinkPruneUnmapped, sinkClear
};
