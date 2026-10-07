'use strict';

/**
 * AdGuard Home 客户端管理（新建 / 重算 ids / 批量同步 / 定时自动同步 / 删除）。
 * 单次操作先出差异预览，确认后才提交；自动同步只更新 ids。
 *
 * 写入规则：
 *   1. ids 只写主 MAC、当前 IPv4，以及仍在产生的 IPv6；链路本地、回环、组播不写，窗口读不到退回 24 小时。
 *   2. IPv6 以 AdGuard 的统计保留时长（/control/stats/config 的 interval）为窗口。
 *   3. 只处理能唯一归属到一台设备的客户端，其余只读。
 *   4. 写入前做完整 diff，未明确无意义的项默认保留。
 *   5. 写入前强校验（含主 MAC、合法去重、不超 MAX_IDS），IPv6 按 RFC 5952 规范化。
 */

const { firstEnabled, adguardClient } = require('./connections');
const { settingGet, settingSet, recordJob, db } = require('./db');
const D = require('./devices');
const net = require('net');

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
const MAX_IDS = 64;       // 单个客户端的 ids 项数上限（MAC + IPv4 + 若干 IPv6），防异常膨胀
const BATCH_LIMIT = 50;   // 单轮批量/自动同步最多处理多少个客户端
// IPv6 的取舍窗口：跟随 AdGuard 的"统计保留时长"，读不到时退回 24 小时
const DEFAULT_SYNC_WINDOW_MS = 24 * 3600 * 1000;
const WINDOW_CACHE_MS = 10 * 60 * 1000;      // 同一个进程内多久重新读一次 AdGuard 的窗口设置
const WINDOW_SETTING_KEY = 'agh_stats_interval_ms';

function lc(s) { return String(s === null || s === undefined ? '' : s).trim().toLowerCase(); }

function isMac(s) { return MAC_RE.test(String(s)); }

function isIpv4(s) {
  const p = String(s).split('.');
  if (p.length !== 4) return false;
  return p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}

/** 合法的 IPv6（用 net.isIPv6 判断，能识别 :: 缩写等形式） */
function isV6(s) { return net.isIPv6(String(s)); }

/** 链路本地 fe80::/10：只在本链路有效，写给 AdGuard 没有意义，必须排除 */
function isLinkLocalV6(s) {
  const v = lc(s);
  if (!isV6(v)) return false;
  const first = v.split(':')[0];
  if (!first) return false;                     // 以 "::" 开头的（如 ::1）另判
  const n = parseInt(first, 16);
  return Number.isFinite(n) && (n & 0xffc0) === 0xfe80;
}

function isLoopbackV6(s) { return lc(s) === '::1'; }

/** ff00::/8 组播地址同样不该写进客户端 ids */
function isMulticastV6(s) {
  const v = lc(s);
  if (!isV6(v)) return false;
  const first = v.split(':')[0];
  const n = parseInt(first, 16);
  return Number.isFinite(n) && (n & 0xff00) === 0xff00;
}

/** 是否值得写进 AdGuard 的 IPv6（排除链路本地 / 回环 / 组播） */
function isWritableV6(s) { return isV6(s) && !isLinkLocalV6(s) && !isLoopbackV6(s) && !isMulticastV6(s); }

/**
 * IPv6 规范化（RFC 5952：小写、去前导零、最长的一段零压缩成 ::）。
 * AdGuard 写入后会按同一规则规范化存储，不规范化则两边字符串不相等，每次同步都会删了再加。
 */
function canonV6(s) {
  const v = lc(s);
  if (!isV6(v)) return v;
  let addr = v;
  const pct = addr.indexOf('%');
  if (pct >= 0) addr = addr.slice(0, pct);            // 去掉 zone id（fe80::1%eth0）
  let head = [];
  let tail = [];
  if (addr.includes('::')) {
    const parts = addr.split('::');
    if (parts.length !== 2) return v;
    head = parts[0] ? parts[0].split(':') : [];
    tail = parts[1] ? parts[1].split(':') : [];
  } else {
    head = addr.split(':');
  }
  if (head.length + tail.length > 8) return v;
  const groups = head.concat(new Array(8 - head.length - tail.length).fill('0'), tail);
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return v;   // 内嵌 IPv4 等少见写法原样返回
  const hex = groups.map((g) => g.replace(/^0+/, '') || '0');
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (hex[i] !== '0') continue;
    let j = i;
    while (j < 8 && hex[j] === '0') j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j - 1;
  }
  if (bestLen < 2) return hex.join(':');
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

/** 归一化一个 id（MAC 小写；IPv6 走 RFC 5952；其它原样小写） */
function canonId(s) {
  const v = lc(s);
  return isV6(v) ? canonV6(v) : v;
}

/**
 * IPv6 的取舍窗口（毫秒）：跟随 AdGuard 的统计保留时长。
 * 窗口内有查询的地址才写进 ids，被 AdGuard 淘汰的就删掉，本系统不另立标准。
 * 该值由 ensureSyncWindow() 读回并缓存，读不到时退回 24 小时。
 */
function syncWindowMs() {
  const n = Number(settingGet(WINDOW_SETTING_KEY, DEFAULT_SYNC_WINDOW_MS));
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_SYNC_WINDOW_MS;
}

function fmtWindow(ms) {
  const h = ms / 3600000;
  return h % 24 === 0 && h >= 24 ? `${h / 24} 天` : `${Math.round(h * 10) / 10} 小时`;
}

let windowCheckedAt = 0;

/** 从 AdGuard 读一次窗口设置并缓存（进程内 10 分钟最多读一次，避免每次打开页面都多一次请求） */
async function ensureSyncWindow() {
  if (Date.now() - windowCheckedAt < WINDOW_CACHE_MS) return syncWindowMs();
  windowCheckedAt = Date.now();
  try {
    const cfg = await agClient().statsConfig();
    const ms = Number(cfg && cfg.interval);
    if (Number.isFinite(ms) && ms > 0) settingSet(WINDOW_SETTING_KEY, Math.round(ms));
  } catch (e) {
    // 读不到就沿用上一次的值（首次运行时是 24 小时的默认值），不影响其它逻辑
  }
  return syncWindowMs();
}

/** 带冒号但不是 MAC，即视为 IPv6（AGH 也接受 "::" 之类写法） */
function isIpv6(s) { const v = String(s); return v.includes(':') && !isMac(v); }

/**
 * 本地日志归档的最早时间（epoch ms，0 表示还没有任何日志）。
 * 归档比统计窗口短时，窗口内查不到不代表地址作废，此时不能删，否则会误删还在用的地址。
 */
function logCoverageFrom() {
  const r = db.prepare('SELECT MIN(ts) AS m FROM query_log').get();
  return (r && r.m) || 0;
}

/** 判断窗口是否被本地归档完整覆盖（不覆盖就不许判"过期"） */
function windowCovered(windowMs) {
  const from = logCoverageFrom();
  return !!from && (Date.now() - windowMs) >= from;
}

function fmtDay(ms) {
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function writeAllowed() { return String(settingGet('allow_agh_write', '0')) === '1'; }
function autoSyncOn() { return String(settingGet('agh_auto_sync', '0')) === '1'; }

/**
 * 台账数据的「新鲜度」阈值（秒）：超过它就不信任当前 IP 这个判断。
 * 阈值取 3 倍采集间隔，且不低于 20 分钟（弱机上实际采集周期常比设定间隔长，留够余量）。
 * 采集挂掉时，最坏也就是旧数据多存在 20 分钟，之后所有客户端自动停止同步。
 */
function freshThresholdSec() {
  const iv = Number(settingGet('collect_interval_sec', 300)) || 300;
  return Math.max(1200, iv * 3);
}

/** 人类可读的时长，用于跳过原因 */
function fmtAge(sec) {
  if (sec === null || sec === undefined) return '未知';
  if (sec < 90) return `${sec} 秒`;
  if (sec < 3600) return `${Math.round(sec / 60)} 分钟`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)} 小时`;
  return `${(sec / 86400).toFixed(1)} 天`;
}

function assertWritable() {
  if (!writeAllowed()) {
    const e = new Error('未开启「允许写回 AdGuard」，请到 设置 → 允许写回 AdGuard 打开开关');
    e.status = 403;
    throw e;
  }
}

function agClient() {
  const conn = firstEnabled('adguard');
  if (!conn) { const e = new Error('没有可用的 AdGuard 连接'); e.status = 400; throw e; }
  return adguardClient(conn);
}

/* ------------------------- 本系统台账索引 ------------------------- */

/**
 * 把台账整理成几张查找表，用来判断某个 id 认不认识、属于谁：
 *   deviceByKey    MAC 或 IP → 设备（含历史 IP，用于判断"曾属于谁"）
 *   currentOwner   IP → 当前持有它的设备（准确值，来自当前归属时间线）
 *   macsOf         设备 id → 它名下的所有 MAC
 *   currentIpsOf   设备 id → 它当前的 IP
 *   v6CandidatesOf 设备 id → 该设备"仍要在 AdGuard 里归属"的 IPv6（窗口内有查询的全部地址）
 *   windowMs       IPv6 取舍窗口（= AdGuard 的统计保留时长）
 */
function buildIndex() {
  const { devices } = D.listDevices({});
  const deviceByKey = new Map();
  const currentOwner = new Map();
  const macsOf = new Map();
  const currentIpsOf = new Map();
  const ageSecOf = new Map();          // 设备 id → 台账里该设备最近一次被观测到距今多少秒
  const v6CandidatesOf = new Map();    // 设备 id → [IPv6...]
  const windowMs = syncWindowMs();
  const v6Traffic = v6TrafficByDevice(windowMs);   // 设备 id → { IPv6 → 窗口内查询数 }
  const routerIps = new Set(D.routerIpList().map((x) => lc(x)));
  const coverageFrom = logCoverageFrom();
  // 归档是否覆盖了整个窗口：不覆盖时只能"加"不能"删"（见 windowCovered 的说明）
  const covered = windowCovered(windowMs);
  const now = Date.now();
  for (const d of devices) {
    const seenAt = Date.parse(d.last_seen || '') || 0;
    ageSecOf.set(d.id, seenAt ? Math.max(0, Math.round((now - seenAt) / 1000)) : null);
    const macs = new Set();
    for (const m of d.macs || []) { const k = lc(m); if (k) { macs.add(k); deviceByKey.set(k, d); } }
    if (d.mac) { const k = lc(d.mac); macs.add(k); deviceByKey.set(k, d); }
    macsOf.set(d.id, macs);
    const cur = new Set();
    for (const ip of d.current_ips || []) {
      const k = canonId(ip);            // IPv6 统一成 AdGuard 存的那种写法，差异比对才稳定
      if (k) { cur.add(k); currentOwner.set(k, d); }
    }
    currentIpsOf.set(d.id, cur);
    const lastSeenOf = new Map();
    for (const ip of d.ips || []) {
      const k = canonId(ip.ip);
      if (!k) continue;
      lastSeenOf.set(k, ip.last_seen || '');
      if (!deviceByKey.has(k)) deviceByKey.set(k, d);   // 历史 IP 只记"首次出现"的那台
    }
    // IPv6 候选：该设备名下、在窗口内（= AdGuard 的统计保留时长）被 AdGuard 记录过查询的地址，
    // 排除链路本地/回环/组播/路由器本机，按查询数降序。
    // 窗口内一条查询都没有的地址写进去也归属不到任何流量，只会让 ids 越积越长（完整 diff 时会删掉）。
    {
      const traffic = v6Traffic.get(d.id) || new Map();
      const cands = [...cur].filter((x) => isWritableV6(x) && !routerIps.has(x) && (traffic.get(x) || {}).n > 0);
      cands.sort((a, b) => {
        const ta = traffic.get(a) || { n: 0, last_ts: 0 };
        const tb = traffic.get(b) || { n: 0, last_ts: 0 };
        if (tb.n !== ta.n) return tb.n - ta.n;
        if (tb.last_ts !== ta.last_ts) return tb.last_ts - ta.last_ts;
        return String(lastSeenOf.get(b) || '').localeCompare(String(lastSeenOf.get(a) || ''));
      });
      if (cands.length) v6CandidatesOf.set(d.id, cands);
    }
  }
  return {
    devices, deviceByKey, currentOwner, macsOf, currentIpsOf, ageSecOf,
    v6CandidatesOf, v6Traffic, windowMs, coverageFrom, covered
  };
}

/**
 * 设备 id → { IPv6 → 窗口内查询数 / 最近一次查询时间 }。
 * 用来在"该设备用过的多个 IPv6"里挑出 AdGuard 仍在统计的地址。
 * 按 device_id 分组，这样统计的是"日志归到该设备头上"的次数，
 * 地址在设备之间迁移时不会把旧设备的流量算进来。
 */
function v6TrafficByDevice(windowMs) {
  const map = new Map();
  const rows = db.prepare(`SELECT device_id AS did, client_ip AS ip, COUNT(*) AS n, MAX(ts) AS last_ts
    FROM query_log WHERE ts >= ? AND client_ip LIKE '%:%' GROUP BY device_id, client_ip`)
    .all(Date.now() - windowMs);
  for (const r of rows) {
    if (r.did === null || r.did === undefined) continue;
    const k = canonId(r.ip);
    if (!k) continue;
    if (!map.has(r.did)) map.set(r.did, new Map());
    map.get(r.did).set(k, { n: r.n || 0, last_ts: r.last_ts || 0 });
  }
  return map;
}

/* ------------------------- 差异计算（纯函数，不写任何东西） ------------------------- */

/**
 * 算出某个 AdGuard 客户端"应该变成什么样"。
 * opts.device 指定时（单个重算场景）不靠 ids 猜设备，直接用指定的设备。
 * opts.includeUnknown=true 时，把"本系统无法判断"的项也列入移除。
 */
function planClient(cl, index, others, opts = {}) {
  const includeUnknown = !!opts.includeUnknown;
  const before = (cl.ids || []).map(String).map(canonId).filter(Boolean);

  // 1) 这个客户端对应本系统的哪台设备
  let device = opts.device || null;
  let skipReason = null;
  if (!device) {
    const cand = new Map();
    for (const id of before) {
      const d = index.deviceByKey.get(id);
      if (d) cand.set(d.id, d);
    }
    if (!cand.size) skipReason = 'ids 里没有本系统认识的 MAC/IP，无法归属到设备';
    else if (cand.size > 1) {
      skipReason = `ids 分属多台设备（${[...cand.values()].map((d) => d.display_name).join('、')}），请先在本系统「合并设备」`;
    } else device = [...cand.values()][0];
  }
  const mainMac = device && device.mac && isMac(device.mac) ? lc(device.mac) : null;
  if (!skipReason && !mainMac) skipReason = '该设备没有可用的 MAC，无法作为 AdGuard 客户端';

  // 台账新鲜度闸门：采集长时间没成功时不信任"当前 IP"，免得把已属于别人的地址写进去
  const rawAge = device ? index.ageSecOf.get(device.id) : null;
  const ageSec = rawAge === undefined ? null : rawAge;
  const freshSec = freshThresholdSec();
  const dataStale = !!device && (ageSec === null || ageSec > freshSec);
  if (!skipReason && dataStale && opts.strict) {
    skipReason = ageSec === null
      ? '台账里没有该设备的观测时间，暂不同步'
      : `台账里该设备最近一次观测已是 ${fmtAge(ageSec)}前（超过 ${fmtAge(freshSec)}），可能与 AdGuard 看到的不一致，暂不同步；下次采集成功后会自动恢复`;
  }

  const plan = {
    name: cl.name,
    exists: opts.exists !== false,
    managed: !skipReason,
    skip_reason: skipReason,
    device_id: device ? device.id : null,
    device_name: device ? device.display_name : null,
    main_mac: mainMac,
    data_age_sec: ageSec,
    data_stale: dataStale,
    ids_before: before,
    final_ids: [],
    window_sec: 0,
    coverage_ok: true, log_from: null,
    ipv6_written: [], ipv6_added: [], truncated: [],
    add: [], remove: [], keep: [], unknown: [], conflicts: []
  };
  if (skipReason) return plan;

  const curIps = index.currentIpsOf.get(device.id) || new Set();
  const myMacs = index.macsOf.get(device.id) || new Set();
  const v6Keep = new Set((index.v6CandidatesOf && index.v6CandidatesOf.get(device.id)) || []);
  const windowMs = index.windowMs || DEFAULT_SYNC_WINDOW_MS;
  const winText = fmtWindow(windowMs);
  const v6Traffic = (index.v6Traffic && index.v6Traffic.get(device.id)) || new Map();
  const removed = new Map();        // id → 为什么移除
  const unknown = [];               // 本系统判断不了的项（默认保留）
  const survivors = [];             // 保留的原有项（保持原顺序，不产生无意义 diff）

  for (const id of before) {
    if (isMac(id)) {
      if (id === mainMac || myMacs.has(id)) { survivors.push(id); continue; }   // 本设备的 MAC，一律保留
      const owner = index.deviceByKey.get(id);
      if (owner && owner.id !== device.id) { removed.set(id, `该 MAC 在本系统属于「${owner.display_name}」`); continue; }
      unknown.push({ id, why: '本系统没见过这个 MAC，可能是你手工加的' });
      if (includeUnknown) { removed.set(id, '本系统没见过这个 MAC（你选择一并清理）'); continue; }
      survivors.push(id);
      continue;
    }
    if (isIpv6(id)) {
      if (v6Keep.has(id)) { survivors.push(id); continue; }        // 本次要写的 IPv6，保留
      const cur6 = index.currentOwner.get(id);
      if (cur6 && cur6.id !== device.id) {
        removed.set(id, `该 IPv6 当前归属「${cur6.display_name}」，留着会把它的流量算到本客户端`);
        continue;
      }
      const hist6 = index.deviceByKey.get(id);
      if (hist6 && hist6.id !== device.id) {
        removed.set(id, `该 IPv6 在本系统属于「${hist6.display_name}」`);
        continue;
      }
      // IPv6 地址轮换很快：窗口（= AdGuard 的统计保留时长）内 AdGuard 还在统计的地址才写，
      // 已经被 AdGuard 淘汰的（窗口内一条查询都没有）就删掉，免得 ids 越积越长
      if (!index.covered) {
        // 本地归档比窗口还短：查不到不代表不用了，宁可不删（否则会误删仍在用的地址）
        unknown.push({
          id,
          why: `本系统日志只归档到 ${fmtDay(index.coverageFrom)}，短于 AdGuard 的统计窗口（${winText}），`
            + '无法判断它是否还在用，暂不删除'
        });
        survivors.push(id);
        continue;
      }
      const n = (v6Traffic.get(id) || {}).n || 0;
      if (n > 0) removed.set(id, `该 IPv6 有 ${n} 次查询，但不在本设备名下（已不归它使用）`);
      else removed.set(id, `该 IPv6 在 AdGuard 最近 ${winText}的日志里没有任何查询，已经用不上了`);
      continue;
    }
    if (isIpv4(id)) {
      if (curIps.has(id)) { survivors.push(id); continue; }                     // 它当前的 IP，保留
      const cur = index.currentOwner.get(id);
      if (cur && cur.id !== device.id) {
        removed.set(id, `该 IP 当前归属「${cur.display_name}」，留着会把它的流量算到本客户端`);
        continue;
      }
      const hist = index.deviceByKey.get(id);
      if (hist && hist.id === device.id) { removed.set(id, '曾属于该设备，但已不是它的当前 IP'); continue; }
      if (hist) { removed.set(id, `曾属于「${hist.display_name}」，已不是本设备的地址`); continue; }
      unknown.push({ id, why: '本系统从未见过这个 IP，可能是你手工加的' });
      if (includeUnknown) { removed.set(id, '本系统从未见过这个 IP（你选择一并清理）'); continue; }
      survivors.push(id);
      continue;
    }
    // 既不是合法 MAC 也不是合法 IP：不判断，默认原样保留
    unknown.push({ id, why: '不是 MAC 也不是合法 IP，本系统无法判断' });
    if (includeUnknown) { removed.set(id, '不是 MAC 也不是合法 IP（你选择一并清理）'); continue; }
    survivors.push(id);
  }

  // 最终 ids：主 MAC 置顶 → 保留原有项（含默认保留的未知项）→ 当前 IPv4 → 选出的 IPv6
  const curV4 = [...curIps].filter((x) => isIpv4(x)).sort();
  const finalIds = [];
  const push = (x) => { if (x && !finalIds.includes(x) && finalIds.length < MAX_IDS) finalIds.push(x); };
  push(mainMac);
  for (const id of survivors) push(id);
  if (curV4.length) push(curV4[0]);
  const v6Written = [];
  for (const id of v6Keep) {
    if (!finalIds.includes(id)) push(id);
    if (finalIds.includes(id)) v6Written.push({ id, queries: (v6Traffic.get(id) || {}).n || 0 });
  }
  plan.window_sec = Math.round(windowMs / 1000);
  plan.coverage_ok = !!index.covered;              // 本地归档是否覆盖了整个窗口（否则不删过期项）
  plan.log_from = index.coverageFrom || null;
  plan.ipv6_written = v6Written;                                    // 本次会保留/写入的 IPv6（含窗口内查询数）
  plan.ipv6_added = v6Written.filter((x) => !before.includes(x.id)); // 其中属于新增的
  plan.truncated = v6Written.filter((x) => !finalIds.includes(x.id)).map((x) => x.id);   // 极少见：超出 MAX_IDS 被截掉的

  plan.final_ids = finalIds;
  plan.add = finalIds.filter((x) => !before.includes(x));
  plan.keep = before.filter((x) => finalIds.includes(x));
  plan.remove = before.filter((x) => !finalIds.includes(x)).map((id) => ({ id, why: removed.get(id) || '不再需要' }));
  plan.unknown = unknown.map((u) => ({ ...u, removed: !finalIds.includes(u.id) }));

  // AdGuard 的 id 全局唯一：想加的 id 若已被别的客户端占用，写入会失败（不会覆盖）
  for (const id of plan.add) {
    for (const c of others) {
      if (c.name === cl.name) continue;
      if ((c.ids || []).some((x) => canonId(x) === id)) plan.conflicts.push({ id, owner: c.name });
    }
  }
  return plan;
}

/** 批量算差异（只读） */
function buildPlans(raw, opts = {}) {
  const index = buildIndex();
  return raw.map((cl) => planClient(cl, index, raw, opts));
}

/** 写入前的强校验：不通过就不提交 */
function validateIds(ids, mainMac) {
  const errors = [];
  const norm = [];
  for (const raw of ids || []) {
    const s = canonId(raw);
    if (!s) { errors.push('存在空的 id'); continue; }
    if (isMac(s) || isIpv4(s)) { norm.push(s); continue; }
    if (isV6(s)) {
      // 只拦"写了也没意义"的地址：链路本地（fe80::/10 出不了本链路）、回环、组播
      if (!isWritableV6(s)) { errors.push(`拒绝写入链路本地/回环/组播 IPv6：${s}`); continue; }
      norm.push(s);
      continue;
    }
    errors.push(`不是合法的 MAC / IPv4 / IPv6：${s}`);
  }
  const uniq = [...new Set(norm)];
  if (!uniq.length) errors.push('ids 不能为空');
  if (!mainMac) errors.push('该设备没有主 MAC');
  else if (!uniq.includes(mainMac)) errors.push(`ids 里必须包含该设备的主 MAC（${mainMac}）`);
  if (uniq.length > MAX_IDS) errors.push(`ids 项数 ${uniq.length} 超过上限 ${MAX_IDS}`);
  return { ok: !errors.length, errors, ids: uniq };
}

/* ------------------------- 读：客户端列表 ------------------------- */

/** 列出 AdGuard 的持久客户端，标注每个 id 映射到本系统哪台设备，以及同步状态 */
async function listClients() {
  await ensureSyncWindow();
  const data = await agClient().clients();
  const raw = (data && data.clients) || [];
  const index = buildIndex();
  const clients = raw.map((cl) => {
    const p = planClient(cl, index, raw, { strict: true });
    const ids = (cl.ids || []).map(String);
    return {
      name: cl.name,
      ids,
      tags: cl.tags || [],
      use_global_settings: cl.use_global_settings !== false,
      ignore_querylog: !!cl.ignore_querylog,
      device_id: p.device_id,
      device_name: p.device_name,
      managed: p.managed,
      skip_reason: p.skip_reason,
      data_age_sec: p.data_age_sec,
      data_stale: p.data_stale,
      pending_add: p.managed ? p.add.length : 0,
      pending_remove: p.managed ? p.remove.length : 0,
      unknown_count: p.unknown.length,
      state: !p.managed ? 'unmanaged' : ((p.add.length || p.remove.length) ? 'pending' : 'ok'),
      mapped: ids.map((id) => {
        const key = canonId(id);
        const d = index.deviceByKey.get(key);
        const curIpsOfDev = d ? (index.currentIpsOf.get(d.id) || new Set()) : null;
        return {
          id,
          device_name: d ? d.display_name : null,
          // 该 id 是不是"当下"的地址（MAC 看主 MAC；IP 看当前归属）
          current: !!(d && (isMac(key) ? key === lc(d.mac) : curIpsOfDev.has(key)))
        };
      })
    };
  });
  return {
    clients,
    auto_clients: (data && data.auto_clients) || [],
    write_allowed: writeAllowed(),
    auto_sync: autoSyncOn(),
    window_sec: Math.round(index.windowMs / 1000),   // 写入窗口（跟随 AdGuard 的统计保留时长）
    coverage_ok: !!index.covered,                    // 本地日志是否覆盖了整个窗口
    log_from: index.coverageFrom || null
  };
}

/* ------------------------- 单个：新建 / 重算 ------------------------- */

/** 差异预览（只读）：把"该设备应有的 ids"与目标客户端现有 ids 对比 */
async function planForDevice(name, deviceId, opts = {}) {
  await ensureSyncWindow();
  const dev = D.getDevice(Number(deviceId));
  if (!dev) { const e = new Error('设备不存在'); e.status = 400; throw e; }
  const nm = String(name || '').trim();
  const data = await agClient().clients();
  const raw = (data && data.clients) || [];
  const cur = nm ? raw.find((c) => c.name === nm) : null;
  const index = buildIndex();
  return planClient(
    { name: nm, ids: cur ? (cur.ids || []) : [] },
    index,
    raw,
    { device: dev, exists: !!cur, includeUnknown: !!opts.includeUnknown }
  );
}

/** 执行：不存在则新建，存在则把 ids 调整为新算出来的集合 */
async function applyForDevice(name, deviceId, opts = {}) {
  assertWritable();
  const nm = String(name || '').trim();
  if (!nm) { const e = new Error('客户端名称不能为空'); e.status = 400; throw e; }
  if (isIpv4(nm) || (/^[0-9a-f:]+$/i.test(nm) && nm.includes(':'))) {
    const e = new Error('客户端名称不能是 IP 地址');
    e.status = 400;
    throw e;
  }
  const plan = await planForDevice(nm, deviceId, opts);
  if (plan.conflicts.length) {
    const e = new Error('以下 id 已被其它客户端占用，AdGuard 不允许重复（不会覆盖）：'
      + plan.conflicts.map((c) => `${c.id}（属于「${c.owner}」）`).join('、'));
    e.status = 409;
    throw e;
  }
  const v = validateIds(plan.final_ids, plan.main_mac);
  if (!v.ok) { const e = new Error('写入前校验未通过，已中止：' + v.errors.join('；')); e.status = 400; throw e; }

  const c = agClient();
  if (plan.exists) {
    const data = await c.clients();
    const cur = (data.clients || []).find((x) => x.name === nm);
    if (!cur) { const e = new Error('该客户端刚刚被删除或改名，请刷新后重试'); e.status = 409; throw e; }
    await c.updateClient(nm, mergeClient(cur, v.ids));
    recordJob('agh_client', 'success', `更新 AdGuard 客户端「${nm}」ids → ${v.ids.join(', ')}`);
    return { action: 'updated', name: nm, ids: v.ids };
  }
  await c.addClient({ name: nm, ids: v.ids });
  recordJob('agh_client', 'success', `新建 AdGuard 客户端「${nm}」ids = ${v.ids.join(', ')}`);
  return { action: 'created', name: nm, ids: v.ids };
}

/** 只保留 AdGuard 可写字段（uid 等只读字段不传），其余原有配置原样带上 */
function mergeClient(cur, ids) {
  const data = {
    name: cur.name,
    ids,
    use_global_settings: cur.use_global_settings !== false,
    filtering_enabled: !!cur.filtering_enabled,
    parental_enabled: !!cur.parental_enabled,
    safebrowsing_enabled: !!cur.safebrowsing_enabled,
    use_global_blocked_services: cur.use_global_blocked_services !== false,
    ignore_querylog: !!cur.ignore_querylog,
    ignore_statistics: !!cur.ignore_statistics,
    tags: cur.tags || []
  };
  if (cur.safe_search) data.safe_search = cur.safe_search;
  if (cur.blocked_services) data.blocked_services = cur.blocked_services;
  if (cur.upstreams) data.upstreams = cur.upstreams;
  if (cur.upstreams_cache_enabled !== undefined) data.upstreams_cache_enabled = cur.upstreams_cache_enabled;
  if (cur.upstreams_cache_size !== undefined) data.upstreams_cache_size = cur.upstreams_cache_size;
  return data;
}

/* ------------------------- 批量 / 全量 ------------------------- */

/**
 * 批量差异预览（只读）。names 省略或为空 = 所有客户端（全量）。
 * 只返回"可管理且有变化"的客户端明细，其余分类列出，便于你确认。
 */
async function planBatch(names, opts = {}) {
  const includeUnknown = !!opts.includeUnknown;
  await ensureSyncWindow();
  const data = await agClient().clients();
  const raw = (data && data.clients) || [];
  const wanted = Array.isArray(names) && names.length ? new Set(names.map(String)) : null;
  const index = buildIndex();                      // 只建一次（内部有窗口内的日志聚合，别重复跑）
  const plans = raw.map((cl) => planClient(cl, index, raw, { includeUnknown, strict: true }))
    .filter((p) => !wanted || wanted.has(p.name));
  const changed = plans.filter((p) => p.managed && (p.add.length || p.remove.length));
  return {
    include_unknown: includeUnknown,
    total: plans.length,
    limit: BATCH_LIMIT,
    fresh_threshold_sec: freshThresholdSec(),
    window_sec: Math.round(index.windowMs / 1000),
    coverage_ok: !!index.covered,
    log_from: index.coverageFrom || null,
    changed,
    unchanged: plans.filter((p) => p.managed && !p.add.length && !p.remove.length).map((p) => p.name),
    skipped: plans.filter((p) => !p.managed).map((p) => ({ name: p.name, reason: p.skip_reason })),
    blocked: changed.filter((p) => p.conflicts.length).map((p) => ({ name: p.name, conflicts: p.conflicts })),
    batch_too_large: changed.length > BATCH_LIMIT
  };
}

/**
 * 批量 / 全量执行。names 省略 = 全量（仅限"可管理"的客户端）。
 * auto=true 时按自动同步记账，并且只更新 ids，不新建、不删除客户端。
 */
async function applyBatch(names, opts = {}) {
  assertWritable();
  const includeUnknown = !!opts.includeUnknown;
  const auto = !!opts.auto;
  const job = auto ? 'agh_auto_sync' : 'agh_sync';
  await ensureSyncWindow();
  const data = await agClient().clients();
  const raw = (data && data.clients) || [];
  const wanted = Array.isArray(names) && names.length ? new Set(names.map(String)) : null;
  const plans = buildPlans(raw, { includeUnknown, strict: true }).filter((p) => !wanted || wanted.has(p.name));

  if (wanted && !plans.length) { const e = new Error('没有找到要同步的客户端'); e.status = 400; throw e; }
  const todo = plans.filter((p) => p.managed && (p.add.length || p.remove.length));
  if (!todo.length) {
    recordJob(job, 'success', `${auto ? '自动' : '批量'}同步：全部已是最新（检查 ${plans.length} 个客户端，无需变更）`);
    return { updated: 0, failed: [], changed: [], unchanged: plans.length };
  }
  if (todo.length > BATCH_LIMIT) {
    const e = new Error(`一轮最多同步 ${BATCH_LIMIT} 个客户端，本次需要 ${todo.length} 个。请勾选分批同步或缩小范围。`);
    e.status = 400;
    throw e;
  }

  const c = agClient();
  const done = [];
  const failed = [];
  for (const p of todo) {
    try {
      if (p.conflicts.length) {
        const e = new Error('id 已被其它客户端占用：' + p.conflicts.map((x) => `${x.id}（${x.owner}）`).join('、'));
        e.status = 409;
        throw e;
      }
      const v = validateIds(p.final_ids, p.main_mac);
      if (!v.ok) { const e = new Error(v.errors.join('；')); e.status = 400; throw e; }
      const cur = raw.find((x) => x.name === p.name);
      if (!cur) { failed.push({ name: p.name, error: '客户端已不存在，跳过' }); continue; }
      await c.updateClient(p.name, mergeClient(cur, v.ids));
      done.push({ name: p.name, add: p.add, remove: p.remove.map((x) => x.id), ids: v.ids });
    } catch (e) {
      failed.push({ name: p.name, error: e.message });
    }
  }

  const unchanged = plans.filter((p) => p.managed && !p.add.length && !p.remove.length).length;
  const skipped = plans.filter((p) => !p.managed).length;
  const msg = `${auto ? '自动' : '批量'}同步 AdGuard 客户端：更新 ${done.length} 个`
    + (failed.length ? `，失败 ${failed.length} 个（${failed[0].error}）` : '')
    + `，无需变更 ${unchanged} 个，跳过不可管理 ${skipped} 个`
    + (done.length ? `；${done.map((d) => `「${d.name}」+${d.add.length}/−${d.remove.length}`).join(' ')}` : '');
  recordJob(job, failed.length ? 'failed' : 'success', msg, { done: done.map((d) => d.name), failed });
  return { updated: done.length, failed, changed: done, unchanged, skipped };
}

/* ------------------------- 失效 id 扫描与清理 ------------------------- */

/**
 * 扫描需要清理的 id（只读，与批量同步用同一套规则）：
 *   stale   明确无意义的（窗口内已无查询的 IPv6 / 曾属于该设备但已不是当前 IP / 当前归属别的设备）
 *   unknown 本系统判断不了的（可能是手工加的），默认保留，需显式勾选才会清
 * 无法归属到设备的客户端整体跳过，不参与。
 */
async function scanStale() {
  await ensureSyncWindow();
  const data = await agClient().clients();
  const raw = (data && data.clients) || [];
  const plans = buildPlans(raw, { includeUnknown: false, strict: true });
  const out = [];
  for (const p of plans) {
    if (!p.managed) continue;
    if (!p.remove.length && !p.unknown.length) continue;
    out.push({
      name: p.name,
      device_name: p.device_name,
      data_age_sec: p.data_age_sec,
      total: p.ids_before.length,
      keep: p.keep,
      stale: p.remove,
      unknown: p.unknown
    });
  }
  return out;
}

/** 执行清理：按名字走批量同步（不采信前端传来的 ids，由服务端重算） */
async function cleanStale(args) {
  const input = args && typeof args === 'object' ? args : {};
  const names = Array.isArray(input.names) ? input.names
    : (Array.isArray(input.items) ? input.items.map((x) => (x && x.name) || x) : []);
  if (!names.length) { const e = new Error('没有要清理的客户端'); e.status = 400; throw e; }
  return applyBatch(names, { includeUnknown: !!input.include_unknown });
}

async function removeClient(name) {
  assertWritable();
  const nm = String(name || '').trim();
  if (!nm) { const e = new Error('名称不能为空'); e.status = 400; throw e; }
  await agClient().deleteClient(nm);
  recordJob('agh_client', 'success', `删除 AdGuard 客户端「${nm}」`);
  return { deleted: nm };
}

/** 自动同步入口（定时任务用）：只有开关打开时才真的执行 */
async function runAutoSync() {
  if (!writeAllowed() || !autoSyncOn()) return { skipped: true, reason: '开关未开启' };
  return applyBatch(null, { includeUnknown: false, auto: true });
}

module.exports = {
  writeAllowed, autoSyncOn, listClients, planForDevice, applyForDevice,
  planBatch, applyBatch, removeClient, scanStale, cleanStale, runAutoSync
};
