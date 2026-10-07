'use strict';

const { db, settingGet } = require('./db');
const oui = require('./oui');
const { httpError } = require('./httperr');

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;

function normalizeMac(mac) {
  if (!mac) return null;
  const m = String(mac).trim().toLowerCase().replace(/-/g, ':');
  if (!MAC_RE.test(m)) return null;
  if (m === '00:00:00:00:00:00' || m === 'ff:ff:ff:ff:ff:ff') return null;
  return m;
}

/** 本地管理位（bit1）为 1 表示随机/隐私 MAC，手机会轮换，不适合作为唯一锚点 */
function isRandomMac(mac) {
  const m = normalizeMac(mac);
  if (!m) return false;
  return (parseInt(m.slice(0, 2), 16) & 0x02) === 0x02;
}

function isIpv6(ip) { return String(ip).includes(':'); }

function isPrivateIp(ip) {
  const s = String(ip);
  if (s.includes(':')) {
    return s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80') || s === '::1';
  }
  const p = s.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  return false;
}

function nowIso() { return new Date().toISOString(); }

/** 网关/本机地址列表（不计入设备；其日志标为"路由器本机"） */
function routerIpList() {
  // 不能传显式 fallback：设置项缺失会得到空列表，把 127.0.0.1 / ::1 当成普通客户端（未归属统计与清理会出错）
  const raw = settingGet('router_ips');
  return String(raw || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function isRouterIp(ip) { return routerIpList().includes(String(ip).trim()); }

/* ------------------------- 设备与 IP 归并 ------------------------- */

function findDeviceByMac(mac) {
  const m = normalizeMac(mac);
  if (!m) return null;
  const row = db.prepare('SELECT d.* FROM device_macs m JOIN devices d ON d.id = m.device_id WHERE m.mac = ?').get(m);
  return row || null;
}

function findDeviceByAnchor(anchor) {
  return db.prepare('SELECT * FROM devices WHERE anchor = ?').get(anchor) || null;
}

function createDevice(anchor, { name = null, suggestedName = null, source = 'discovered' } = {}) {
  const ts = nowIso();
  const mac = MAC_RE.test(anchor) ? anchor : null;
  const info = db.prepare(`INSERT INTO devices
    (anchor, name, suggested_name, vendor, random_mac, first_seen, last_seen, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(anchor, name, suggestedName, mac ? oui.lookup(mac) : null, mac && isRandomMac(mac) ? 1 : 0, ts, ts, ts, ts);
  const id = info.lastInsertRowid;
  if (mac) {
    db.prepare('INSERT INTO device_macs (mac, device_id, source, first_seen, last_seen) VALUES (?,?,?,?,?) ON CONFLICT(mac) DO NOTHING')
      .run(mac, id, source, ts, ts);
  }
  return db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
}

function touchDevice(id, { suggestedName, lastSeen } = {}) {
  const ts = lastSeen || nowIso();
  if (suggestedName) {
    db.prepare('UPDATE devices SET last_seen = ?, suggested_name = COALESCE(NULLIF(suggested_name, \'\'), ?), updated_at = ? WHERE id = ?')
      .run(ts, suggestedName, ts, id);
  } else {
    db.prepare('UPDATE devices SET last_seen = ?, updated_at = ? WHERE id = ?').run(ts, ts, id);
  }
}

function upsertIp(deviceId, { ip, mac, hostname, clientId, iface, source, isStatic, seenAt }) {
  const ts = seenAt || nowIso();
  const ver = isIpv6(ip) ? 6 : 4;
  const existing = db.prepare('SELECT id FROM device_ips WHERE device_id = ? AND ip = ?').get(deviceId, ip);
  if (existing) {
    db.prepare(`UPDATE device_ips SET last_seen = ?, mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),
      client_id = COALESCE(?, client_id), interface = COALESCE(?, interface), source = ?, is_static = MAX(is_static, ?) WHERE id = ?`)
      .run(ts, mac || null, hostname || null, clientId || null, iface || null, source || null, isStatic ? 1 : 0, existing.id);
  } else {
    db.prepare(`INSERT INTO device_ips (device_id, mac, ip, ip_ver, hostname, client_id, interface, source, is_static, first_seen, last_seen)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(deviceId, mac || null, ip, ver, hostname || null, clientId || null, iface || null, source || null, isStatic ? 1 : 0, ts, ts);
  }
}

/** 记录一次观察：内部完成"设备锚点解析 -> 复用/新建 -> IP 落库" */
function observe({ mac, ip, hostname, clientId, iface, source, isStatic, seenAt }) {
  const nmac = normalizeMac(mac);
  const addr = ip ? String(ip).trim() : null;
  if (!nmac && !addr) return null;

  let device = null;
  if (nmac) {
    device = findDeviceByMac(nmac);
    if (!device) {
      // IP 已归属某个"仅按 IP 锚定"的设备（例如从 AGH 采纳而来）→ 升级为以 MAC 锚定
      if (addr) {
        const owner = ownerOfIp(addr);
        if (owner && String(owner.anchor).startsWith('ip:')) {
          const ts = nowIso();
          db.prepare('UPDATE devices SET anchor = ?, random_mac = ?, vendor = COALESCE(vendor, ?), updated_at = ? WHERE id = ?')
            .run(nmac, isRandomMac(nmac) ? 1 : 0, oui.lookup(nmac), ts, owner.id);
          db.prepare('INSERT INTO device_macs (mac, device_id, source, first_seen, last_seen) VALUES (?,?,?,?,?) ON CONFLICT(mac) DO NOTHING')
            .run(nmac, owner.id, 'reanchor', ts, ts);
          device = db.prepare('SELECT * FROM devices WHERE id = ?').get(owner.id);
        }
      }
      if (!device) device = createDevice(nmac, { suggestedName: hostname, source: source || 'discovered' });
    } else {
      db.prepare('UPDATE device_macs SET last_seen = ? WHERE mac = ?').run(seenAt || nowIso(), nmac);
    }
  } else if (addr) {
    const owner = ownerOfIp(addr);
    if (owner) device = owner;
    else device = createDevice('ip:' + addr, { suggestedName: hostname, source: source || 'discovered' });
  }

  const cleanHost = hostname && hostname !== '*' ? String(hostname).trim() : null;
  touchDevice(device.id, { suggestedName: cleanHost, lastSeen: seenAt });
  if (addr) upsertIp(device.id, { ip: addr, mac: nmac, hostname: cleanHost, clientId, iface, source, isStatic, seenAt });
  return device.id;
}

/** 某 IP 的当前归属设备（以 last_seen 最新者为准） */
function ownerOfIp(ip) {
  const row = db.prepare('SELECT device_id FROM device_ips WHERE ip = ? ORDER BY last_seen DESC, id DESC LIMIT 1').get(String(ip));
  if (!row) return null;
  return db.prepare('SELECT * FROM devices WHERE id = ?').get(row.device_id) || null;
}

/** 全量 IP -> 最新归属设备（供只按"当前归属"判定的场景使用） */
function ipOwnerMap() {
  const map = new Map();
  for (const row of db.prepare('SELECT ip, device_id FROM device_ips ORDER BY last_seen ASC, id ASC').all()) {
    map.set(row.ip, row.device_id);
  }
  return map;
}

/** IP -> 归属时间线 [{deviceId, first, last}]：一个 IP 被 DHCP 回收再分配会形成多段区间，据此把历史查询归给当时的持有者 */
function ipOwnerTimeline() {
  const map = new Map();
  const rows = db.prepare('SELECT ip, device_id, first_seen, last_seen FROM device_ips ORDER BY first_seen ASC, id ASC').all();
  for (const r of rows) {
    if (!map.has(r.ip)) map.set(r.ip, []);
    map.get(r.ip).push({
      deviceId: r.device_id,
      first: Date.parse(r.first_seen) || 0,
      last: Date.parse(r.last_seen) || 0
    });
  }
  return map;
}

/** 在时间线上解析某 IP 在 ts 时刻的归属；区间外则退化为时间上最近的一段 */
function resolveOwnerAt(timeline, ip, ts) {
  const list = timeline.get(String(ip));
  if (!list || !list.length) return null;
  const t = Number(ts) || Date.now();
  let best = null;
  for (const seg of list) {
    if (t >= seg.first && t <= seg.last) {
      // 多个区间都覆盖该时刻时，取区间更短（更精确）的一段
      if (!best || (seg.last - seg.first) < (best.last - best.first)) best = seg;
    }
  }
  if (best) return best.deviceId;
  let nearest = list[0];
  let dist = Infinity;
  for (const seg of list) {
    const d = t < seg.first ? seg.first - t : t - seg.last;
    if (d < dist) { dist = d; nearest = seg; }
  }
  return nearest.deviceId;
}

/* ------------------------- 采集结果解析 ------------------------- */

function parseLeases(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    const [expiry, mac, ip, host, clientId] = parts;
    if (!normalizeMac(mac)) continue;
    out.push({
      mac, ip, hostname: host === '*' ? null : host,
      clientId: clientId && clientId !== '*' ? clientId : null,
      expiry: Number(expiry) * 1000 || null
    });
  }
  return out;
}

function parseNeigh(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?/);
    if (!m) continue;
    const [, ip, dev, mac] = m;
    if (!mac) continue;                        // FAILED / INCOMPLETE 无 MAC
    if (!normalizeMac(mac)) continue;
    if (line.includes('FAILED')) continue;
    out.push({ ip, mac, iface: dev });
  }
  return out;
}

function parseStatic(text) {
  // uci show dhcp 输出形如：dhcp.@host[0].mac='xx:..' / .ip='..' / .name='..'
  const groups = new Map();
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^(dhcp\.[^\s=]+)\.(mac|ip|name|hostname)=(.*)$/);
    if (!m) continue;
    const [, section, key, valRaw] = m;
    const val = valRaw.replace(/^'|'$/g, '').trim();
    if (!groups.has(section)) groups.set(section, {});
    groups.get(section)[key] = val;
  }
  const out = [];
  for (const cfg of groups.values()) {
    if (normalizeMac(cfg.mac) && cfg.ip) {
      out.push({ mac: cfg.mac, ip: cfg.ip, hostname: cfg.name || cfg.hostname || null });
    }
  }
  return out;
}

function parseArp(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/).slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6) continue;
    const [ip, , flags, mac, , dev] = parts;
    if (flags === '0x0') continue;
    if (!normalizeMac(mac)) continue;
    out.push({ ip, mac, iface: dev });
  }
  return out;
}

/** 把采集到的原始文本落库 */
function applyCollected(sections) {
  const stat = { leases: 0, neigh4: 0, neigh6: 0, static: 0, arp: 0, devices: new Set() };
  const run = db.transaction(() => {
    for (const l of parseLeases(sections.LEASES)) {
      const id = observe({ mac: l.mac, ip: l.ip, hostname: l.hostname, clientId: l.clientId, source: 'dhcp_lease' });
      if (id) { stat.leases++; stat.devices.add(id); }
    }
    for (const n of parseNeigh(sections.NEIGH4)) {
      const id = observe({ mac: n.mac, ip: n.ip, iface: n.iface, source: 'arp' });
      if (id) { stat.neigh4++; stat.devices.add(id); }
    }
    for (const n of parseNeigh(sections.NEIGH6)) {
      const id = observe({ mac: n.mac, ip: n.ip, iface: n.iface, source: 'arp6' });
      if (id) { stat.neigh6++; stat.devices.add(id); }
    }
    for (const s of parseStatic(sections.STATIC)) {
      const id = observe({ mac: s.mac, ip: s.ip, hostname: s.hostname, source: 'static', isStatic: true });
      if (id) { stat.static++; stat.devices.add(id); }
    }
    for (const a of parseArp(sections.ARP)) {
      const id = observe({ mac: a.mac, ip: a.ip, iface: a.iface, source: 'arp' });
      if (id) { stat.arp++; stat.devices.add(id); }
    }
  });
  run();
  stat.deviceCount = stat.devices.size;
  delete stat.devices;
  return stat;
}

/** 只读 AdGuard 持久客户端以继承已有中文名；/control/clients 不返回 uid，故"已匹配"以 agh_synced_name 为准（已有 name 不覆盖） */
function importAdGuardClients(clientsPayload) {
  const list = (clientsPayload && clientsPayload.clients) || [];
  let imported = 0;
  for (const c of list) {
    const ids = c.ids || [];
    const macs = ids.map(normalizeMac).filter(Boolean);
    const ips = ids.filter((i) => !normalizeMac(i));
    let device = null;
    for (const m of macs) { device = findDeviceByMac(m); if (device) break; }
    if (!device && ips.length) device = ownerOfIp(ips[0]);
    if (!device && macs.length) device = createDevice(macs[0], { name: c.name, source: 'agh_import' });
    if (!device && ips.length) device = createDevice('ip:' + ips[0], { name: c.name, source: 'agh_import' });
    if (!device) continue;

    const ts = nowIso();
    db.prepare(`UPDATE devices SET name = COALESCE(NULLIF(name,''), ?), agh_uid = ?, agh_synced_name = ?,
      updated_at = ? WHERE id = ?`).run(c.name || null, c.uid || null, c.name || null, ts, device.id);
    for (const m of macs) {
      db.prepare('INSERT INTO device_macs (mac, device_id, source, first_seen, last_seen) VALUES (?,?,?,?,?) ON CONFLICT(mac) DO NOTHING')
        .run(m, device.id, 'agh_import', ts, ts);
    }
    for (const ip of ips) upsertIp(device.id, { ip, source: 'agh' });
    imported++;
  }
  return { imported, total: list.length };
}

/* ------------------------- 查询 ------------------------- */

/** 两个时间尺度：ipActiveWindowMs = 邻居表/租约最近还观测到（说明此刻仍持有）；statsWindowMs = AdGuard 统计保留时长（同步客户端 ids 用的就是这个窗口） */
function ipActiveWindowMs() {
  const iv = Number(settingGet('collect_interval_sec', 300)) || 300;
  return Math.max(3600 * 1000, iv * 6 * 1000);
}

const DEFAULT_STATS_WINDOW_MS = 24 * 3600 * 1000;

function statsWindowMs() {
  const n = Number(settingGet('agh_stats_interval_ms', DEFAULT_STATS_WINDOW_MS));
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_STATS_WINDOW_MS;
}

function deviceSummary(row, ownerMap, { withStats = true } = {}) {
  const ips = db.prepare('SELECT ip, ip_ver, last_seen, first_seen, source, interface, is_static FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC').all(row.id);
  const macs = db.prepare('SELECT mac, source FROM device_macs WHERE device_id = ?').all(row.id);
  const ipMap = ownerMap || ipOwnerMap();   // 列表场景由调用方传入，避免每台设备都全表扫一次
  const current = ips.filter((i) => ipMap.get(i.ip) === row.id);
  const currentV4 = current.filter((i) => i.ip_ver === 4);
  const currentV6 = current.filter((i) => i.ip_ver === 6);
  const now = Date.now();
  // 24h 统计只在设备详情页用到；列表页不查（设备多时逐台查会很慢）
  const stats = withStats
    ? (db.prepare(`SELECT COUNT(*) AS queries, SUM(blocked) AS blocked FROM query_log WHERE device_id = ? AND ts >= ?`)
        .get(row.id, now - 24 * 3600 * 1000) || {})
    : {};
  // 每个 IP 在统计窗口内的查询数：详情页用来标出哪些地址真的还有流量（与同步口径一致）
  const winMs = statsWindowMs();
  const ipQueries = new Map();
  if (withStats) {
    for (const r of db.prepare('SELECT client_ip, COUNT(*) AS n FROM query_log WHERE device_id = ? AND ts >= ? GROUP BY client_ip')
      .all(row.id, now - winMs)) {
      ipQueries.set(String(r.client_ip).toLowerCase(), r.n);
    }
  }
  const activeWindow = ipActiveWindowMs();
  const q = (ip) => ipQueries.get(String(ip).toLowerCase()) || 0;
  const ipsOut = ips.map((i) => ({
    ...i,
    queries: q(i.ip),
    recently_seen: !!Date.parse(i.last_seen || '') && (now - Date.parse(i.last_seen)) < activeWindow
  }));
  return {
    id: row.id,
    anchor: row.anchor,
    mac: MAC_RE.test(row.anchor) ? row.anchor : (macs[0] && macs[0].mac) || null,
    macs: macs.map((m) => m.mac),
    name: row.name,
    display_name: row.name || row.suggested_name || `未命名-${(row.anchor || '').replace(/[^0-9a-z]/gi, '').slice(-6)}`,
    suggested_name: row.suggested_name,
    vendor: row.vendor,
    category: row.category,
    tags: safeJson(row.tags, []),
    notes: row.notes,
    ignored: !!row.ignored,
    random_mac: !!row.random_mac,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    agh_uid: row.agh_uid,
    agh_synced_name: row.agh_synced_name,
    current_ip: currentV4[0] ? currentV4[0].ip : (current[0] ? current[0].ip : null),
    current_ips: current.map((i) => i.ip),
    current_ipv6: currentV6.map((i) => i.ip),
    // 真正"还在用"的地址：统计窗口内有查询，或最近一个活跃窗口内还被邻居表/租约观测到
    active_ips: current
      .filter((i) => q(i.ip) > 0 || (now - (Date.parse(i.last_seen) || 0)) < activeWindow)
      .map((i) => i.ip),
    active_window_sec: Math.round(activeWindow / 1000),
    stats_window_sec: Math.round(winMs / 1000),
    interfaces: [...new Set(ips.map((i) => i.interface).filter(Boolean))],
    ip_count: ips.length,
    ips: ipsOut,
    queries_24h: stats.queries || 0,
    blocked_24h: stats.blocked || 0
  };
}

function safeJson(s, fb) { try { return JSON.parse(s); } catch (e) { return fb; } }

function listDevices({ query = '', filter = 'all', category = '', tag = '' } = {}) {
  const rows = db.prepare('SELECT * FROM devices ORDER BY last_seen DESC').all();
  const ownerMap = ipOwnerMap();                       // 只算一次
  const result = rows.map((r) => deviceSummary(r, ownerMap, { withStats: false }));
  let out = result;
  if (filter === 'named') out = out.filter((d) => !!d.name);
  else if (filter === 'unnamed') out = out.filter((d) => !d.name);
  else if (filter === 'ignored') out = out.filter((d) => d.ignored);
  else if (filter === 'random') out = out.filter((d) => d.random_mac);
  else if (filter === 'active') out = out.filter((d) => d.last_seen && Date.now() - Date.parse(d.last_seen) < 24 * 3600 * 1000);
  else if (filter !== 'all') out = out.filter((d) => !d.ignored);
  if (category === '__none__') out = out.filter((d) => !d.category);
  else if (category) out = out.filter((d) => d.category === category);
  if (tag) out = out.filter((d) => (d.tags || []).includes(tag));
  if (query) {
    const q = query.toLowerCase();
    out = out.filter((d) =>
      (d.name || '').toLowerCase().includes(q) ||
      (d.suggested_name || '').toLowerCase().includes(q) ||
      (d.mac || '').toLowerCase().includes(q) ||
      (d.current_ips || []).some((ip) => ip.includes(q)) ||
      (d.vendor || '').toLowerCase().includes(q) ||
      (d.notes || '').toLowerCase().includes(q) ||
      (d.tags || []).some((t) => String(t).toLowerCase().includes(q)) ||
      (d.category || '').toLowerCase().includes(q) ||
      d.macs.some((m) => m.includes(q))
    );
  }
  const allCategories = [...new Set(result.map((d) => d.category).filter(Boolean))].sort();
  const allTags = [...new Set(result.flatMap((d) => d.tags || []))].sort();
  // 关联建议：同主机名的多个设备（很可能同一台设备更换了 MAC/IP）
  const byHost = new Map();
  for (const d of result) {
    const h = (d.suggested_name || '').toLowerCase().trim();
    if (!h) continue;
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h).push({ id: d.id, mac: d.mac, name: d.display_name });
  }
  const hints = [];
  for (const [host, group] of byHost) {
    if (group.length > 1) hints.push({ type: 'same_hostname', hostname: host, devices: group });
  }
  return { devices: out, hints, total: result.length, categories: allCategories, tags: allTags };
}

/** 批量修改多台设备（忽略 / 分类 / 标签等） */
function bulkUpdate(ids, patch) {
  const list = (Array.isArray(ids) ? ids : []).map(Number).filter((n) => Number.isInteger(n) && n > 0);
  if (!list.length) throw httpError(400, '未选择设备');
  const tx = db.transaction(() => { for (const id of list) updateDevice(id, patch); });
  tx();
  return { updated: list.length };
}

function getDevice(id) {
  const row = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
  if (!row) return null;
  const d = deviceSummary(row);
  d.macs_detail = db.prepare('SELECT mac, source, first_seen, last_seen FROM device_macs WHERE device_id = ?').all(row.id);
  d.recent_logs = db.prepare('SELECT * FROM query_log WHERE device_id = ? ORDER BY ts DESC LIMIT 50').all(row.id);
  return d;
}

function updateDevice(id, patch) {
  const allow = ['name', 'category', 'tags', 'notes', 'ignored', 'vendor'];
  const sets = [];
  const vals = [];
  for (const k of allow) {
    if (k in patch) {
      sets.push(`${k} = ?`);
      vals.push(k === 'tags' ? JSON.stringify(patch[k] || []) : (typeof patch[k] === 'boolean' ? (patch[k] ? 1 : 0) : patch[k]));
    }
  }
  if (!sets.length) return getDevice(id);
  sets.push('updated_at = ?');
  vals.push(nowIso(), id);
  db.prepare(`UPDATE devices SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  return getDevice(id);
}

function addManualIp(id, ip, { hostname, isStatic } = {}) {
  const addr = String(ip || '').trim();
  if (!addr) throw httpError(400, 'IP 不能为空');
  upsertIp(id, { ip: addr, source: 'manual', hostname, isStatic });
  touchDevice(id, {});
  return getDevice(id);
}

function removeIp(id, ip) {
  db.prepare('DELETE FROM device_ips WHERE device_id = ? AND ip = ?').run(id, String(ip));
  return getDevice(id);
}

/** 合并设备：把 source 的所有 MAC/IP/日志并入 target */
function mergeDevices(sourceId, targetId) {
  if (Number(sourceId) === Number(targetId)) throw httpError(400, '不能与自己合并');
  const src = db.prepare('SELECT * FROM devices WHERE id = ?').get(sourceId);
  const tgt = db.prepare('SELECT * FROM devices WHERE id = ?').get(targetId);
  if (!src || !tgt) throw httpError(404, '设备不存在');
  const tx = db.transaction(() => {
    db.prepare('UPDATE device_macs SET device_id = ? WHERE device_id = ?').run(targetId, sourceId);
    const ips = db.prepare('SELECT * FROM device_ips WHERE device_id = ?').all(sourceId);
    for (const row of ips) {
      upsertIp(targetId, { ip: row.ip, mac: row.mac, hostname: row.hostname, clientId: row.client_id, iface: row.interface, source: row.source, isStatic: !!row.is_static, seenAt: row.last_seen });
    }
    db.prepare('DELETE FROM device_ips WHERE device_id = ?').run(sourceId);
    db.prepare('UPDATE query_log SET device_id = ? WHERE device_id = ?').run(targetId, sourceId);
    // 合并首/末次出现时间（ISO 字符串可直接按字典序比较），并继承 AdGuard 匹配信息
    const first = [tgt.first_seen, src.first_seen].filter(Boolean).sort()[0] || nowIso();
    const last = [tgt.last_seen, src.last_seen].filter(Boolean).sort().pop() || nowIso();
    db.prepare(`UPDATE devices SET first_seen = ?, last_seen = ?, updated_at = ?,
      agh_uid = COALESCE(agh_uid, ?), agh_synced_name = COALESCE(agh_synced_name, ?) WHERE id = ?`)
      .run(first, last, nowIso(), src.agh_uid || null, src.agh_synced_name || null, targetId);
    db.prepare('DELETE FROM devices WHERE id = ?').run(sourceId);
  });
  tx();
  return getDevice(targetId);
}

/** 删除设备台账记录，返回实际删除的行数（0 表示该 id 不存在） */
function deleteDevice(id) {
  return db.prepare('DELETE FROM devices WHERE id = ?').run(id).changes;
}

function restartDeviceAnchor(mac, deviceId) {
  const m = normalizeMac(mac);
  if (!m) throw httpError(400, 'MAC 格式不正确');
  const ts = nowIso();
  db.prepare('INSERT INTO device_macs (mac, device_id, source, first_seen, last_seen) VALUES (?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET device_id = excluded.device_id')
    .run(m, deviceId, 'manual', ts, ts);
  return getDevice(deviceId);
}

module.exports = {
  normalizeMac, isRandomMac, isIpv6, isPrivateIp, isRouterIp, routerIpList,
  observe, ownerOfIp, ipOwnerMap, ipOwnerTimeline, resolveOwnerAt, applyCollected,
  importAdGuardClients, listDevices, getDevice, updateDevice, bulkUpdate,
  addManualIp, removeIp, mergeDevices, deleteDevice, restartDeviceAnchor, deviceSummary
};
