'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const { db, settingSet, allSettings, recordJob } = require('./db');
const { encrypt } = require('./crypto');
const auth = require('./auth');
const jobs = require('./jobs');
const D = require('./devices');
const ingest = require('./ingest');
const oui = require('./oui');
const agh = require('./aghclients');
const sysinfo = require('./sysinfo');
const sinkhole = require('./sinkhole');
const sinkcerts = require('./sinkcerts');
const { listConnections, getConnection, sshOptions, adguardClient } = require('./connections');
const { sshExec } = require('./sshclient');
const { httpError } = require('./httperr');

const router = express.Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** CSV 字段转义 */
function csvCell(v) {
  return `"${String(v === null || v === undefined ? '' : v).replace(/"/g, '""').replace(/[\r\n]+/g, ' ')}"`;
}

/* --------------------------- 认证 --------------------------- */

router.get('/setup/status', (req, res) => {
  res.json({ setup_done: auth.hasAdmin() });
});

// 该接口在初始化完成前无需登录：按来源限流，并把创建者与时间写入日志与任务记录
router.post('/setup', wrap((req, res) => {
  if (auth.hasAdmin()) throw httpError(409, '已完成初始化，请直接登录');
  if (auth.setupRateLimited(req.ip)) {
    console.warn(`[setup] 来源 ${req.ip} 的初始化请求过于频繁，已拒绝（${new Date().toISOString()}）`);
    throw httpError(429, '尝试次数过多，请 10 分钟后再试');
  }
  const { username, password } = req.body || {};
  const name = String(username || '').trim() || 'admin';
  auth.noteSetupAttempt(req.ip);
  auth.createAdmin(name, password);
  const { token } = auth.login(name, password, req.ip, req.headers['user-agent']);
  auth.setCookie(res, token, req.secure);
  const msg = `管理员「${name}」由 ${req.ip} 创建`;
  console.warn(`[setup] ${msg}（${new Date().toISOString()}）。若非本人操作，请立即重置口令。`);
  try { recordJob('setup', 'success', msg); } catch (e) { /* 记录失败不影响初始化 */ }
  res.json({ ok: true });
}));

router.post('/login', wrap((req, res) => {
  const { username, password } = req.body || {};
  const { token } = auth.login(username, password, req.ip, req.headers['user-agent']);
  auth.setCookie(res, token, req.secure);
  res.json({ ok: true });
}));

router.post('/logout', (req, res) => {
  auth.logout(req.cookies && req.cookies[auth.COOKIE]);
  auth.clearCookie(res);
  res.json({ ok: true });
});

router.get('/me', auth.requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username }, setup_done: true });
});

router.post('/password', auth.requireAuth, wrap((req, res) => {
  const { old_password, new_password } = req.body || {};
  auth.changePassword(req.user.id, old_password, new_password, req.user.token);
  res.json({ ok: true });
}));

/* 以下均需登录 */
router.use(auth.requireAuth);

// 任何写操作 (非 GET) 完成后清掉统计缓存，保证下一次读取拿到最新数字
router.use((req, res, next) => {
  if (req.method !== 'GET') res.on('finish', () => { try { ingest.invalidateStats(); } catch (e) { /* ignore */ } });
  next();
});

/* --------------------------- 设置 --------------------------- */

router.get('/settings', (req, res) => {
  res.json({ settings: allSettings() });
});

router.put('/settings', wrap((req, res) => {
  const patch = req.body || {};
  const allow = Object.keys(require('./config').DEFAULT_SETTINGS);
  for (const [k, v] of Object.entries(patch)) {
    if (allow.includes(k)) settingSet(k, v);
  }
  jobs.restart();
  res.json({ ok: true, settings: allSettings() });
}));

router.get('/status', (req, res) => {
  res.json(jobs.status());
});

router.get('/jobs', (req, res) => {
  res.json({ jobs: db.prepare('SELECT * FROM job_runs ORDER BY id DESC LIMIT 100').all() });
});

// 运行本系统的这台机器自身的系统/硬件/温度信息（只读，供「设置 → 运行环境」展示）
router.get('/sysinfo', (req, res) => {
  res.json(sysinfo.snapshot());
});

/* --------------------------- 连接 --------------------------- */

router.get('/connections', (req, res) => {
  res.json({ connections: listConnections() });
});

function saveConnectionFields(body, isUpdate) {
  const fields = {
    kind: body.kind,
    name: body.name,
    enabled: body.enabled === undefined ? 1 : (body.enabled ? 1 : 0),
    host: body.host || null,
    port: body.port ? Number(body.port) : null,
    username: body.username || null,
    auth_type: body.auth_type || 'password',
    base_url: body.base_url || null,
    verify_tls: body.verify_tls === undefined ? 1 : (body.verify_tls ? 1 : 0),
    remark: body.remark || null
  };
  if (body.secret) fields.secret_enc = encrypt(body.secret);
  if (body.passphrase) fields.passphrase_enc = encrypt(body.passphrase);
  if (isUpdate && !body.secret) delete fields.secret_enc;
  if (isUpdate && !body.passphrase) delete fields.passphrase_enc;
  return fields;
}

router.post('/connections', wrap((req, res) => {
  const body = req.body || {};
  if (!body.kind || !body.name) throw httpError(400, 'kind 与 name 必填');
  const f = saveConnectionFields(body, false);
  const cols = Object.keys(f);
  const info = db.prepare(`INSERT INTO connections (${cols.join(',')}, created_at, updated_at) VALUES (${cols.map(() => '?').join(',')},?,?)`)
    .run(...cols.map((c) => f[c]), new Date().toISOString(), new Date().toISOString());
  res.json({ ok: true, id: info.lastInsertRowid });
}));

router.put('/connections/:id', wrap((req, res) => {
  const id = Number(req.params.id);
  if (!getConnection(id)) throw httpError(404, '连接不存在');
  const f = saveConnectionFields(req.body || {}, true);
  const cols = Object.keys(f);
  db.prepare(`UPDATE connections SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = ? WHERE id = ?`)
    .run(...cols.map((c) => f[c]), new Date().toISOString(), id);
  res.json({ ok: true });
}));

router.delete('/connections/:id', wrap((req, res) => {
  const info = db.prepare('DELETE FROM connections WHERE id = ?').run(Number(req.params.id));
  // 同上：删不存在的连接以前也回 ok:true
  if (!info.changes) throw httpError(404, '连接不存在');
  res.json({ ok: true });
}));

router.post('/connections/:id/test', wrap(async (req, res) => {
  const row = getConnection(Number(req.params.id));
  if (!row) throw httpError(404, '连接不存在');
  if (row.kind === 'ssh') {
    const out = await sshExec(sshOptions(row), 'echo SSH_OK; uname -a; uptime', { timeoutMs: 15000 });
    res.json({ ok: /SSH_OK/.test(out.stdout), output: out.stdout.trim(), stderr: out.stderr.trim() });
  } else {
    const adg = adguardClient(row);
    const info = await adg.test();
    res.json({ ok: true, info });
  }
}));

/* --------------------------- 采集（只读） --------------------------- */

router.post('/collect', wrap(async (req, res) => {
  const stat = await jobs.runCollect();
  res.json({ ok: true, stat });
}));

router.post('/ingest', wrap(async (req, res) => {
  const days = req.body && req.body.days ? Number(req.body.days) : null;
  const stat = await jobs.runIngest(days ? { days } : {});
  res.json({ ok: true, stat });
}));

// 读取 AdGuard 持久客户端并匹配到本系统台账（只读，用于继承已有中文名）
router.post('/agh/import', wrap(async (req, res) => {
  const stat = await jobs.runImportClients();
  res.json({ ok: true, stat });
}));

/* --------------------------- 设备 --------------------------- */

router.get('/devices', (req, res) => {
  const { query = '', filter = 'all', category = '', tag = '' } = req.query;
  res.json(D.listDevices({
    query: String(query), filter: String(filter),
    category: String(category), tag: String(tag)
  }));
});

router.get('/devices/:id', (req, res) => {
  const d = D.getDevice(Number(req.params.id));
  if (!d) return res.status(404).json({ error: '设备不存在' });
  res.json({ device: d });
});

router.put('/devices/:id', wrap((req, res) => {
  const d = D.updateDevice(Number(req.params.id), req.body || {});
  if (!d) throw httpError(404, '设备不存在');
  res.json({ ok: true, device: d });
}));

router.post('/devices/:id/ips', wrap((req, res) => {
  const { ip, isStatic, hostname } = req.body || {};
  const d = D.addManualIp(Number(req.params.id), ip, { isStatic, hostname });
  res.json({ ok: true, device: d });
}));

router.delete('/devices/:id/ips', wrap((req, res) => {
  const d = D.removeIp(Number(req.params.id), req.query.ip);
  res.json({ ok: true, device: d });
}));

router.post('/devices/:id/macs', wrap((req, res) => {
  const d = D.restartDeviceAnchor(req.body && req.body.mac, Number(req.params.id));
  res.json({ ok: true, device: d });
}));

router.post('/devices/bulk', wrap((req, res) => {
  const { ids, patch } = req.body || {};
  res.json({ ok: true, ...D.bulkUpdate(ids, patch || {}) });
}));

router.post('/devices/bulk-delete', wrap((req, res) => {
  const ids = (req.body && req.body.ids) || [];
  let deleted = 0;
  for (const id of ids) deleted += D.deleteDevice(Number(id));
  res.json({ ok: true, deleted });
}));

router.post('/devices/merge', wrap((req, res) => {
  const { sourceId, targetId } = req.body || {};
  const d = D.mergeDevices(Number(sourceId), Number(targetId));
  res.json({ ok: true, device: d });
}));

router.delete('/devices/:id', wrap((req, res) => {
  // deleteDevice 返回实际删除的行数（0 = 该 id 不存在），以前被丢弃，删不存在的设备也会回 ok:true
  const deleted = D.deleteDevice(Number(req.params.id));
  if (!deleted) throw httpError(404, '设备不存在');
  res.json({ ok: true, deleted });
}));

/* --------------------------- 日志与统计 --------------------------- */

router.get('/overview', (req, res) => {
  res.json(ingest.overview(String(req.query.range || '24h'), { root: req.query.root === 'true' }));
});

router.get('/stats/devices', (req, res) => {
  res.json({ rows: ingest.deviceStats(String(req.query.range || '24h')) });
});

router.get('/stats/top', (req, res) => {
  const blocked = req.query.blocked === undefined || req.query.blocked === '' ? null : req.query.blocked === 'true';
  res.json({
    rows: ingest.topDomains({
      range: String(req.query.range || '24h'),
      blocked,
      deviceId: req.query.deviceId ? String(req.query.deviceId) : null,
      limit: req.query.limit ? Number(req.query.limit) : 30,
      root: req.query.root === 'true'
    })
  });
});

router.get('/logs', (req, res) => {
  const q = req.query;
  const blocked = q.blocked === undefined || q.blocked === '' ? null : q.blocked === 'true';
  res.json(ingest.listLogs({
    deviceId: q.deviceId ? String(q.deviceId) : null,
    blocked,
    domain: String(q.domain || ''),
    clientIp: String(q.clientIp || ''),
    from: q.from ? Number(q.from) : null,
    to: q.to ? Number(q.to) : null,
    page: q.page, size: q.size
  }));
});

// 异常画像：零拦截的高流量设备 / 查询频率过高
router.get('/stats/anomalies', (req, res) => {
  res.json({ rows: ingest.anomalies({ range: String(req.query.range || '24h') }) });
});

// 按 IP 汇总的"未能归属到设备"的日志（不含路由器本机）
router.get('/logs/unmapped-ips', (req, res) => {
  res.json({
    rows: ingest.unmappedIps({
      range: String(req.query.range || '24h'),
      limit: req.query.limit ? Number(req.query.limit) : 100
    })
  });
});

// 把某个 IP 指派给设备，并回填该 IP 的历史未归属日志
router.post('/logs/assign-ip', wrap((req, res) => {
  const { ip, deviceId } = req.body || {};
  res.json({ ok: true, ...ingest.assignIp(ip, Number(deviceId)) });
}));

// 清理未归属的历史日志
router.post('/logs/prune-unmapped', wrap((req, res) => {
  res.json({ ok: true, ...ingest.pruneUnmapped() });
}));

/* --------------------------- AdGuard 客户端管理（写操作受 allow_agh_write 控制） --------------------------- */

router.get('/agh/clients', wrap(async (req, res) => { res.json(await agh.listClients()); }));

// 差异预览：不写入，只返回将新增/移除哪些 id
router.get('/agh/clients/plan', wrap(async (req, res) => {
  res.json(await agh.planForDevice(String(req.query.name || ''), Number(req.query.deviceId), {
    includeUnknown: req.query.includeUnknown === 'true'
  }));
}));

// includeUnknown 必须透传，否则"一并清理未知项"只在预览里生效、真正写入时又保留，出现"预览说要删、结果没删"的不一致
router.post('/agh/clients', wrap(async (req, res) => {
  const { name, deviceId, includeUnknown } = req.body || {};
  res.json({ ok: true, ...(await agh.applyForDevice(name, Number(deviceId), { includeUnknown: !!includeUnknown })) });
}));

// 批量 / 全量的差异预览（只读，不写入）。names 省略 = 所有客户端
router.get('/agh/clients/plan-batch', wrap(async (req, res) => {
  const names = String(req.query.names || '').split(',').map((s) => s.trim()).filter(Boolean);
  res.json(await agh.planBatch(names.length ? names : null, { includeUnknown: req.query.includeUnknown === 'true' }));
}));

// 批量 / 全量同步：names 省略 = 全量（只处理"可管理"的客户端）
router.post('/agh/clients/sync', wrap(async (req, res) => {
  const { names, includeUnknown } = req.body || {};
  res.json({ ok: true, ...(await agh.applyBatch(Array.isArray(names) && names.length ? names : null, { includeUnknown: !!includeUnknown })) });
}));

router.post('/agh/clients/delete', wrap(async (req, res) => {
  res.json({ ok: true, ...(await agh.removeClient((req.body || {}).name)) });
}));

// 扫描所有客户端里已失效的 id（只读）
router.get('/agh/stale', wrap(async (req, res) => { res.json({ rows: await agh.scanStale() }); }));

// 清理失效 id：只传客户端名字，ids 由服务端按规则重算（不采信前端传来的 ids）
router.post('/agh/stale/clean', wrap(async (req, res) => {
  res.json({ ok: true, ...(await agh.cleanStale(req.body || {})) });
}));

/* --------------------------- 拦截流量分析（sinkhole） --------------------------- */
/* 拦截流量分析：只读查询 + 少量用户主动确认的清理；不写路由器 / AdGuard 任何配置 */

router.get('/sink/status', (req, res) => res.json(sinkhole.status()));

router.get('/sink/overview', (req, res) => {
  res.json(ingest.sinkOverview(String(req.query.range || '24h')));
});

router.get('/sink/stats/devices', (req, res) => {
  res.json({ rows: ingest.sinkDeviceStats(String(req.query.range || '24h')) });
});

router.get('/sink/stats/hosts', (req, res) => {
  res.json({
    rows: ingest.sinkHostStats({
      range: String(req.query.range || '24h'),
      deviceId: req.query.deviceId ? String(req.query.deviceId) : null,
      proto: String(req.query.proto || ''),
      limit: req.query.limit ? Number(req.query.limit) : 50
    })
  });
});

// 按 User-Agent 聚合（同一 App 常把上报分散到多个域名，UA 反而更容易看清是谁在报）
router.get('/sink/stats/uas', (req, res) => {
  res.json({
    rows: ingest.sinkUaStats({
      range: String(req.query.range || '24h'),
      deviceId: req.query.deviceId ? String(req.query.deviceId) : null,
      proto: String(req.query.proto || ''),
      limit: req.query.limit ? Number(req.query.limit) : 50
    })
  });
});

// 按 JA4 指纹聚合（仅 SNI 的记录也能用，用来把"同一个 App 的多个域名"串起来）
router.get('/sink/stats/fp', (req, res) => {
  res.json({
    rows: ingest.sinkFpStats({
      range: String(req.query.range || '24h'),
      deviceId: req.query.deviceId ? String(req.query.deviceId) : null,
      proto: String(req.query.proto || ''),
      limit: req.query.limit ? Number(req.query.limit) : 50
    })
  });
});

// 明细筛选参数：列表与 CSV 导出共用，保证"导出的就是看到的"
function sinkFiltersFromQuery(q) {
  return {
    deviceId: q.deviceId ? String(q.deviceId) : null,
    host: String(q.host || ''),
    ua: String(q.ua || ''),
    queryStr: String(q.q || ''),
    outcome: String(q.outcome || ''),
    ja4: String(q.ja4 || ''),
    proto: String(q.proto || ''),
    lport: q.lport ? Number(q.lport) : null,
    bodyKind: String(q.bodyKind || ''),
    body: String(q.body || ''),
    decrypted: q.decrypted === undefined || q.decrypted === '' ? null : q.decrypted === 'true',
    range: String(q.range || '24h')
  };
}

router.get('/sink/events', (req, res) => {
  const q = req.query;
  res.json(ingest.sinkListEvents(Object.assign(sinkFiltersFromQuery(q), { page: q.page, size: q.size })));
});

// 未能归属到设备的连接记录（按 IP 汇总，可一键指派）
router.get('/sink/unmapped-ips', (req, res) => {
  res.json({
    rows: ingest.sinkUnmappedIps({
      range: String(req.query.range || '24h'),
      limit: req.query.limit ? Number(req.query.limit) : 100
    })
  });
});

router.post('/sink/assign-ip', wrap((req, res) => {
  const { ip, deviceId } = req.body || {};
  res.json({ ok: true, ...ingest.sinkAssignIp(ip, Number(deviceId)) });
}));

router.post('/sink/prune-unmapped', wrap((req, res) => {
  res.json({ ok: true, ...ingest.sinkPruneUnmapped() });
}));

// 清空全部连接记录（危险操作，前端需二次确认）
router.post('/sink/clear', wrap((req, res) => {
  res.json({ ok: true, ...ingest.sinkClear() });
}));

// 手动把内存里聚合中的事件落库，便于"刚验证完就想立刻看到"
router.post('/sink/flush', wrap((req, res) => {
  res.json({ ok: true, ...sinkhole.flush() });
}));

router.get('/sink/export.csv', (req, res) => {
  const rows = ingest.sinkExport(sinkFiltersFromQuery(req.query));
  // 导出必须与界面一致：完整头部、源端口、耗时、应答方式等界面能看到的都要带上，否则取证交付时没法用
  const header = ['首次出现', '最后一次', '次数', '设备', '客户端IP', '客户端源端口', '协议', '端口',
    '主机(SNI/Host)', '方法', '路径', '查询串', 'HTTP版本', 'User-Agent', '来源页',
    '内容可读', '正文长度', '正文预览', '内容类型', '内容编码', '字符集', '正文类型', '结构化字段',
    'TLS版本', 'TLS套件', '客户端套件数', 'JA3', 'JA4', 'ALPN',
    '应答', '耗时(ms)', '备注', '完整头部'];
  const lines = rows.map((r) => [
    new Date(r.ts).toISOString(), new Date(r.last_ts).toISOString(), r.hits,
    r.device_name || '', r.client_ip || '', r.client_port == null ? '' : r.client_port,
    r.proto || '', r.lport || '', r.host || '',
    r.method || '', r.path || '', r.query || '', r.http_ver || '', r.ua || '', r.referer || '',
    (r.decrypted || r.proto === 'http') ? '明文' : '仅SNI',
    r.body_bytes == null ? '' : r.body_bytes, r.body_preview || '',
    r.content_type || '', r.content_encoding || '', r.charset || '', r.body_kind || '', r.body_fields || '',
    r.tls_version || '', r.tls_cipher || '', r.tls_client_ciphers == null ? '' : r.tls_client_ciphers,
    r.ja3 || '', r.ja4 || '', r.alpn || '', r.outcome || '', r.duration_ms == null ? '' : r.duration_ms,
    r.tls_note || '', r.headers_json || ''
  ].map(csvCell).join(','));
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="sinkhole-${stamp}.csv"`);
  res.send('\ufeff' + [header.join(','), ...lines].join('\n'));
});

// 下载自签根证书：要在目标设备上解 HTTPS 明文，必须先把这张证书装进设备的受信任根列表
router.get('/sink/ca.crt', wrap((req, res) => {
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.setHeader('Content-Disposition', 'attachment; filename="adh-device-hub-sinkhole-ca.crt"');
  res.send(sinkcerts.caCertPem());
}));

/* --------------------------- 数据库维护 / 备份 --------------------------- */

router.get('/db/info', (req, res) => {
  res.json(ingest.dbInfo());
});

router.post('/db/vacuum', wrap((req, res) => {
  res.json({ ok: true, ...ingest.vacuum() });
}));

// 下载数据库快照（用 SQLite 在线备份 API，保证一致性；不含 secret.key）
router.get('/backup/db', wrap(async (req, res) => {
  const tmp = path.join(os.tmpdir(), `adh-device-hub-${Date.now()}.db`);
  await db.backup(tmp);
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '');
  res.download(tmp, `adh-device-hub-${stamp}.db`, (err) => {
    // 下载中断（客户端取消、连接断）以前是彻底无声的，用户只会拿到一个不完整的文件
    if (err) console.warn(`[backup] 数据库快照下载未完成：${err.message}`);
    // 删不掉就是一份完整的库副本留在临时目录（库动辄几百 MB），不记下来磁盘会被慢慢吃掉且无迹可循
    try {
      fs.unlinkSync(tmp);
    } catch (e) {
      console.warn(`[backup] 临时快照清理失败，请手工删除：${tmp}（${e.message}）`);
    }
  });
}));

/* --------------------------- OUI / 导出 --------------------------- */

router.get('/oui/stats', (req, res) => res.json(oui.stats()));

router.post('/oui/update', wrap(async (req, res) => {
  const r = await oui.updateOnline();
  res.json({ ok: true, result: r });
}));

router.get('/export/devices.csv', (req, res) => {
  const { devices } = D.listDevices({});
  const header = ['名称', '分类', '标签', 'MAC', '当前IP', '历史IP数', '厂商', '随机MAC', '忽略', 'AdGuard同名客户端', '最后活动', '备注'];
  const lines = devices.map((d) => [
    d.display_name, d.category || '', (d.tags || []).join(' '), d.macs.join(' '), d.current_ip || '', d.ip_count,
    d.vendor || '', d.random_mac ? '是' : '', d.ignored ? '是' : '', d.agh_synced_name || '', d.last_seen || '', d.notes || ''
  ].map(csvCell).join(','));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="devices.csv"');
  res.send('\ufeff' + [header.join(','), ...lines].join('\n'));
});

router.get('/export/logs.csv', (req, res) => {
  const q = req.query;
  const blocked = q.blocked === undefined || q.blocked === '' ? null : q.blocked === 'true';
  const rows = ingest.exportLogs({
    deviceId: q.deviceId ? String(q.deviceId) : null,
    blocked,
    domain: String(q.domain || ''),
    clientIp: String(q.clientIp || ''),
    from: q.from ? Number(q.from) : null,
    to: q.to ? Number(q.to) : null
  });
  const header = ['时间', '设备', '客户端IP', '域名', '类型', '结果', '状态', '命中规则', '上游'];
  const lines = rows.map((r) => [
    new Date(r.ts).toISOString(), r.device_name || '', r.client_ip || '', r.domain || '', r.qtype || '',
    r.blocked ? '拦截' : '放行', r.status || '', r.rule || r.reason || '', r.upstream || ''
  ].map(csvCell).join(','));
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="querylog-${stamp}.csv"`);
  res.send('\ufeff' + [header.join(','), ...lines].join('\n'));
});

module.exports = router;
