'use strict';

const Database = require('better-sqlite3');
const { DB_FILE, DEFAULT_SETTINGS } = require('./config');

const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
// 针对 SD 卡 / 低配设备的 SQLite 调优：NORMAL 同步、临时表放内存、32MB 页缓存、
// 降低 checkpoint 频率、限制 WAL 大小、忙时等待而非直接报错
db.pragma('synchronous = NORMAL');
db.pragma('temp_store = MEMORY');
db.pragma('cache_size = -32000');
db.pragma('wal_autocheckpoint = 2000');
db.pragma('journal_size_limit = 16777216');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT,
  ua TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                -- ssh | adguard
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  host TEXT,
  port INTEGER,
  username TEXT,
  auth_type TEXT,                    -- password | key
  secret_enc TEXT,                   -- 加密后的 口令 / 私钥内容
  passphrase_enc TEXT,
  base_url TEXT,
  verify_tls INTEGER NOT NULL DEFAULT 1,
  remark TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anchor TEXT NOT NULL UNIQUE,        -- 锚点：MAC 或 ip:<addr>（AGH 仅有 IP 时）
  name TEXT,                          -- 中文备注名
  suggested_name TEXT,                -- 采集到的建议名（主机名等）
  vendor TEXT,
  category TEXT,
  tags TEXT NOT NULL DEFAULT '[]',
  notes TEXT,
  ignored INTEGER NOT NULL DEFAULT 0,
  random_mac INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT,
  agh_uid TEXT,                        -- AdGuard 中同名客户端的 uid（仅用于识别/匹配，不写回）
  agh_synced_name TEXT,                -- AdGuard 中同名客户端的名称（只读参考）
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS device_macs (
  mac TEXT PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  source TEXT,
  first_seen TEXT,
  last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_macs_dev ON device_macs(device_id);

CREATE TABLE IF NOT EXISTS device_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  mac TEXT,
  ip TEXT NOT NULL,
  ip_ver INTEGER NOT NULL DEFAULT 4,
  hostname TEXT,
  client_id TEXT,
  interface TEXT,
  source TEXT,                        -- dhcp_lease | arp | arp6 | agh | manual | static
  is_static INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT,
  UNIQUE(device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip);
CREATE INDEX IF NOT EXISTS idx_device_ips_dev ON device_ips(device_id);

CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,                -- epoch ms
  client_ip TEXT,
  device_id INTEGER,
  device_name TEXT,
  domain TEXT,
  qtype TEXT,
  status TEXT,
  reason TEXT,
  rule TEXT,
  upstream TEXT,
  answer TEXT,
  elapsed_ms REAL,
  blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ql_ts ON query_log(ts);
CREATE INDEX IF NOT EXISTS idx_ql_dev ON query_log(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_ql_blocked ON query_log(blocked, ts);
CREATE INDEX IF NOT EXISTS idx_ql_domain ON query_log(domain);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ql_uniq ON query_log(ts, client_ip, domain, qtype);
-- 覆盖索引：时间窗口 + 拦截标记 + 域名（趋势图、Top 域名、各项计数都只读索引不回表，低配设备上差别明显）
CREATE INDEX IF NOT EXISTS idx_ql_ts_blocked_domain ON query_log(ts, blocked, domain);
-- 覆盖索引：时间窗口内按设备聚合（Top 设备 / 异常画像），带 blocked 以便索引内直接求和
CREATE INDEX IF NOT EXISTS idx_ql_ts_device ON query_log(ts, device_id, blocked);
-- 下面两个索引已被上面的组合索引完全覆盖（ts 是它们的前缀），删掉省空间与写入开销
DROP INDEX IF EXISTS idx_ql_ts;
DROP INDEX IF EXISTS idx_ql_blocked;

CREATE TABLE IF NOT EXISTS job_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  status TEXT,
  message TEXT,
  details TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_runs ON job_runs(job, id);

CREATE TABLE IF NOT EXISTS oui (
  prefix TEXT PRIMARY KEY,            -- 前3字节，如 BC2411
  vendor TEXT
);

-- 拦截流量分析：AdGuard 拦截后客户端连到本机，连接在此留痕；与 query_log 平行，按 device_id 归并，可与之 join
CREATE TABLE IF NOT EXISTS sink_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,               -- 首次出现时间 epoch ms
  last_ts INTEGER NOT NULL,          -- 最后一次出现（去重窗口内更新）
  hits INTEGER NOT NULL DEFAULT 1,   -- 去重窗口内合并的次数
  client_ip TEXT,
  client_port INTEGER,
  device_id INTEGER,
  device_name TEXT,
  proto TEXT,                        -- http | tls | tcp
  lport INTEGER,                     -- 本机监听端口
  host TEXT,                         -- Host 头（明文）或 SNI
  method TEXT,
  path TEXT,
  query TEXT,
  http_ver TEXT,                     -- HTTP/1.1 | HTTP/2
  ua TEXT,
  referer TEXT,
  headers_json TEXT,                 -- 仅在开启「采集完整头部」时写入
  body_bytes INTEGER,
  body_preview TEXT,                 -- 仅在开启「采集正文预览」时写入
  content_type TEXT,                 -- 请求的 Content-Type（只留 MIME，不含 charset）
  content_encoding TEXT,             -- 实际解开的压缩编码（gzip/deflate/br），未压缩为空
  charset TEXT,                      -- 实际用于解码的字符集（含嗅探结果）
  body_kind TEXT,                    -- json | form | multipart | xml | text | binary
  body_fields TEXT,                  -- 从正文抽出的键值对（JSON 字符串，有上限）
  tls_version TEXT,
  tls_cipher TEXT,                   -- 握手协商出的套件（仅 SNI 的行没有协商，为空）
  tls_client_ciphers INTEGER,        -- ClientHello 里客户端提供的套件数量（弱指纹，仅 SNI 的行也有）
  ja3 TEXT,                          -- TLS 客户端指纹（JA3，md5；TLS 1.3 客户端不稳定，仅供参考）
  ja4 TEXT,                          -- TLS 客户端指纹（JA4，推荐用这个判断"是不是同一个 App"）
  alpn TEXT,
  tls_note TEXT,                     -- 未解密的原因（如证书签发受限 / 客户端拒绝）
  decrypted INTEGER NOT NULL DEFAULT 0,  -- 是否成功解出明文
  outcome TEXT,                      -- empty | closed | page | reset | error
  duration_ms INTEGER,
  created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_se_ts ON sink_events(ts, host);
CREATE INDEX IF NOT EXISTS idx_se_dev ON sink_events(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_se_last ON sink_events(last_ts);
-- 唯一索引只是兜底：真正的去重由内存窗口完成（窗口内 UPDATE 累加 hits）
CREATE UNIQUE INDEX IF NOT EXISTS idx_se_uniq ON sink_events(ts, client_ip, lport, host, method, path);
`);

/** 轻量迁移：CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，故单独判断；必须在建表之后执行，只加不删、幂等 */
function addColumnIfMissing(table, column, decl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }
}
addColumnIfMissing('sink_events', 'tls_client_ciphers', 'INTEGER');
addColumnIfMissing('sink_events', 'ja3', 'TEXT');
addColumnIfMissing('sink_events', 'ja4', 'TEXT');
addColumnIfMissing('sink_events', 'content_type', 'TEXT');
addColumnIfMissing('sink_events', 'content_encoding', 'TEXT');
addColumnIfMissing('sink_events', 'charset', 'TEXT');
addColumnIfMissing('sink_events', 'body_kind', 'TEXT');
addColumnIfMissing('sink_events', 'body_fields', 'TEXT');

function settingGet(key, fallback) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (!row) {
    if (fallback !== undefined) return fallback;
    return Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key) ? DEFAULT_SETTINGS[key] : null;
  }
  try { return JSON.parse(row.value); } catch (e) { return row.value; }
}

function settingSet(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, JSON.stringify(value));
}

function allSettings() {
  const out = { ...DEFAULT_SETTINGS };
  for (const row of db.prepare('SELECT key, value FROM settings').all()) {
    try { out[row.key] = JSON.parse(row.value); } catch (e) { out[row.key] = row.value; }
  }
  return out;
}

function seedSettings() {
  const exists = db.prepare('SELECT 1 FROM settings WHERE key = ?');
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (!exists.get(k)) settingSet(k, v);
  }
}

function recordJob(job, status, message, details, startedAt) {
  const now = new Date().toISOString();
  if (startedAt) {
    db.prepare('INSERT INTO job_runs (job, started_at, finished_at, status, message, details) VALUES (?,?,?,?,?,?)')
      .run(job, startedAt, now, status, message || '', details ? JSON.stringify(details) : null);
  } else {
    db.prepare('INSERT INTO job_runs (job, started_at, finished_at, status, message, details) VALUES (?,?,?,?,?,?)')
      .run(job, now, now, status, message || '', details ? JSON.stringify(details) : null);
  }
  // 只保留最近 200 条任务记录
  db.prepare('DELETE FROM job_runs WHERE id NOT IN (SELECT id FROM job_runs ORDER BY id DESC LIMIT 200)').run();
}

module.exports = { db, settingGet, settingSet, allSettings, seedSettings, recordJob };
