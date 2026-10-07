'use strict';

const { db } = require('./db');
const { decrypt } = require('./crypto');
const { AdGuard } = require('./adguard');
const { httpError } = require('./httperr');

/** 连接配置：数据库存密文，运行时解密后使用 */
function listConnections(kind) {
  const rows = kind
    ? db.prepare('SELECT * FROM connections WHERE kind = ? ORDER BY id').all(kind)
    : db.prepare('SELECT * FROM connections ORDER BY kind, id').all();
  return rows.map(publicConn);
}

function publicConn(row) {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    enabled: !!row.enabled,
    host: row.host,
    port: row.port,
    username: row.username,
    auth_type: row.auth_type,
    has_secret: !!row.secret_enc,
    base_url: row.base_url,
    verify_tls: !!row.verify_tls,
    remark: row.remark,
    updated_at: row.updated_at
  };
}

function getConnection(id) {
  return db.prepare('SELECT * FROM connections WHERE id = ?').get(id) || null;
}

function firstEnabled(kind) {
  return db.prepare('SELECT * FROM connections WHERE kind = ? AND enabled = 1 ORDER BY id LIMIT 1').get(kind) || null;
}

/** 解密出可直接用于 SSH 的配置 */
function sshOptions(row) {
  if (!row) throw httpError(400, '未配置可用的 SSH 连接');
  return {
    host: row.host,
    port: row.port || 22,
    username: row.username,
    auth_type: row.auth_type || 'password',
    secret: decrypt(row.secret_enc),
    passphrase: decrypt(row.passphrase_enc)
  };
}

function adguardClient(row) {
  if (!row) throw httpError(400, '未配置可用的 AdGuard 连接');
  return new AdGuard({
    baseUrl: row.base_url,
    username: row.username,
    password: decrypt(row.secret_enc),
    verifyTls: !!row.verify_tls
  });
}

module.exports = { listConnections, publicConn, getConnection, firstEnabled, sshOptions, adguardClient };
