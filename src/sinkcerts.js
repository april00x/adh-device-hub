'use strict';

/**
 * 拦截流量分析的自签根 CA 与按 SNI 动态签发证书。
 *
 * 只在 sink_tls_mode = 'mitm' 时才会被调用；'sni' 模式不会走到这里（不生成证书与私钥）。
 *
 * node-forge 的 RSA 签名是纯 JS 同步运算，会阻塞事件循环，因此需要 LRU 缓存、共用叶证书私钥、
 * 按耗时动态限流；限流触发时放弃本次签发（只记 SNI，tls_note 标注原因），宁可不解密也不拖垮进程。
 */

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const forge = require('node-forge');
const { SINK_CA_DIR } = require('./config');

const CA_KEY_FILE = path.join(SINK_CA_DIR, 'ca.key.pem');
const CA_CRT_FILE = path.join(SINK_CA_DIR, 'ca.crt.pem');
const LEAF_KEY_FILE = path.join(SINK_CA_DIR, 'leaf.key.pem');

// 缓存上限：每项持有一个 SecureContext（含一张证书与私钥），上限需控制住内存占用
const CACHE_MAX = 256;
// 签发允许占用事件循环的比例上限；超过就放弃本次签发（只记 SNI）
const MAX_DUTY = 0.25;

const cache = new Map();        // servername -> { ctx, certPem }
const signLog = [];             // 最近 1 秒内的签发耗时样本
let avgSignMs = 10;             // 签发耗时的指数滑动平均，用于限流估算

let ca = null;                  // { keyPem, certPem, key, cert }
let leafKey = null;             // forge 私钥对象（所有叶证书共用，省去每次签发的密钥生成开销）
let leafKeyPem = '';

function log(...args) {
  console.log('[sinkhole/certs]', ...args);
}

function writeSecret(file, content, mode) {
  fs.writeFileSync(file, content, { mode });
  try { fs.chmodSync(file, mode); } catch (e) { /* Windows 上无效，忽略 */ }
}

/** 生成/加载根 CA；叶证书私钥也只生成一次并复用 */
function ensure() {
  if (ca) return ca;
  fs.mkdirSync(SINK_CA_DIR, { recursive: true });

  if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CRT_FILE)) {
    const keyPem = fs.readFileSync(CA_KEY_FILE, 'utf8');
    const certPem = fs.readFileSync(CA_CRT_FILE, 'utf8');
    ca = {
      keyPem, certPem,
      key: forge.pki.privateKeyFromPem(keyPem),
      cert: forge.pki.certificateFromPem(certPem)
    };
    log('已加载现有根 CA:', path.basename(CA_CRT_FILE));
  } else {
    log('首次运行，正在生成根 CA（RSA-2048）…');
    const keys = forge.pki.rsa.generateKeyPair(2048, 0x10001);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + forge.util.bytesToHex(forge.random.getBytesSync(8));
    cert.validity.notBefore = new Date(Date.now() - 86400000);
    cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400000);
    const attrs = [{ name: 'commonName', value: 'ADH Device Hub Sinkhole CA' },
                   { name: 'organizationName', value: 'ADH Device Hub (local sinkhole)' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
      { name: 'subjectKeyIdentifier' }
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    const certPem = forge.pki.certificateToPem(cert);
    writeSecret(CA_KEY_FILE, keyPem, 0o600);
    writeSecret(CA_CRT_FILE, certPem, 0o644);
    ca = { keyPem, certPem, key: keys.privateKey, cert };
    log('根 CA 已生成并写入', SINK_CA_DIR);
  }

  if (fs.existsSync(LEAF_KEY_FILE)) {
    leafKeyPem = fs.readFileSync(LEAF_KEY_FILE, 'utf8');
    leafKey = forge.pki.privateKeyFromPem(leafKeyPem);
  } else {
    // 叶私钥只生成一次以省掉每个新域名的密钥生成开销（本机自用可接受，外部不可信环境不要这么用）
    const kp = forge.pki.rsa.generateKeyPair(2048, 0x10001);
    leafKey = kp.privateKey;
    leafKeyPem = forge.pki.privateKeyToPem(kp.privateKey);
    writeSecret(LEAF_KEY_FILE, leafKeyPem, 0o600);
  }
  return ca;
}

/** 是否还允许做一次签发：把签发占用控制在事件循环的 MAX_DUTY 以内 */
function allowSign() {
  const now = Date.now();
  while (signLog.length && now - signLog[0].t > 1000) signLog.shift();
  const spent = signLog.reduce((a, x) => a + x.ms, 0);
  return spent < 1000 * MAX_DUTY;
}

function isIpLiteral(name) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(name) || name.includes(':');
}

/** 为某个 SNI 签发证书并返回 TLS 上下文；超预算或失败返回 null（该次握手不解密） */
function contextFor(servername) {
  const name = String(servername || '').trim().slice(0, 253);
  const hit = cache.get(name);
  if (hit) {
    // LRU：命中后移到队尾
    cache.delete(name);
    cache.set(name, hit);
    return hit.ctx;
  }
  if (!allowSign()) return null;

  const t0 = Date.now();
  try {
    ensure();
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.rsa.setPublicKey(leafKey.n, leafKey.e);
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date(Date.now() - 86400000);
    cert.validity.notAfter = new Date(Date.now() + 825 * 86400000);

    const cn = (name || 'sinkhole.local').slice(0, 64);
    cert.setSubject([{ name: 'commonName', value: cn }]);
    cert.setIssuer(ca.cert.subject.attributes);
    const altNames = isIpLiteral(name) ? [{ type: 7, ip: name }] : [{ type: 2, value: name }];
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames }
    ]);
    cert.sign(ca.key, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const ctx = tls.createSecureContext({ key: leafKeyPem, cert: certPem });

    if (cache.size >= CACHE_MAX) {
      // 淘汰最久未用的一项
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(name, { ctx, certPem });
    return ctx;
  } catch (e) {
    log('签发失败', name, e.message);
    return null;
  } finally {
    const ms = Date.now() - t0;
    signLog.push({ t: Date.now(), ms });
    avgSignMs = avgSignMs * 0.7 + ms * 0.3;
  }
}

/** 无 SNI 时的兜底证书：tls.createServer 必须有一份基础 key + cert，否则 Node 在握手前直接断开（这份 PEM 不是可选项） */
let fallbackPems = null;
function defaultPems(bindIp) {
  if (fallbackPems) return fallbackPems;
  const t0 = Date.now();
  try {
    ensure();
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.rsa.setPublicKey(leafKey.n, leafKey.e);
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date(Date.now() - 86400000);
    cert.validity.notAfter = new Date(Date.now() + 825 * 86400000);
    cert.setSubject([{ name: 'commonName', value: 'sinkhole.local' }]);
    cert.setIssuer(ca.cert.subject.attributes);
    const altNames = [{ type: 2, value: 'sinkhole.local' }];
    if (bindIp && isIpLiteral(bindIp)) altNames.push({ type: 7, ip: bindIp });
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames }
    ]);
    cert.sign(ca.key, forge.md.sha256.create());
    fallbackPems = { key: leafKeyPem, cert: forge.pki.certificateToPem(cert) };
  } catch (e) {
    log('兜底证书生成失败', e.message);
    fallbackPems = null;
  } finally {
    signLog.push({ t: Date.now(), ms: Date.now() - t0 });
  }
  return fallbackPems;
}

/** 供「设置」页下载安装的根证书 */
function caCertPem() {
  ensure();
  return ca.certPem;
}

/** 根证书信息（指纹等），用于页面上核对装的是不是同一张 */
function caInfo() {
  let created = null;
  try { created = fs.statSync(CA_CRT_FILE).mtime.toISOString(); } catch (e) { /* ignore */ }
  ensure();
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(ca.cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const fp = md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();
  return {
    dir: SINK_CA_DIR,
    created_at: created,
    subject: 'ADH Device Hub Sinkhole CA',
    fingerprint_sha256: fp,
    leaf_key_shared: true,
    cache_size: cache.size,
    cache_max: CACHE_MAX,
    avg_sign_ms: Math.round(avgSignMs * 10) / 10,
    signs_last_sec: signLog.filter((x) => Date.now() - x.t <= 1000).length
  };
}

/** 设置变更/停用时清空缓存，避免旧证书与新开关状态不一致 */
function reset() {
  cache.clear();
  fallbackPems = null;
}

module.exports = { contextFor, defaultPems, caCertPem, caInfo, reset, ensure };
