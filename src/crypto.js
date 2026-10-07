'use strict';

const crypto = require('crypto');
const fs = require('fs');
const { KEY_FILE } = require('./config');

let cachedKey = null;
let lastDecryptWarnAt = 0;      // 解密失败告警的节流时间戳

/** 主密钥：首次启动生成并落盘（600 权限），用于加密数据库中的 SSH/AGH 凭据 */
function masterKey() {
  if (cachedKey) return cachedKey;
  if (fs.existsSync(KEY_FILE)) {
    cachedKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
    if (cachedKey.length !== 32) throw new Error('secret.key 长度非法，应为 32 字节');
  } else {
    cachedKey = crypto.randomBytes(32);
    fs.writeFileSync(KEY_FILE, cachedKey.toString('hex'), { mode: 0o600 });
  }
  return cachedKey;
}

/** AES-256-GCM 加密，输出 base64(iv | tag | ciphertext) */
function encrypt(plain) {
  if (plain === null || plain === undefined || plain === '') return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

function decrypt(payload) {
  if (!payload) return '';
  try {
    const buf = Buffer.from(payload, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch (e) {
    // 解不开基本只有一个原因：密文不是当前主密钥加的——最常见是恢复 data/ 备份时漏了 secret.key，
    // 于是 masterKey() 另生成了一把，库里的旧凭据就全部解不开。返回空串会让下游表现为"密码填错了"，
    // 用户会一直重填密码也修不好，所以必须留痕。连接每次取用都会解密，故按 60 秒节流。
    if (Date.now() - lastDecryptWarnAt > 60000) {
      lastDecryptWarnAt = Date.now();
      console.warn(`[crypto] 凭据解密失败（主密钥不匹配？）：${e.message}；`
        + `若刚从备份恢复，请确认 data/secret.key 与 device-hub.db 是同一份`);
    }
    return '';
  }
}

/** 口令哈希：scrypt$N$r$p$salt$hash */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(String(password), salt, 64, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const [, N, r, p, saltHex, hashHex] = parts;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(String(password), salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch (e) {
    return false;
  }
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { masterKey, encrypt, decrypt, hashPassword, verifyPassword, randomToken };
