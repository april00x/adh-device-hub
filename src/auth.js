'use strict';

const { db, settingSet, settingGet } = require('./db');
const { hashPassword, verifyPassword, randomToken } = require('./crypto');
const { SESSION_TTL_MS } = require('./config');
const { httpError } = require('./httperr');

const COOKIE = 'adhsid';
const MAX_ATTEMPTS = 8;              // 登录：同一 IP 在窗口内允许的失败次数
const MAX_SETUP_ATTEMPTS = 5;        // 初始化：同一 IP 在窗口内允许的尝试次数
const WINDOW_MS = 10 * 60 * 1000;
// 失败次数按来源 IP 记录，最多保留 MAX_TRACKED 条：先清已过窗口的，再淘汰未触顶的，
// 最后按插入顺序淘汰最旧的，既保证内存有上限，又尽量保住"已被限流"的状态
const MAX_TRACKED = 20000;

function createLimiter(maxAttempts, windowMs) {
  const map = new Map();

  function prune(now) {
    if (map.size < MAX_TRACKED) return;
    for (const [ip, rec] of map) {
      if (now - rec.first > windowMs) map.delete(ip);
    }
    if (map.size >= MAX_TRACKED) {
      for (const [ip, rec] of map) {
        if (map.size < MAX_TRACKED) break;
        if (rec.count < maxAttempts) map.delete(ip);
      }
    }
    while (map.size >= MAX_TRACKED) {
      const oldest = map.keys().next();
      if (oldest.done) break;
      map.delete(oldest.value);
    }
  }

  return {
    limited(ip) {
      const rec = map.get(ip);
      if (!rec) return false;
      if (Date.now() - rec.first > windowMs) { map.delete(ip); return false; }
      return rec.count >= maxAttempts;
    },
    note(ip) {
      const now = Date.now();
      const rec = map.get(ip);
      if (!rec || now - rec.first > windowMs) {
        prune(now);
        map.set(ip, { first: now, count: 1 });
      } else {
        rec.count++;
      }
    },
    clear(ip) { map.delete(ip); }
  };
}

const loginLimiter = createLimiter(MAX_ATTEMPTS, WINDOW_MS);
const setupLimiter = createLimiter(MAX_SETUP_ATTEMPTS, WINDOW_MS);

function hasAdmin() {
  return db.prepare('SELECT COUNT(*) AS c FROM users').get().c > 0;
}

function createAdmin(username, password) {
  if (!username || !password || String(password).length < 6) throw httpError(400, '用户名不能为空，密码至少 6 位');
  db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)')
    .run(String(username).trim(), hashPassword(password), new Date().toISOString());
  settingSet('setup_done', true);
}

function changePassword(userId, oldPassword, newPassword, keepToken) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) throw httpError(400, '用户不存在');
  // 这几项都用 400 而不是 401：前端把 401 当作"会话已过期"处理，会顶掉这里的具体原因
  if (!verifyPassword(oldPassword, user.password_hash)) throw httpError(400, '原密码不正确');
  if (!newPassword || String(newPassword).length < 6) throw httpError(400, '新密码至少 6 位');
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), userId);
  // 改密后让其它的登录态失效（保留当前这次会话，避免自己也被踢掉）
  if (keepToken) db.prepare('DELETE FROM sessions WHERE user_id = ? AND token <> ?').run(userId, keepToken);
  else db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

function login(username, password, ip, ua) {
  if (loginLimiter.limited(ip)) {
    console.warn(`[auth] 来源 ${ip} 的登录尝试过于频繁，已拒绝（${new Date().toISOString()}）`);
    throw httpError(429, '尝试次数过多，请 10 分钟后再试');
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || '').trim());
  if (!user || !verifyPassword(password, user.password_hash)) {
    loginLimiter.note(ip);
    // 失败尝试要留痕：/api/login 在局域网可达，而限流状态只在内存里，进程重启即丢。
    // 不回显提交的用户名，避免用户把口令误填进用户名框时被明文写进日志。
    console.warn(`[auth] 登录失败（${user ? '口令错误' : '用户不存在'}）来自 ${ip}（${new Date().toISOString()}）`);
    throw httpError(401, '用户名或密码错误');
  }
  loginLimiter.clear(ip);
  const token = randomToken(32);
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at, ip, ua) VALUES (?,?,?,?,?,?)')
    .run(token, user.id, new Date(now).toISOString(), now + SESSION_TTL_MS, ip, String(ua || '').slice(0, 200));
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  return { token, user: { id: user.id, username: user.username } };
}

function logout(token) {
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function userFromToken(token) {
  if (!token) return null;
  const row = db.prepare(`SELECT s.*, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) { db.prepare('DELETE FROM sessions WHERE token = ?').run(token); return null; }
  return { id: row.user_id, username: row.username, token, expires_at: row.expires_at };
}

/** 鉴权中间件：未登录返回 401（前端跳登录页）；有效期过半时自动续期，避免长期使用被强制登出 */
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE];
  const user = userFromToken(token);
  if (!user) return res.status(401).json({ error: '未登录或会话已过期', need_login: true });
  if (user.expires_at - Date.now() < SESSION_TTL_MS / 2) {
    db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(Date.now() + SESSION_TTL_MS, token);
    setCookie(res, token, req.secure);
  }
  req.user = user;
  next();
}

function setCookie(res, token, secure) {
  const parts = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

/** 初始化尝试次数：初始化完成前 /api/setup 无需登录，用它限制同一来源反复调用 */
function setupRateLimited(ip) { return setupLimiter.limited(ip); }
function noteSetupAttempt(ip) { setupLimiter.note(ip); }

function clearCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

module.exports = {
  COOKIE, hasAdmin, createAdmin, changePassword, login, logout,
  setupRateLimited, noteSetupAttempt,
  userFromToken, requireAuth, setCookie, clearCookie
};
