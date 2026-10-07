'use strict';

/**
 * 重置 / 创建管理员密码（忘记密码时的恢复入口）。
 *
 * 用法：
 *   node src/reset-password.js <新密码> [用户名]
 *   npm run reset-password -- <新密码> [用户名]
 *
 * 说明：设置成功后会让所有已登录会话失效（需要重新登录）。
 */

const { db, seedSettings } = require('./db');
const { hashPassword } = require('./crypto');

seedSettings();

const password = process.argv[2];
const username = String(process.argv[3] || 'admin').trim();

if (!password || String(password).length < 6) {
  console.error('用法: node src/reset-password.js <新密码（至少 6 位）> [用户名，默认 admin]');
  process.exit(1);
}

const users = db.prepare('SELECT id, username FROM users ORDER BY id').all();

if (users.length && !users.some((u) => u.username === username)) {
  console.error(`未找到用户「${username}」。现有用户：${users.map((u) => u.username).join('、')}`);
  console.error(`若想重置已有账号，请把用户名作为第三个参数，例如：`);
  console.error(`  node src/reset-password.js 新密码 ${users[0].username}`);
  process.exit(1);
}

const hash = hashPassword(password);
const target = users.find((u) => u.username === username);
if (target) {
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, target.id);
  console.log(`已重置用户「${username}」的密码。`);
} else {
  db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)')
    .run(username, hash, new Date().toISOString());
  console.log(`已创建用户「${username}」。`);
}

const cleared = db.prepare('DELETE FROM sessions').run().changes;
console.log(`已使 ${cleared} 个已登录会话失效，请用新密码重新登录。`);
