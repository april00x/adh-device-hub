'use strict';

const { Client } = require('ssh2');

/**
 * 一次性 SSH 执行器：连接、执行脚本、关闭。
 * 支持密码与私钥（可带 passphrase）两种认证。
 */
function sshExec(opts, command, { timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let stdout = '';
    let stderr = '';
    let finished = false;

    const cleanup = () => { try { conn.end(); } catch (e) { /* ignore */ } };
    const done = (err, result) => {
      if (finished) return;
      finished = true;
      cleanup();
      if (err) reject(err); else resolve(result);
    };

    const timer = setTimeout(() => done(new Error(`SSH 执行超时(${timeoutMs}ms)`)), timeoutMs + 5000);

    conn.on('ready', () => {
      conn.exec(command, { pty: false }, (err, stream) => {
        if (err) { clearTimeout(timer); return done(err); }
        stream.on('close', (code) => {
          clearTimeout(timer);
          done(null, { stdout, stderr, code });
        });
        stream.on('data', (d) => { stdout += d.toString('utf8'); });
        stream.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
      });
    });
    conn.on('error', (e) => { clearTimeout(timer); done(e); });
    conn.on('timeout', () => { clearTimeout(timer); done(new Error('SSH 连接超时')); });

    const config = {
      host: opts.host,
      port: opts.port || 22,
      username: opts.username,
      readyTimeout: timeoutMs,
      keepaliveInterval: 5000,
      algorithms: undefined
    };
    if (opts.auth_type === 'key') {
      config.privateKey = opts.secret;
      if (opts.passphrase) config.passphrase = opts.passphrase;
      // 私钥模式下也允许尝试口令（部分设备两者皆可）
      if (opts.password) config.password = opts.password;
    } else {
      config.password = opts.secret;
      config.tryKeyboard = true;
    }

    try {
      conn.connect(config);
    } catch (e) {
      clearTimeout(timer);
      done(e);
    }
  });
}

/** 采集脚本：一次性取回租约、IPv4/IPv6 邻居表、静态绑定、主机名映射 */
const COLLECT_SCRIPT = [
  'echo "###LEASES###"',
  'cat /tmp/dhcp.leases 2>/dev/null',
  'echo "###NEIGH4###"',
  'ip neigh show 2>/dev/null',
  'echo "###NEIGH6###"',
  'ip -6 neigh show 2>/dev/null',
  'echo "###STATIC###"',
  'uci show dhcp 2>/dev/null | grep -E "\\.(mac|ip|name|hostname)=" ',
  'echo "###ARP###"',
  'cat /proc/net/arp 2>/dev/null',
  'echo "###END###"'
].join('\n');

async function collectRaw(opts) {
  const res = await sshExec(opts, COLLECT_SCRIPT, { timeoutMs: 30000 });
  return parseSections(res.stdout);
}

function parseSections(text) {
  const sections = { LEASES: '', NEIGH4: '', NEIGH6: '', STATIC: '', ARP: '' };
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^###([A-Z0-9]+)###$/);
    if (m) { current = m[1]; if (!(current in sections)) sections[current] = ''; continue; }
    if (current) sections[current] += line + '\n';
  }
  return sections;
}

module.exports = { sshExec, collectRaw, COLLECT_SCRIPT, parseSections };
