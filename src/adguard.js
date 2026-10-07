'use strict';

const http = require('http');
const https = require('https');

/** AdGuard Home HTTP API 客户端（Basic 认证） */
class AdGuard {
  constructor({ baseUrl, username, password, verifyTls = true, timeoutMs = 20000 }) {
    this.baseUrl = String(baseUrl || '').replace(/\/+$/, '');
    this.username = username || '';
    this.password = password || '';
    this.verifyTls = verifyTls !== false;
    this.timeoutMs = timeoutMs;
  }

  authHeader() {
    const raw = `${this.username}:${this.password}`;
    return 'Basic ' + Buffer.from(raw, 'utf8').toString('base64');
  }

  async request(path, { method = 'GET', body, query } = {}) {
    let url = this.baseUrl + path;
    if (query && Object.keys(query).length) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
      }
      const s = qs.toString();
      if (s) url += (url.includes('?') ? '&' : '?') + s;
    }
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      throw new Error(`AdGuard 连接地址无效：${this.baseUrl}（需要带上 http:// 或 https://）`);
    }

    const isHttps = target.protocol === 'https:';
    const transport = isHttps ? https : http;
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8');
    const headers = {
      Authorization: this.authHeader(),
      'Content-Type': 'application/json'
    };
    if (payload) headers['Content-Length'] = payload.length;

    // 关闭证书校验只对本请求生效，不用 NODE_TLS_REJECT_UNAUTHORIZED（会连带影响其它出站 HTTPS 请求）
    const options = {
      method,
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      headers,
      timeout: this.timeoutMs
    };
    if (isHttps && !this.verifyTls) options.rejectUnauthorized = false;

    const { status, text } = await new Promise((resolve, reject) => {
      const req = transport.request(options, (resp) => {
        const chunks = [];
        resp.on('data', (c) => chunks.push(c));
        resp.on('error', reject);
        resp.on('end', () => resolve({ status: resp.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('timeout', () => req.destroy(new Error(`AdGuard API 请求超时(${this.timeoutMs}ms)`)));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
    if (status < 200 || status >= 300) {
      const err = new Error(`AdGuard API ${method} ${path} -> HTTP ${status}: ${text.slice(0, 300)}`);
      err.status = status;
      throw err;
    }
    if (!text) return null;
    try { return JSON.parse(text); } catch (e) { return text; }
  }

  status() { return this.request('/control/status'); }
  stats() { return this.request('/control/stats'); }
  clients() { return this.request('/control/clients'); }
  querylog(params) { return this.request('/control/querylog', { query: params }); }
  /** 统计的保留设置（{interval: 毫秒}），本系统用它作为"多久没出现算过期"的窗口 */
  statsConfig() { return this.request('/control/stats/config'); }

  /* ---- 写接口：仅在设置里打开“允许写回 AdGuard”后才会被调用 ---- */
  addClient(client) {
    return this.request('/control/clients/add', {
      method: 'POST',
      body: {
        name: client.name,
        ids: client.ids || [],
        use_global_settings: client.use_global_settings !== false,
        filtering_enabled: !!client.filtering_enabled,
        parental_enabled: !!client.parental_enabled,
        safebrowsing_enabled: !!client.safebrowsing_enabled,
        use_global_blocked_services: client.use_global_blocked_services !== false,
        ignore_querylog: !!client.ignore_querylog,
        ignore_statistics: !!client.ignore_statistics,
        tags: client.tags || []
      }
    });
  }

  /** data 必须是完整的客户端对象：AdGuard 的 update 是用它整体替换的 */
  updateClient(name, data) {
    return this.request('/control/clients/update', { method: 'POST', body: { name, data } });
  }

  deleteClient(name) {
    return this.request('/control/clients/delete', { method: 'POST', body: { name } });
  }

  async test() {
    const st = await this.status();
    return {
      version: st && st.version,
      protection_enabled: st && st.protection_enabled,
      dns_addresses: (st && st.dns_addresses) || [],
      running: st && st.running
    };
  }
}

module.exports = { AdGuard };
