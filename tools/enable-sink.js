/**
 * 用下面这套参数打开「拦截流量分析」，适合部署时一次性执行：跑完重启服务即生效。
 * 走项目自身的 settingSet 写入，避免手工拼 JSON 造成编码不一致。
 *
 * 用法：node tools/enable-sink.js
 * 这些设置项在界面上「设置 → 拦截流量分析」里同样可以改，改完以数据库为准。
 */
const { settingSet, allSettings, db } = require('../src/db');

const patch = {
  sink_enabled: '1',
  sink_bind_ip: '',            // 留空 = 双栈监听全部网卡（绑具体 IPv4 会丢掉 IPv6 流量）
  sink_http_port: 80,
  sink_https_port: 443,
  sink_extra_ports: '',
  sink_tls_mode: 'mitm',       // 动态签发证书解密
  sink_response: 'close',      // 直接关闭连接
  sink_capture_body: '1',      // 采集正文预览（前 512 字节）
  sink_capture_headers: '0',   // 完整头部仍不采集（可能含 Cookie/Token）
  sink_body_preview_bytes: 512,
  sink_dedup_window_sec: 60,
  sink_max_rows_per_sec: 50,
  sink_retention_days: 14
};

for (const [k, v] of Object.entries(patch)) settingSet(k, v);

const s = allSettings();
console.log('=== 写入后的 sink_* 设置 ===');
for (const k of Object.keys(patch).sort()) console.log('  ' + k.padEnd(26) + ' = ' + JSON.stringify(s[k]));
console.log();
console.log('=== 连接记录表当前行数 ===');
console.log('  ' + db.prepare('SELECT COUNT(*) AS c FROM sink_events').get().c);
