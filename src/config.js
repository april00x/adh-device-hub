'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

module.exports = {
  ROOT,
  DATA_DIR,
  DB_FILE: path.join(DATA_DIR, 'device-hub.db'),
  KEY_FILE: path.join(DATA_DIR, 'secret.key'),
  OUI_FILE: path.join(DATA_DIR, 'oui.csv'),
  // 拦截流量分析自签根 CA 的存放目录（key 与证书都在这里，备份时一并带上）
  SINK_CA_DIR: path.join(DATA_DIR, 'sink-ca'),
  PUBLIC_DIR: path.join(ROOT, 'public'),
  PORT: Number(process.env.PORT || 7788),
  HOST: process.env.HOST || '0.0.0.0',
  SESSION_TTL_MS: 7 * 24 * 3600 * 1000,
  // 默认设置项（首次启动写入 settings 表，之后以数据库为准）
  DEFAULT_SETTINGS: {
    // 采集
    collect_interval_sec: 300,        // 定期采集（DHCP租约/邻居表）间隔
    ingest_interval_sec: 120,          // 定期摄取 AdGuard 查询日志间隔
    backfill_days: 7,                  // 从 AdGuard 抓取日志的范围（天）：首次摄取拉满，之后增量也不超出
    ingest_lookback_min: 30,           // 每次摄取从上次断点再往前多取的分钟数（防漏，重复会自动去重）
    log_retention_days: 30,            // 本地查询日志保留天数
    ip_history_retention_days: 90,     // IP 历史保留天数（0=永久）
    // 网关/本机地址（不计入设备，日志里标为"路由器本机"）；默认是常见家用网关，请按实际网络修改
    router_ips: '192.168.1.1,192.168.0.1,10.0.0.1,172.17.0.1,127.0.0.1,::1',
    // 是否允许写回 AdGuard。默认关闭；显式打开后界面才出现写入口
    allow_agh_write: '0',
    // 是否自动定时把 AdGuard 客户端 ids 同步为主 MAC + 当前 IPv4 + 仍在产生的 IPv6。默认关闭；
    // 仍需 allow_agh_write 才会真正写入，且只更新 ids，不新建/不删除客户端
    agh_auto_sync: '0',
    agh_sync_interval_sec: 600,       // 自动同步间隔（秒）
    // 由本系统定时从 /control/stats/config 读回后写入，仅用于展示与同步判断，不要手工改
    agh_stats_interval_ms: 24 * 3600 * 1000,

    // ---------- 拦截流量分析（sinkhole） ----------
    // 接收 AdGuard 拦截后指向本机的连接，只接受连接、抽取字段、返回固定应答；不写路由器/AGH 配置，默认关闭
    sink_enabled: '0',
    sink_bind_ip: '',                 // 绑定网卡；建议显式写本机 LAN IP，避免暴露到其它网段
    sink_http_port: 80,               // 明文 HTTP 端口
    sink_https_port: 443,             // TLS 端口
    sink_extra_ports: '',             // 额外监听端口（逗号分隔，如 8080,8443）；每个都做首包协议识别
    sink_tcp_preview_bytes: 64,       // 未知协议的首包预览长度（hex）
    // sni  = 只读取 SNI/ALPN，不解密（无需客户端配合）
    // mitm = 用自签 CA 动态签发证书解密明文（需客户端信任该 CA，证书固定的客户端会失败）
    sink_tls_mode: 'sni',
    // 三种应答只影响客户端怎么感知这次失败，不影响抓到的内容，也不能让被拦域名重新可用
    // close = 直接关闭连接 | empty = 204 空响应 | page = 返回提示页
    sink_response: 'close',
    sink_capture_headers: '0',        // 是否落完整 Header（可能含 Cookie/Token）
    sink_capture_body: '0',           // 是否落正文预览（可能含凭据与个人信息）
    sink_body_preview_bytes: 512,     // 正文预览截断长度（压缩正文按解压后的长度算）
    sink_body_wait_ms: 1000,          // 等正文读完的最长时间；到点先应答落库，正文标记为已截断
    sink_dedup_window_sec: 60,        // 同一（客户端,端口,主机,方法,路径）在此窗口内合并为一条并累加次数
    sink_max_rows_per_sec: 50,        // 每秒最多新增多少行明细（超出只计数），保护 SD 卡
    sink_retention_days: 14           // 连接记录保留天数（0=永久）
  }
};
