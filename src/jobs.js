'use strict';

const { allSettings, recordJob, db, settingGet } = require('./db');
const { firstEnabled, sshOptions, adguardClient } = require('./connections');
const { collectRaw } = require('./sshclient');
const { httpError } = require('./httperr');
const D = require('./devices');
const agh = require('./aghclients');
const { ingestQueryLog, pruneIpHistory, pruneQueryLog, pruneSinkEvents, reResolveUnmapped, vacuum } = require('./ingest');
const sinkhole = require('./sinkhole');

const running = new Map();
const timers = [];

async function guard(name, fn) {
  if (running.get(name)) return { skipped: true, reason: '上一次任务仍在执行' };
  running.set(name, true);
  try {
    return await fn();
  } catch (e) {
    // 手动触发（routes 直接调 runXxx）与定时触发共用这里，两条路径的失败都要留痕，
    // 否则「最近任务」里会出现"成功…下一次成功"的断档，排查时以为没点过。
    // 4xx 是调用方能自己纠正的前置校验（如未配置连接），记了只会刷屏，跳过。
    const code = Number(e && e.status);
    if (!(code >= 400 && code < 500)) {
      try { recordJob(name, 'failed', (e && e.message) || String(e)); } catch (_) { /* ignore */ }
    }
    throw e;
  } finally {
    running.delete(name);
  }
}

/** 采集：SSH 读取租约/邻居表，归并设备身份（只读，不修改路由器与 AdGuard 任何配置） */
function runCollect() {
  return guard('collect', async () => {
    const ssh = firstEnabled('ssh');
    if (!ssh) throw httpError(400, '未配置启用的 SSH 连接（请在「设置」中添加路由器 SSH）');
    const raw = await collectRaw(sshOptions(ssh));
    const stat = D.applyCollected(raw);
    // 邻居表更新后，回溯修正此前未能归属的日志（IPv6 临时地址尤其需要）
    const backfilled = reResolveUnmapped();
    const pruned = pruneIpHistory();
    const summary = `租约 ${stat.leases} / IPv4 邻居 ${stat.neigh4} / IPv6 邻居 ${stat.neigh6} / 静态绑定 ${stat.static} / 涉及设备 ${stat.deviceCount}`
      + ` / 回溯归属 ${backfilled.fixed} 条（未归属 ${backfilled.remaining} 条）`
      + (pruned ? ` / 清理IP历史 ${pruned}` : '');
    recordJob('collect', 'success', summary, { ...stat, prunedIpHistory: pruned, backfilled });
    return { ...stat, prunedIpHistory: pruned, backfilled };
  });
}

/** 摄取 AdGuard 查询日志到本地归档（只读拉取） */
function runIngest(opts = {}) {
  return guard('ingest', async () => {
    const adgRow = firstEnabled('adguard');
    if (!adgRow) throw httpError(400, '未配置启用的 AdGuard 连接（请在「设置」中添加）');
    return ingestQueryLog(adguardClient(adgRow), opts);
  });
}

/** 读取 AdGuard 持久客户端列表，用于继承已有名称（只读） */
function runImportClients() {
  return guard('import_clients', async () => {
    const adgRow = firstEnabled('adguard');
    if (!adgRow) throw httpError(400, '未配置启用的 AdGuard 连接');
    const payload = await adguardClient(adgRow).clients();
    const stat = D.importAdGuardClients(payload);
    recordJob('import_clients', 'success', `匹配 AdGuard 客户端 ${stat.imported}/${stat.total} 个`, stat);
    return stat;
  });
}

/** 自动同步 AdGuard 客户端 ids（可选，两个开关都打开才会真的写） */
function runAghAutoSync() {
  return guard('agh_auto_sync', async () => agh.runAutoSync());
}

function schedule(intervalSec, fn) {
  const ms = Math.max(15, Number(intervalSec) || 60) * 1000;
  const timer = setInterval(() => {
    // 失败由 guard() 写进任务记录，这里只吞掉 rejection，避免未处理的拒绝把进程带走
    fn().catch(() => {});
  }, ms);
  timer.unref?.();
  timers.push(timer);
}

function restart() {
  stop();
  const s = allSettings();
  // 未配置对应连接时静默跳过，避免定时任务反复写入"未配置"的失败记录
  schedule(s.collect_interval_sec, async () => {
    if (!firstEnabled('ssh')) return;
    await runCollect();
  });
  schedule(s.ingest_interval_sec, async () => {
    if (!firstEnabled('adguard')) return;
    await runIngest({});
  });
  // 自动同步 AdGuard 客户端 ids：默认关，且必须同时打开“允许写回 AdGuard”才会真的写
  schedule(s.agh_sync_interval_sec, async () => {
    if (!firstEnabled('adguard')) return;
    if (String(s.allow_agh_write || '0') !== '1' || String(s.agh_auto_sync || '0') !== '1') return;
    await runAghAutoSync();
  });
  schedule(3600, () => guard('maintenance', async () => {
    pruneQueryLog();
    pruneIpHistory();
    pruneSinkEvents();
    // 每小时也把流量缓冲刷一次：定时器是 5 秒一次，这里只是兜底
    sinkhole.flush();
    // VACUUM 会重写整库并短暂独占访问，SD 卡上既慢又伤卡，故最多每周一次
    const lastVacuum = Number(settingGet('vacuum.last_ts', 0)) || 0;
    if (Date.now() - lastVacuum > 7 * 24 * 3600 * 1000) vacuum();
  }));

  // 拦截流量分析：开关/端口/模式变了就按新配置重新监听
  sinkhole.restart();
}

function stop() {
  while (timers.length) clearInterval(timers.pop());
  sinkhole.stop();
}

function status() {
  const s = allSettings();
  return {
    running: [...running.keys()],
    collect_interval_sec: s.collect_interval_sec,
    ingest_interval_sec: s.ingest_interval_sec,
    ssh_configured: !!firstEnabled('ssh'),
    adguard_configured: !!firstEnabled('adguard'),
    last_runs: db.prepare('SELECT job, status, message, finished_at FROM job_runs ORDER BY id DESC LIMIT 12').all()
  };
}

module.exports = { runCollect, runIngest, runImportClients, runAghAutoSync, restart, stop, status };
