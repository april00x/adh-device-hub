'use strict';

/**
 * 运行环境信息：运行本系统的这台机器自身的系统 / 硬件 / 温度（只读）。
 *
 * 数据来源：Node 的 os 模块 + Linux 的 /proc、/sys。
 * 非 Linux 平台能读到多少算多少，读不到的项返回 null，前端显示为不可用。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { DATA_DIR, ROOT } = require('./config');
const pkg = require('../package.json');

function readText(p) {
  try {
    // 设备树的 model 等文件末尾带 \0，去掉
    return fs.readFileSync(p, 'utf8').replace(/\0+$/, '').trim();
  } catch (e) { return null; }
}

function readNum(p) {
  const t = readText(p);
  if (t === null) return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

/** /proc/cpuinfo 里的型号（ARM 上 os.cpus()[0].model 往往只给 "ARMv7 Processor rev 5"） */
function cpuModel() {
  const txt = readText('/proc/cpuinfo');
  if (txt) {
    for (const key of ['model name', 'Model', 'cpu model']) {
      const m = txt.match(new RegExp(`^${key}\\s*:\\s*(.+)$`, 'mi'));
      if (m) return m[1].trim();
    }
  }
  const cpus = os.cpus();
  return cpus.length ? String(cpus[0].model).trim() : null;
}

/** ARM 板子这类平台 /proc/cpuinfo 里只有泛泛的 "ARMv7 Processor rev 5"，SoC 名称在 Hardware 行 */
function cpuSoc() {
  const m = (readText('/proc/cpuinfo') || '').match(/^Hardware\s*:\s*(.+)$/mi);
  return m ? m[1].trim() : null;
}

/** 整机型号（单板机靠设备树给出，如 "某款单板机"；x86 服务器没有） */
function boardModel() {
  return readText('/sys/firmware/devicetree/base/model');
}

/** 发行版名称（/etc/os-release 的 PRETTY_NAME） */
function distroName() {
  const txt = readText('/etc/os-release');
  if (!txt) return null;
  const m = txt.match(/^PRETTY_NAME\s*=\s*"?([^"\n]+)"?/m);
  return m ? m[1].trim() : null;
}

/** 内存：优先用 /proc/meminfo 的 MemAvailable（比 os.freemem 更贴近"可用"的真实含义） */
function memoryInfo() {
  const out = {
    total: os.totalmem(),
    free: os.freemem(),
    available: os.freemem(),
    swap_total: null,
    swap_free: null
  };
  const txt = readText('/proc/meminfo');
  if (txt) {
    // MemTotal、MemFree 等都是 kB
    const kb = (key) => {
      const m = txt.match(new RegExp(`^${key}:\\s+(\\d+)\\s*kB`, 'm'));
      return m ? Number(m[1]) * 1024 : null;
    };
    const total = kb('MemTotal');
    const free = kb('MemFree');
    const avail = kb('MemAvailable');
    if (total) out.total = total;
    if (free !== null) out.free = free;
    if (avail !== null) out.available = avail;
    out.swap_total = kb('SwapTotal');
    out.swap_free = kb('SwapFree');
  }
  out.used = Math.max(0, out.total - out.available);
  out.used_pct = out.total ? +(out.used / out.total * 100).toFixed(1) : 0;
  return out;
}

/** 温度：先看 /sys/class/thermal，桌面 x86 常只有 /sys/class/hwmon，作为兜底 */
function thermalZones() {
  const out = [];
  let zones = [];
  try { zones = fs.readdirSync('/sys/class/thermal').filter((d) => /^thermal_zone\d+$/.test(d)); } catch (e) { /* 无 */ }
  for (const z of zones) {
    const raw = readNum(`/sys/class/thermal/${z}/temp`);
    if (raw === null) continue;
    const c = raw > 1000 ? raw / 1000 : raw;          // 多数平台是毫摄氏度
    if (c < -50 || c > 200) continue;                 // 明显不是有效温度，丢掉
    out.push({ zone: z, type: readText(`/sys/class/thermal/${z}/type`) || z, temp: +c.toFixed(1) });
  }
  if (!out.length) {
    let chips = [];
    try { chips = fs.readdirSync('/sys/class/hwmon'); } catch (e) { return out; }
    for (const chip of chips) {
      const name = readText(`/sys/class/hwmon/${chip}/name`) || chip;
      let files = [];
      try { files = fs.readdirSync(`/sys/class/hwmon/${chip}`).filter((f) => /^temp\d+_input$/.test(f)); } catch (e) { continue; }
      for (const f of files) {
        const raw = readNum(`/sys/class/hwmon/${chip}/${f}`);
        if (raw === null) continue;
        const c = raw > 1000 ? raw / 1000 : raw;
        if (c < -50 || c > 200) continue;
        out.push({ zone: `${chip}/${f.replace('_input', '')}`, type: name, temp: +c.toFixed(1) });
      }
    }
  }
  return out.sort((a, b) => b.temp - a.temp);
}

/** CPU 当前/最高频率（sysfs 里是 kHz） */
function cpuFreq() {
  const mhz = (v) => (v === null ? null : Math.round(v / 1000));
  const cur = readNum('/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq')
    ?? readNum('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq');
  return {
    cur_mhz: mhz(cur),
    min_mhz: mhz(readNum('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq')),
    max_mhz: mhz(readNum('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq')),
    governor: readText('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
  };
}

/** 数据目录所在分区的容量 */
function diskInfo(dir) {
  try {
    const s = fs.statfsSync(dir);
    const total = s.blocks * s.bsize;
    const free = s.bavail * s.bsize;
    const used = Math.max(0, total - free);
    return { path: dir, total, free, used, used_pct: total ? +(used / total * 100).toFixed(1) : 0 };
  } catch (e) {
    return null;
  }
}

/** 有地址的网卡（内网 IPv6 临时地址会很多，每张网卡最多留 2 个） */
function networkInfo() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    const ip4 = [];
    const ip6 = [];
    let mac = null;
    for (const a of addrs || []) {
      if (a.internal) continue;
      if (a.family === 'IPv4') {
        ip4.push(a.address);
        if (!mac && a.mac && a.mac !== '00:00:00:00:00:00') mac = a.mac;
      } else if (a.family === 'IPv6') {
        ip6.push(String(a.address).split('%')[0]);
      }
    }
    if (ip4.length || ip6.length) out.push({ name, ip4, ip6: ip6.slice(0, 2), mac });
  }
  return out;
}

function snapshot() {
  const mem = process.memoryUsage();
  const upSec = process.uptime();
  const temps = thermalZones();
  const freq = cpuFreq();
  const cpus = os.cpus();
  return {
    generated_at: new Date().toISOString(),
    host: {
      hostname: os.hostname(),
      board: boardModel(),
      platform: os.platform(),
      distro: distroName(),
      kernel: os.release(),
      arch: os.arch(),
      uptime_sec: Math.round(os.uptime()),
      is_docker: fs.existsSync('/.dockerenv'),
      now: Date.now()
    },
    cpu: {
      model: cpuModel(),
      soc: cpuSoc(),
      cores: cpus.length,
      load: os.loadavg().map((n) => +n.toFixed(2)),
      cur_mhz: freq.cur_mhz,
      min_mhz: freq.min_mhz,
      max_mhz: freq.max_mhz,
      governor: freq.governor,
      // 取最热的那个传感器作为"CPU 温度"，其余在 temps 里列全
      temp: temps.length ? temps[0].temp : null,
      temp_type: temps.length ? temps[0].type : null,
      temps
    },
    memory: memoryInfo(),
    disk: diskInfo(DATA_DIR),
    net: networkInfo(),
    runtime: {
      app_version: pkg.version,
      node: process.version,
      pid: process.pid,
      rss: mem.rss,
      heap_used: mem.heapUsed,
      app_uptime_sec: Math.round(upSec),
      started_at: new Date(Date.now() - upSec * 1000).toISOString(),
      data_dir: DATA_DIR,
      root: ROOT,
      cwd: process.cwd()
    }
  };
}

module.exports = { snapshot };
