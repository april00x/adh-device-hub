'use strict';

const fs = require('fs');
const { OUI_FILE } = require('./config');
const { db } = require('./db');
const { httpError } = require('./httperr');

/** 厂商(OUI)查询：用 data/oui.csv（IEEE 格式）或在线 Wireshark manuf，不内置猜测数据；未命中返回 null */
let memMap = new Map();
let loaded = false;

function normalizePrefix(mac) {
  const hex = String(mac || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  return hex.length >= 6 ? hex.slice(0, 6) : null;
}

function parseIeeeCsv(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    // Registry,Assignment,Organization Name,Organization Address
    const m = line.match(/^[^,]*,"?([0-9A-Fa-f]{6})"?,"?([^",]*)"?/);
    if (m) out.push([m[1].toUpperCase(), m[2].trim()]);
  }
  return out;
}

function parseManuf(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const parts = line.split('\t');
    if (parts.length < 2) continue;
    const hex = parts[0].replace(/[^0-9a-fA-F]/g, '').toUpperCase();
    if (hex.length >= 6) out.push([hex.slice(0, 6), parts[1].trim()]);
  }
  return out;
}

function load() {
  if (loaded) return;
  loaded = true;
  memMap = new Map();
  // 1) 数据库缓存
  for (const row of db.prepare('SELECT prefix, vendor FROM oui').all()) memMap.set(row.prefix, row.vendor);
  if (memMap.size > 0) return;
  // 2) 本地文件
  try {
    if (fs.existsSync(OUI_FILE)) {
      const text = fs.readFileSync(OUI_FILE, 'utf8');
      const pairs = text.includes('\t') ? parseManuf(text) : parseIeeeCsv(text);
      savePairs(pairs);
    }
  } catch (e) { /* 忽略，退化为未知厂商 */ }
}

function savePairs(pairs) {
  const insert = db.prepare('INSERT INTO oui (prefix, vendor) VALUES (?, ?) ON CONFLICT(prefix) DO UPDATE SET vendor = excluded.vendor');
  const tx = db.transaction((rows) => { for (const [p, v] of rows) if (p && v) insert.run(p, v); });
  tx(pairs);
  for (const [p, v] of pairs) memMap.set(p, v);
}

function lookup(mac) {
  load();
  const prefix = normalizePrefix(mac);
  if (!prefix) return null;
  return memMap.get(prefix) || null;
}

/** 在线更新 OUI 库（优先 IEEE 官方 CSV，失败则用 Wireshark 官方发布的 manuf） */
async function updateOnline() {
  // IEEE 服务器有时很慢，故每个源单独限时、超时换下一个；Wireshark manuf 通常更快，作为备选
  const sources = [
    { url: 'https://standards-oui.ieee.org/oui/oui.csv', name: 'IEEE oui.csv', type: 'ieee', timeoutMs: 45000 },
    { url: 'https://www.wireshark.org/download/automated/data/manuf', name: 'Wireshark manuf', type: 'manuf', timeoutMs: 45000 }
  ];
  const errors = [];
  for (const s of sources) {
    try {
      const resp = await fetch(s.url, { signal: AbortSignal.timeout(s.timeoutMs), redirect: 'follow' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      const pairs = s.type === 'ieee' ? parseIeeeCsv(text) : parseManuf(text);
      if (pairs.length < 100) throw new Error(`解析结果过少(${pairs.length})`);
      // 整表替换必须在一个事务里，否则中途失败会留下半截的库，厂商全变成"未知"
      const insert = db.prepare('INSERT INTO oui (prefix, vendor) VALUES (?, ?) ON CONFLICT(prefix) DO UPDATE SET vendor = excluded.vendor');
      db.transaction(() => {
        db.prepare('DELETE FROM oui').run();
        for (const [p, v] of pairs) if (p && v) insert.run(p, v);
      })();
      memMap = new Map();
      for (const [p, v] of pairs) if (p && v) memMap.set(p, v);
      try { fs.writeFileSync(OUI_FILE, text); } catch (e) { /* 缓存失败不影响已落库的数据 */ }
      return { source: s.name, count: pairs.length };
    } catch (e) {
      errors.push(`${s.name}: ${e.message}`);
    }
  }
  // 两个上游源都拿不到：属于"上游网关"问题（网络不通 / 对方返回异常），用 502
  throw httpError(502, '在线更新失败：' + errors.join('; '));
}

function stats() {
  load();
  return { count: memMap.size };
}

module.exports = { lookup, updateOnline, stats };
