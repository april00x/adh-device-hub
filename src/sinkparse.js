'use strict';

/**
 * 拦截流量分析的协议识别与请求内容抽取。
 * 不假设端口等于协议：先按首包识别，再决定交给 tls / http / h2 哪个解析器。
 * 本模块只做纯函数：输入 Buffer，输出结构体。不碰 socket、不碰数据库。
 */

const crypto = require('crypto');
const zlib = require('zlib');

// 客户端只可能在 URL 里写这些方法，用它们判定"这是明文 HTTP"
const HTTP_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'];

// 单个 ClientHello 最多等这么多字节：常见报文远小于该值，但后量子 key share 会把它撑大
const MAX_HELLO_BYTES = 8192;

/** TLS 记录版本 -> 人类可读名（仅用于展示） */
function tlsRecordVersionName(v) {
  switch (v) {
    case 0x0300: return 'SSL 3.0';
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default: return '0x' + v.toString(16).padStart(4, '0');
  }
}

/** 带游标与越界保护的读取器：任何越界都抛错，由调用方兜住，避免畸形报文把进程搞崩 */
class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  left() { return this.buf.length - this.pos; }
  need(n) { if (this.left() < n) throw new Error('ClientHello 长度不足'); }
  u8() { this.need(1); return this.buf[this.pos++]; }
  u16() { this.need(2); const v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; }
  bytes(n) { this.need(n); const v = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return v; }
  skip(n) { this.need(n); this.pos += n; }
}

/**
 * 判断首包协议。返回 { kind, need }：
 *   kind = 'pending' 表示字节不够，need 是希望等到的最小长度；
 *   kind = 'tls' | 'http' | 'unknown' 为最终判定。
 */
function probe(buf) {
  if (!buf || !buf.length) return { kind: 'pending', need: 1 };
  const b0 = buf[0];

  // TLS handshake record（0x16）；0x80 是旧版 SSLv2 兼容 ClientHello，同样按 TLS 处理
  if (b0 === 0x16) {
    if (buf.length < 5) return { kind: 'pending', need: 5 };
    const total = 5 + buf.readUInt16BE(3);
    const want = Math.min(total, MAX_HELLO_BYTES);
    if (buf.length < want) return { kind: 'pending', need: want };
    return { kind: 'tls' };
  }
  if (b0 === 0x80) return { kind: 'tls' };

  const head = buf.toString('latin1', 0, Math.min(buf.length, 8));
  for (const m of HTTP_METHODS) {
    if (buf.length >= m.length + 1 && head.startsWith(m + ' ')) return { kind: 'http' };
    // 只收到一半（如 "GE"）时继续等，不要急着判成未知协议
    if (head.length < m.length + 1 && (m + ' ').startsWith(head)) return { kind: 'pending', need: 16 };
  }
  if (buf.length < 16) return { kind: 'pending', need: 16 };
  return { kind: 'unknown' };
}

/** Node 的 socket.getProtocol() 返回值 -> 展示名 */
function protocolName(p) {
  const s = String(p || '');
  const m = s.match(/^TLSv(\d)\.(\d)$/);
  return m ? `TLS ${m[1]}.${m[2]}` : (s || '');
}

/**
 * RFC 8701 的 GREASE 值（高字节等于低字节，且形如 0x?A0A）。
 * Chrome / Android 会塞进 supported_versions、ALPN、密码套件列表，必须忽略，
 * 否则会被当成真实版本，也让套件计数虚高 1。
 */
function isGrease16(v) {
  return (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
}

/** 判断 ALPN 项是不是 GREASE 占位（RFC 8701 规定 GREASE 的 ALPN 是 2 字节且等于该 GREASE 值） */
function isGreaseAlpn(buf) {
  return buf.length === 2 && isGrease16((buf[0] << 8) | buf[1]);
}

/* ---------------- TLS 客户端指纹（JA3 / JA4） ---------------- */

// 版本号 -> JA4 版本段（其余一律 "00"，见 JA4 规范）
const JA4_VERSION = {
  0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
  0x0002: 's2', 0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'
};
const hex4 = (n) => n.toString(16).padStart(4, '0');
const sha12 = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);

/**
 * JA3 = md5("版本,套件,扩展,曲线,点格式")，各列表用 '-' 连接十进制值，GREASE 一律忽略。
 * 判断客户端优先用 JA4，JA3 仅为对齐外部情报库。
 */
function computeJa3(h) {
  const s = [
    h.clientVersionRaw || 0,
    h.cipherIds.join('-'),
    h.extIds.join('-'),
    h.groups.join('-'),
    h.ecPointFormats.join('-')
  ].join(',');
  return crypto.createHash('md5').update(s).digest('hex');
}

/**
 * JA4 = [协议][版本][SNI有无][套件数][扩展数][ALPN首末字符]_[套件列表哈希12]_[扩展+签名算法哈希12]
 * ALPN 段取首末字符；端点不是 ASCII 字母数字时，改用其十六进制表示的首末字符。
 */
function computeJa4(h) {
  const ver = h.highestVersion != null
    ? (JA4_VERSION[h.highestVersion] || '00')
    : (JA4_VERSION[h.clientVersionRaw] || '00');
  const sni = h.extIds.includes(0) ? 'd' : 'i';           // 有 SNI 扩展 = 连的是域名
  const cc = Math.min(99, h.cipherIds.length).toString().padStart(2, '0');
  const ec = Math.min(99, h.extIds.length).toString().padStart(2, '0');
  const alpn = alpnTag(h.alpn[0]);

  const b = h.cipherIds.length ? sha12(h.cipherIds.map(hex4).sort().join(',')) : '000000000000';

  // c 段：扩展排序后去掉 SNI(0000) 与 ALPN(0010)，再追加按原顺序的签名算法
  const extPart = h.extIds.filter((t) => t !== 0x0000 && t !== 0x0010).map(hex4).sort().join(',');
  let cSrc = extPart;
  if (h.sigAlgs.length) cSrc += '_' + h.sigAlgs.map(hex4).join(',');
  const c = extPart ? sha12(cSrc) : '000000000000';

  return `t${ver}${sni}${cc}${ec}${alpn}_${b}_${c}`;
}

/** ALPN 段的 2 个字符，见 computeJa4 注释 */
function alpnTag(first) {
  if (!first) return '00';
  const b = Buffer.from(String(first), 'latin1');
  if (!b.length) return '00';
  const isAlnum = (x) => (x >= 0x30 && x <= 0x39) || (x >= 0x41 && x <= 0x5a) || (x >= 0x61 && x <= 0x7a);
  if (isAlnum(b[0]) && isAlnum(b[b.length - 1])) {
    return String.fromCharCode(b[0]) + String.fromCharCode(b[b.length - 1]);
  }
  const hexStr = b.toString('hex');
  return hexStr[0] + hexStr[hexStr.length - 1];
}

/**
 * 解析 TLS ClientHello 里的 SNI / ALPN / 支持版本。
 * 结构严格按 RFC 8446 / RFC 6066，每一步都做长度校验，畸形报文只返回空结果。
 *
 * 记录头的版本字段是历史兼容值（现代客户端一律填 0x0301），不要用它判断真实 TLS 版本；
 * 真实版本来自 supported_versions 扩展，解密成功后由协商结果覆盖（见 sinkhole.js）。
 */
function parseHello(buf) {
  const out = {
    sni: '', alpn: [], versions: [], cipherCount: 0,
    legacyVersion: '',            // 记录头的版本（兼容值，仅作参考）
    clientVersionRaw: 0,          // ClientHello 里的 client_version，JA3 用的就是它
    highestVersion: null,         // supported_versions 里除 GREASE 外的最高值，JA4 用
    cipherIds: [], extIds: [], groups: [], ecPointFormats: [], sigAlgs: [],
    ja3: '', ja4: ''
  };
  try {
    const r = new Reader(buf);
    if (r.u8() !== 0x16) return out;
    out.legacyVersion = tlsRecordVersionName(r.u16());
    const recLen = r.u16();
    const body = r.bytes(Math.min(recLen, r.left()));

    const h = new Reader(body);
    if (h.u8() !== 0x01) return out;                // handshake type: client_hello
    h.skip(3);                                      // handshake 长度
    out.clientVersionRaw = h.u16();                 // client_version
    h.skip(32);                                     // random
    h.skip(h.u8());                                 // legacy_session_id

    const cipherLen = h.u16();
    // 逐个套件收集（跳过 GREASE，并按规范把 SCSV 0x00FF/0x5600 这类非套件值也算进去）
    const cipherList = new Reader(h.bytes(Math.min(cipherLen, h.left())));
    while (cipherList.left() >= 2) {
      const id = cipherList.u16();
      if (!isGrease16(id)) out.cipherIds.push(id);
    }
    out.cipherCount = out.cipherIds.length;

    h.skip(h.u8());                                 // legacy_compression_methods

    if (h.left() < 2) return fingerprint(out);      // 没有扩展：老客户端
    const extTotal = h.u16();
    const exts = new Reader(h.bytes(Math.min(extTotal, h.left())));

    while (exts.left() >= 4) {
      const type = exts.u16();
      const len = exts.u16();
      const data = new Reader(exts.bytes(Math.min(len, exts.left())));
      if (!isGrease16(type)) out.extIds.push(type);

      if (type === 0x0000) {                        // server_name
        const listLen = data.u16();
        const list = new Reader(data.bytes(Math.min(listLen, data.left())));
        while (list.left() >= 3) {
          const nameType = list.u8();
          const nameLen = list.u16();
          const name = list.bytes(Math.min(nameLen, list.left())).toString('utf8');
          if (nameType === 0 && name) out.sni = name;
        }
      } else if (type === 0x0010) {                 // ALPN
        const alpnListLen = data.u16();
        const list = new Reader(data.bytes(Math.min(alpnListLen, data.left())));
        while (list.left() >= 1) {
          const n = list.u8();
          if (!n) break;
          const name = list.bytes(Math.min(n, list.left()));
          if (!isGreaseAlpn(name)) out.alpn.push(name.toString('latin1'));
        }
      } else if (type === 0x002b) {                 // supported_versions
        const n = data.u8();
        const list = new Reader(data.bytes(Math.min(n, data.left())));
        // GREASE 会排在列表首位，必须跳过；否则会显示成 0x0a0a 这种"版本"
        while (list.left() >= 2) {
          const v = list.u16();
          if (isGrease16(v)) continue;
          out.versions.push(tlsRecordVersionName(v));
          if (out.highestVersion == null || v > out.highestVersion) out.highestVersion = v;
        }
      } else if (type === 0x000a) {                 // supported_groups（JA3 的"椭圆曲线"段）
        const n = data.u16();
        const list = new Reader(data.bytes(Math.min(n, data.left())));
        while (list.left() >= 2) {
          const g = list.u16();
          if (!isGrease16(g)) out.groups.push(g);
        }
      } else if (type === 0x000b) {                 // ec_point_formats（JA3 的"点格式"段）
        data.skip(1);                               // 列表长度（1 字节）
        while (data.left() >= 1) out.ecPointFormats.push(data.u8());
      } else if (type === 0x000d) {                 // signature_algorithms（JA4 的 c 段要用）
        const n = data.u16();
        const list = new Reader(data.bytes(Math.min(n, data.left())));
        while (list.left() >= 2) {
          const a = list.u16();
          if (!isGrease16(a)) out.sigAlgs.push(a);
        }
      }
    }
    return fingerprint(out);
  } catch (e) {
    return out;
  }
}

/** 收尾：算出 JA3 / JA4（原料已在 out 里，避免再解析一遍） */
function fingerprint(out) {
  try {
    out.ja3 = computeJa3(out);
    out.ja4 = computeJa4(out);
  } catch (e) { /* 指纹算不出来不影响其它字段 */ }
  return out;
}

/* ------------------------------ 请求正文解码 ------------------------------ */

// 解压需要相对完整的压缩流，压缩正文的原始字节要放宽采集；上限同时兜住内存，
// 落库体积仍由 preview 的长度上限控制。
const RAW_CAP_MIN = 8192;
const RAW_CAP_MAX = 131072;

/** 原始字节的采集上限：未压缩时按预览长度，压缩时按倍数放宽（解压后才是可读内容） */
function rawCaptureLimit(previewBytes) {
  const n = Math.max(1, Number(previewBytes) || 0);
  return Math.min(RAW_CAP_MAX, Math.max(RAW_CAP_MIN, n * 4));
}

// content-encoding 别名归一；identity 视为无编码；未知编码（zstd 等）原样留着，解压会失败并退回 hex
const KNOWN_ENC = { gzip: 'gzip', 'x-gzip': 'gzip', deflate: 'deflate', 'x-deflate': 'deflate', br: 'br', identity: '' };

function contentEncodings(headers) {
  const raw = String((headers && (headers['content-encoding'] || headers['Content-Encoding'])) || '');
  if (!raw) return [];
  return raw.split(',').map((x) => {
    const t = x.trim().toLowerCase();
    return KNOWN_ENC[t] !== undefined ? KNOWN_ENC[t] : t;
  }).filter(Boolean);
}

/** 单层解压；不认识的编码返回 null（让调用方整条退回 hex，而不是把压缩流当文本读） */
function inflateOnce(buf, enc) {
  const opt = { maxOutputLength: RAW_CAP_MAX };   // 防压缩炸弹：超过上限直接抛错，由调用方兜住
  if (enc === 'gzip') return zlib.gunzipSync(buf, opt);
  if (enc === 'br') return zlib.brotliDecompressSync(buf, opt);
  if (enc === 'deflate') {
    // 有的服务端发裸 deflate（无 zlib 头），先按标准解，失败再按裸流解
    try { return zlib.inflateSync(buf, opt); } catch (e) { return zlib.inflateRawSync(buf, opt); }
  }
  return null;
}

/** 逐层解压；任何一层失败就整体放弃，截断的压缩流解出来是垃圾，不如直接显示 hex */
function tryDecompress(buf, encs) {
  let cur = buf;
  try {
    // 声明顺序 = 施加顺序，所以解码要倒着来
    for (let i = encs.length - 1; i >= 0; i--) {
      const out = inflateOnce(cur, encs[i]);
      if (!out) return null;
      cur = out;
    }
    return cur;
  } catch (e) {
    return null;
  }
}

/** 从 Content-Type 里取 charset */
function charsetOf(headers) {
  const ct = String((headers && (headers['content-type'] || headers['Content-Type'])) || '');
  const m = /charset\s*=\s*"?([\w.-]+)"?/i.exec(ct);
  return m ? m[1].toLowerCase() : '';
}

const countRepl = (s) => s.split('\uFFFD').length - 1;

/** 截断可能正好切断多字节序列：从尾部回退掉没补齐的那一段，免得尾部凭空多出替换字符 */
function trimIncompleteUtf8(buf) {
  for (let i = 0; i < 3 && i < buf.length; i++) {
    const b = buf[buf.length - 1 - i];
    if ((b & 0xc0) === 0x80) continue;                        // 续字节，继续往前找首字节
    const need = b < 0x80 ? 1 : (b & 0xe0) === 0xc0 ? 2 : (b & 0xf0) === 0xe0 ? 3 : (b & 0xf8) === 0xf0 ? 4 : 1;
    return need === i + 1 ? buf : buf.subarray(0, buf.length - 1 - i);
  }
  return buf;
}

/**
 * 解码正文文本。声明了 charset 就按它解；没声明时先按 utf8，替换字符占比偏高再试 gb18030 取更好的那个。
 * 回退截断的多字节尾巴只能用在 utf8 上，对 GBK 做回退会多吃掉最后一个字。
 */
function decodeText(buf, charset) {
  const isPlain = ['utf-8', 'utf8', 'us-ascii', 'ascii'].includes(charset);
  if (charset && !isPlain) {
    try { return { text: new TextDecoder(charset).decode(buf), from: charset }; } catch (e) { /* 未知字符集，退回 utf8 */ }
  }
  const utf8 = trimIncompleteUtf8(buf).toString('utf8');
  if (!charset) {
    const bad = countRepl(utf8);
    if (bad && bad * 50 > utf8.length) {                      // 替换字符超过 2% 才值得多解一次
      try {
        const alt = new TextDecoder('gb18030').decode(buf);
        if (countRepl(alt) < bad) return { text: alt, from: 'gb18030' };
      } catch (e) { /* 没有 big 码表就维持 utf8 */ }
    }
  }
  return { text: utf8, from: 'utf-8' };
}

/** 控制字符（除 \t \r \n）过多说明是二进制，不要当文本落库 */
function looksBinary(text) {
  let ctrl = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 && c !== 9 && c !== 10 && c !== 13) ctrl++;
  }
  return ctrl > Math.max(1, text.length * 0.02);
}

/**
 * 把请求正文变成可安全落库的预览字符串。
 * 顺序：解压 → 解码 → 判二进制 → 截断；每一步失败都退回上一步的结果，不抛错。
 * truncated 由调用方判断（原始字节被截断，或客户端没把声明的正文传完），用于在预览末尾标出「已截断」。
 */
function preview(buf, maxBytes, headers, truncated) {
  return analyzeBody(buf, maxBytes, headers, truncated).preview || '';
}

/* ------------------------------ 正文结构化解析 ------------------------------ */

const MAX_FIELDS = 20;        // 最多抽多少个字段，避免畸形正文把 body_fields 撑大
const MAX_VALUE_LEN = 200;    // 单个字段值的最长长度

/** Content-Type 的 MIME 部分（去掉 charset 等参数），小写 */
function mimeOf(headers) {
  const ct = String((headers && (headers['content-type'] || headers['Content-Type'])) || '');
  return ct.split(';')[0].trim().toLowerCase();
}

/** multipart 的 boundary 参数（可能带引号） */
function boundaryOf(headers) {
  const ct = String((headers && (headers['content-type'] || headers['Content-Type'])) || '');
  const m = /boundary\s*=\s*"?([^";]+)"?/i.exec(ct);
  return m ? m[1].trim() : '';
}

/** 字段值统一压成单行短字符串：换行会破坏摘要的可读性 */
function clip(v) {
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  const one = String(s == null ? '' : s).replace(/[\r\n\t]+/g, ' ').trim();
  return one.length > MAX_VALUE_LEN ? one.slice(0, MAX_VALUE_LEN) + '…' : one;
}

/** JSON：只平铺顶层键，嵌套结构压成一行 JSON */
function jsonFields(text) {
  let o;
  try { o = JSON.parse(text); } catch (e) { return null; }   // 截断的 JSON 解不出来，直接返回空
  if (!o || typeof o !== 'object') return null;
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (Object.keys(out).length >= MAX_FIELDS) break;
    out[String(k).slice(0, 60)] = clip(v);
  }
  return out;
}

/** 表单：application/x-www-form-urlencoded */
function formFields(text) {
  try {
    const out = {};
    for (const [k, v] of new URLSearchParams(text)) {
      if (Object.keys(out).length >= MAX_FIELDS) break;
      if (!out[k]) out[k] = clip(v);
    }
    return out;
  } catch (e) { return null; }
}

/**
 * multipart：必须按原始字节切分（文件 part 是二进制，当文本切会错位）；文本 part 记值，
 * 文件 part 只记文件名与大小，缺结束边界时最后一段丢弃。
 */
function multipartFields(buf, boundary, charset) {
  if (!boundary) return null;
  const sep = Buffer.from('--' + boundary);
  const out = {};
  let pos = 0;
  while (Object.keys(out).length < MAX_FIELDS) {
    const at = buf.indexOf(sep, pos);
    if (at < 0) break;
    const after = at + sep.length;
    if (buf[after] === 0x2d && buf[after + 1] === 0x2d) break;      // 结束边界 --boundary--
    const headStart = (buf[after] === 0x0d && buf[after + 1] === 0x0a) ? after + 2 : after;
    const headEnd = buf.indexOf('\r\n\r\n', headStart);
    if (headEnd < 0) break;                                        // 正文被截断，后面看不到了
    const head = buf.toString('utf8', headStart, headEnd);
    const dataStart = headEnd + 4;
    const nextSep = buf.indexOf(sep, dataStart);
    if (nextSep < 0) break;                                        // 没有结束边界（多半被截断），本段不完整
    const dataEnd = Math.max(dataStart, nextSep - 2);              // 段数据后面跟一个 CRLF
    const name = (/name="([^"]*)"/i.exec(head) || [])[1] || '';
    const file = (/filename="([^"]*)"/i.exec(head) || [])[1] || '';
    if (name) {
      const val = file
        ? `${file}，${dataEnd - dataStart} 字节`
        : decodeText(buf.subarray(dataStart, Math.min(dataEnd, dataStart + MAX_VALUE_LEN)), charset).text;
      out[(file ? name + '（文件）' : name).slice(0, 60)] = clip(val);
    }
    pos = nextSep;
  }
  return Object.keys(out).length ? out : null;
}

/**
 * 判定正文类型。先信 Content-Type，声明缺失或对不上时按内容嗅探（被拦的 App 常乱标 Content-Type）。
 */
function bodyKind(mime, text, isHex) {
  if (isHex) return 'binary';
  if (mime.includes('json')) return 'json';
  if (mime === 'application/x-www-form-urlencoded') return 'form';
  if (mime.startsWith('multipart/')) return 'multipart';
  if (mime.includes('xml')) return 'xml';
  if (mime.startsWith('text/')) return 'text';
  const t = text.trim();
  if (t.startsWith('{') || t.startsWith('[')) return 'json';
  if (t.includes('=') && !t.includes('\n') && !t.includes('<')) return 'form';
  return 'text';
}

/**
 * 一次调用拿到正文的全部产物：预览串 + 类型 + 编码/字符集 + 结构化字段。
 * 预览与字段解析共用同一条解压解码链路，避免两遍解析结果不一致。
 */
function analyzeBody(buf, maxBytes, headers, truncated) {
  const none = { preview: null, kind: null, contentType: null, contentEncoding: null, charset: null, fields: null };
  if (!buf || !buf.length) return none;

  const limit = Math.max(1, Number(maxBytes) || 0);
  const encs = contentEncodings(headers);
  const mime = mimeOf(headers);
  let body = buf;
  let used = '';
  if (encs.length) {
    const plain = tryDecompress(buf, encs);
    if (plain) { body = plain; used = encs.join(','); }
  }

  const slice = body.subarray(0, limit);
  const { text, from } = decodeText(slice, charsetOf(headers));
  const cut = body.length > limit || truncated ? ' …[已截断]' : '';
  const isHex = looksBinary(text);
  const preview = isHex
    ? '[hex] ' + slice.toString('hex') + cut
    : (used ? '[' + used + '] ' : '') + text.replace(/\uFFFD/g, '?') + cut;

  // 服务端明确声明了结构化类型时以声明为准：multipart 混着二进制字节，
  // 按控制字符判会误判成二进制并丢掉本该能抽出的字段（预览仍可能显示 hex，这没错）。
  const declared = mime.includes('json') || mime === 'application/x-www-form-urlencoded' || mime.startsWith('multipart/');
  const kind = bodyKind(mime, text, isHex && !declared);
  let fields = null;
  try {
    if (kind === 'json') fields = jsonFields(text);
    else if (kind === 'form') fields = formFields(text);
    else if (kind === 'multipart') fields = multipartFields(body, boundaryOf(headers), from);
  } catch (e) { fields = null; }

  return {
    preview,
    kind,
    contentType: mime ? mime.slice(0, 120) : null,
    contentEncoding: used ? used.slice(0, 60) : null,
    charset: from ? from.slice(0, 40) : null,
    fields: fields && Object.keys(fields).length ? JSON.stringify(fields) : null
  };
}

/** 未知协议的首包预览：固定走 hex，便于人工识别私有协议 */
function hexPreview(buf, bytes) {
  if (!buf || !buf.length) return '';
  return buf.subarray(0, Math.max(1, bytes)).toString('hex').replace(/(..)/g, '$1 ').trim();
}

/**
 * 从 HTTP 请求里挑出我们真正要落库的字段。
 * h2 的伪头部在 Node 的 http2 里被规范化进 headers，所以 h1 / h2 共用同一套逻辑。
 */
function pickHeaders(headers, { captureAll }) {
  const pick = {
    host: String(headers[':authority'] || headers.host || '').trim(),
    ua: String(headers['user-agent'] || '').trim(),
    referer: String(headers.referer || '').trim(),
    all: null
  };
  if (captureAll) {
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
      if (k.startsWith(':')) continue;
      out[k] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    pick.all = JSON.stringify(out);
  }
  return pick;
}

/** 把 URL 的 path 与 query 拆开，便于只对 path 做聚合 */
function splitPath(raw) {
  const s = String(raw || '/');
  const i = s.indexOf('?');
  if (i < 0) return { path: s.slice(0, 512), query: '' };
  return { path: s.slice(0, i), query: s.slice(i + 1, 1024) };
}

module.exports = {
  probe, parseHello, preview, analyzeBody, hexPreview, pickHeaders, splitPath,
  tlsRecordVersionName, protocolName,
  computeJa3, computeJa4, isGrease16, rawCaptureLimit,
  MAX_HELLO_BYTES
};
