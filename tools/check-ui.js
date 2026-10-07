'use strict';

/**
 * 前端模板体检：按浏览器上 Vue 的解析方式检查一遍 index.html 里 #app 的模板。
 *
 * 浏览器用 DOM 解析器读模板，会先解码属性值里的 HTML 实体再当 JS 编译，含 `&#10;` 会变成真实换行，
 * 导致渲染函数语法错误、全站白屏，而 `node --check` 和后端测试发现不了，所以改完前端后先跑一遍。
 *
 * 用法：npm run check-ui [文件路径]      （不带路径则检查 public/index.html）
 */

const fs = require('fs');
const path = require('path');

const file = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(__dirname, '..', 'public', 'index.html');
const html = fs.readFileSync(file, 'utf8');

// 模板范围：#app 容器到引入 Vue 的 script 之前
const start = html.indexOf('<div id="app"');
const end = html.indexOf('<script src="/vendor/vue.global.prod.js">');
if (start < 0 || end <= start) {
  console.error(`在 ${file} 里定位不到 #app 模板范围（是否改了容器写法？）`);
  process.exit(1);
}
const template = html.slice(start, end);

/** 与 Vue 的 DOM 模板解析接近的实体解码（数值实体 + 常用命名实体） */
function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&nbsp;/g, '\u00a0').replace(/&amp;/g, '&');
}

// 会参与 JS 表达式编译的属性
const EXPR_ATTR = /(?:^|\s)([:@][\w.-]+|v-if|v-else-if|v-for|v-show|v-html|v-text|v-model[\w.]*)="([^"]*)"/g;

const problems = [];
let checked = 0;

for (const m of template.matchAll(EXPR_ATTR)) {
  const attr = m[1];
  const raw = m[2];
  const decoded = decodeEntities(raw);
  checked++;

  if (/&#/.test(raw)) {
    problems.push(`${attr}: 表达式里出现 HTML 实体「${raw.slice(0, 70)}」。Vue 会先解码成真实字符再编译，容易造成语法错误`);
  }
  if (/[\r\n]/.test(decoded)) {
    problems.push(`${attr}: 解码后出现真实换行，会导致 JS 字符串未闭合（白屏）`);
    continue;
  }

  if (attr === 'v-for') continue;                   // "x in y" 形态跳过语法校验
  const src = attr.startsWith('@') ? decoded : `return (${decoded})`;
  try {
    // eslint-disable-next-line no-new-func
    new Function(src);
  } catch (e) {
    problems.push(`${attr}: 表达式语法错误 -> ${e.message}  ｜  ${decoded.slice(0, 90)}`);
  }
}

// 模板里调用的组件方法是否都在 app.js 里有定义
const appjs = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const defined = new Set();
for (const m of appjs.matchAll(/^\s{4}(?:async\s+)?([a-zA-Z_$][\w$]*)\s*\(/gm)) defined.add(m[1]);
for (const m of appjs.matchAll(/^\s{4}([a-zA-Z_$][\w$]*)\s*:\s*(?:\(|async)/gm)) defined.add(m[1]);

const KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'return', 'function', 'typeof', 'new', 'in', 'of',
  'catch', 'delete', 'void', 'yield', 'await', 'do', 'else', 'try']);
const GLOBALS = new Set(['URLSearchParams', 'JSON', 'Number', 'String', 'Math', 'Object', 'Array',
  'parseInt', 'parseFloat', 'Date', 'confirm', 'alert', 'Boolean']);
const used = new Set();
for (const m of template.matchAll(EXPR_ATTR)) {
  for (const f of decodeEntities(m[2]).matchAll(/(?<![.\w$])([a-zA-Z_$][\w$]*)\s*\(/g)) {
    used.add(f[1]);
    if (!defined.has(f[1]) && !KEYWORDS.has(f[1]) && !GLOBALS.has(f[1])) {
      problems.push(`模板调用了未定义的方法：${f[1]}()`);
    }
  }
}

console.log(`检查 ${path.relative(process.cwd(), file)}：${checked} 个表达式属性，模板调用方法 ${used.size} 个`);
if (problems.length) {
  console.log('发现问题：');
  for (const p of problems) console.log('  - ' + p);
  process.exit(1);
}
console.log('模板表达式检查：通过');
