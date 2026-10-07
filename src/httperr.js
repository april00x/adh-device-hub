'use strict';

/**
 * 带 HTTP 状态码的错误：把可预期的失败抛给路由层，由 server.js 的错误中间件按原码返回
 * （如 throw httpError(404, '设备不存在')）。
 *
 * 不带状态码的 Error 一律按 500 返回，所以只用来标注调用方能自己纠正的失败，不要伪装真正的 bug。
 */
function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

module.exports = { httpError };
