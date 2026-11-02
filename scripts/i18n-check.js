#!/usr/bin/env node
/* i18n-check.js — 校验 ui/app.js 的 zh/en 键集合完全一致，且所有 t("key") 都有定义 */
"use strict";
const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "..", "ui", "app.js");
const src = fs.readFileSync(file, "utf8");
const start = src.indexOf("var I18N =");
const end = src.indexOf("\n};", start);
if (start < 0 || end < 0) {
  console.error("[i18n] 找不到 I18N 字典");
  process.exit(1);
}
const literal = src.slice(start + "var I18N =".length, end + 2).trim().replace(/;$/, "");
let dict;
try {
  dict = Function('"use strict";return (' + literal + ');')();
} catch (e) {
  console.error("[i18n] I18N 不是合法对象字面量: " + e.message);
  process.exit(1);
}
const zh = Object.keys(dict.zh || {});
const en = Object.keys(dict.en || {});
const missingEn = zh.filter((k) => !(k in (dict.en || {})));
const missingZh = en.filter((k) => !(k in (dict.zh || {})));
const used = new Set([...src.matchAll(/\bt\("([a-zA-Z0-9_]+)"/g)].map((m) => m[1]));
const undefinedKeys = [...used].filter((k) => !(k in (dict.zh || {})) && !(k in (dict.en || {})));
let fail = false;
if (missingEn.length) { console.error("[i18n] en 缺少: " + missingEn.join(", ")); fail = true; }
if (missingZh.length) { console.error("[i18n] zh 缺少: " + missingZh.join(", ")); fail = true; }
if (undefinedKeys.length) { console.error("[i18n] 使用了未定义的键: " + undefinedKeys.join(", ")); fail = true; }
if (fail) process.exit(1);
console.log(`[i18n] zh/en 各 ${zh.length} 个键，一致 ✓`);
