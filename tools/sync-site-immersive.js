#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { fileForRoute } = require("./structured-data-utils");
const { sitemapUrls } = require("./sitemap-utils");
const { seoSignature } = require("./sync-program-visuals");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const CSS_HREF = "/assets/site-immersive.css?v=20260901-1";
const JS_SRC = "/assets/site-immersive.js?v=20260901-1";
const HEAD_START = "SITE_IMMERSIVE_HEAD_START";
const HEAD_END = "SITE_IMMERSIVE_HEAD_END";
const BODY_START = "SITE_IMMERSIVE_SCRIPT_START";
const BODY_END = "SITE_IMMERSIVE_SCRIPT_END";

function canonicalLayerPresent(html) {
  const headBlocks = html.match(new RegExp(`<!--\\s*${HEAD_START}\\s*-->[\\s\\S]*?<!--\\s*${HEAD_END}\\s*-->`, "giu")) || [];
  const bodyBlocks = html.match(new RegExp(`<!--\\s*${BODY_START}\\s*-->[\\s\\S]*?<!--\\s*${BODY_END}\\s*-->`, "giu")) || [];
  const styles = html.match(/<link\b[^>]*href=["']\/assets\/site-immersive\.css(?:\?[^"']*)?["'][^>]*>/giu) || [];
  const scripts = html.match(/<script\b[^>]*src=["']\/assets\/site-immersive\.js(?:\?[^"']*)?["'][^>]*>\s*<\/script>/giu) || [];
  return headBlocks.length === 1
    && bodyBlocks.length === 1
    && styles.length === 1
    && scripts.length === 1
    && headBlocks[0].includes(`href="${CSS_HREF}"`)
    && bodyBlocks[0].includes(`src="${JS_SRC}"`)
    && /<body\b[^>]*\bdata-site-immersive=["']faber-20260901["']/iu.test(html);
}

function routes() {
  return sitemapUrls(ROOT)
    .map((value) => new URL(value).pathname.replace(/\/$/, "") || "/");
}

function synchronizePass(html, route) {
  const eol = html.includes("\r\n") ? "\r\n" : "\n";
  const signatureBefore = seoSignature(html);
  // Asset generators may append analytics scripts after this visual block.
  // Its position inside head/body is irrelevant; preserve an already unique,
  // canonical block instead of creating noisy site-wide reorder diffs.
  if (canonicalLayerPresent(html)) return html;
  let current = html
    .replace(new RegExp(`\\s*<!--\\s*${HEAD_START}\\s*-->[\\s\\S]*?<!--\\s*${HEAD_END}\\s*-->\\s*`, "giu"), eol)
    .replace(new RegExp(`\\s*<!--\\s*${BODY_START}\\s*-->[\\s\\S]*?<!--\\s*${BODY_END}\\s*-->\\s*`, "giu"), eol)
    .replace(/<link\b[^>]*href=["']\/assets\/site-immersive\.css(?:\?[^"']*)?["'][^>]*>\s*/giu, "")
    .replace(/<script\b[^>]*src=["']\/assets\/site-immersive\.js(?:\?[^"']*)?["'][^>]*>\s*<\/script>\s*/giu, "");

  if (!/<head\b[^>]*>/iu.test(current) || !/<\/head>/iu.test(current)) throw new Error(`${route}: head invalid`);
  if (!/<body\b[^>]*>/iu.test(current) || !/<\/body>/iu.test(current)) throw new Error(`${route}: body invalid`);

  current = current.replace(/<body\b([^>]*)>/iu, (match, attributes) => {
    if (/\bdata-site-immersive\s*=/iu.test(attributes)) {
      return `<body${attributes.replace(/\bdata-site-immersive\s*=\s*["'][^"']*["']/iu, 'data-site-immersive="faber-20260901"')}>`;
    }
    return `<body${attributes} data-site-immersive="faber-20260901">`;
  });

  const headBlock = `<!-- ${HEAD_START} -->${eol}<link rel="stylesheet" href="${CSS_HREF}">${eol}<!-- ${HEAD_END} -->`;
  const bodyBlock = `<!-- ${BODY_START} -->${eol}<script src="${JS_SRC}" defer></script>${eol}<!-- ${BODY_END} -->`;
  current = current
    .replace(/<\/head>/iu, `${headBlock}${eol}</head>`)
    .replace(/<\/body>/iu, `${bodyBlock}${eol}</body>`);

  if (seoSignature(current) !== signatureBefore) throw new Error(`${route}: stratul vizual a alterat metadatele SEO sau JSON-LD`);
  return current;
}

function synchronize(html, route) {
  let current = html;
  for (let pass = 0; pass < 4; pass += 1) {
    const next = synchronizePass(current, route);
    if (next === current) return next;
    current = next;
  }
  throw new Error(`${route}: stratul vizual nu converge după patru treceri`);
}

function main() {
  const changed = [];
  for (const route of routes()) {
    const file = fileForRoute(ROOT, route);
    if (!fs.existsSync(file)) throw new Error(`${route}: fișier canonic absent`);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, route);
    if (after === before) continue;
    changed.push(path.relative(ROOT, file));
    if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
  }
  if (CHECK_ONLY && changed.length) throw new Error(`Strat vizual nesincronizat: ${changed.join(", ")}`);
  console.log(`Strat vizual FABER: ${routes().length} rute canonice verificate, ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { BODY_END, BODY_START, CSS_HREF, HEAD_END, HEAD_START, JS_SRC, routes, synchronize };
