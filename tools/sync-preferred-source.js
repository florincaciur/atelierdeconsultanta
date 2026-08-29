#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");

const PARTIAL_PATH = path.join(ROOT, "partials", "preferred-source.html");
const START = "<!-- PREFERRED_SOURCE_START -->";
const END = "<!-- PREFERRED_SOURCE_END -->";
const HEAD_START = "<!-- PREFERRED_SOURCE_HEAD_START -->";
const HEAD_END = "<!-- PREFERRED_SOURCE_HEAD_END -->";
const SCRIPT_START = "<!-- PREFERRED_SOURCE_SCRIPT_START -->";
const SCRIPT_END = "<!-- PREFERRED_SOURCE_SCRIPT_END -->";
const STYLESHEET = '<link rel="stylesheet" href="/assets/preferred-source.css?v=20260829-1">';
const GOOGLE_SCRIPT = '<script async src="https://news.google.com/swg/js/v1/publisher.js"></script>';
const LOCAL_SCRIPT = '<script src="/assets/preferred-source.js?v=20260829-1" defer></script>';
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_FILES = ["sitemap-programs.xml", "sitemap-guides.xml", "sitemap-core.xml"];

function count(text, token) {
  return text.split(token).length - 1;
}

function normalizedPathname(value) {
  const pathname = new URL(value, SITE).pathname.replace(/\/index\.html$/i, "/");
  return pathname === "/" ? "/" : pathname.replace(/\/$/, "");
}

function routeForFile(relativePath) {
  const normalized = relativePath.split(path.sep).join("/");
  if (normalized === "index.html") return "/";
  if (/\/index\.html$/i.test(normalized)) return `/${normalized.replace(/\/index\.html$/i, "")}`;
  return `/${normalized.replace(/\.html$/i, "")}`;
}

function canonicalUrl(html) {
  return html.match(/<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']+)["'])[^>]*>/i)?.[1]
    || html.match(/<link\b(?=[^>]*\bhref=["']([^"']+)["'])(?=[^>]*\brel=["']canonical["'])[^>]*>/i)?.[1]
    || "";
}

function sitemapRoutes() {
  const routes = new Set();
  for (const fileName of SITEMAP_FILES) {
    const filePath = path.join(ROOT, fileName);
    if (!fs.existsSync(filePath)) throw new Error(`Lipsește sitemap-ul necesar Preferred Sources: ${fileName}`);
    const xml = fs.readFileSync(filePath, "utf8");
    for (const match of xml.matchAll(/<loc>([^<]+)<\/loc>/g)) routes.add(normalizedPathname(match[1]));
  }
  return routes;
}

function isCanonicalIndexable(relativePath, html) {
  if (/<meta\b(?=[^>]*\bname=["']robots["'])(?=[^>]*\bcontent=["'][^"']*\bnoindex\b)/i.test(html)) return false;
  const canonical = canonicalUrl(html);
  if (!canonical) return false;
  try {
    const url = new URL(canonical, SITE);
    return url.origin === SITE
      && normalizedPathname(url.href) === normalizedPathname(routeForFile(relativePath))
      && sitemapRoutes().has(normalizedPathname(url.href));
  } catch {
    return false;
  }
}

function partialSource() {
  const partial = fs.readFileSync(PARTIAL_PATH, "utf8").replace(/^\uFEFF/, "").trim();
  if (count(partial, START) !== 1 || count(partial, END) !== 1) throw new Error("Partialul Preferred Sources trebuie să aibă exact o pereche de delimitatori.");
  if (!partial.includes("google-add-preferred-source-btn")) throw new Error("Partialul nu conține controlul oficial Google Preferred Sources.");
  return partial;
}

function removeManagedAsset(html, expression) {
  return html.replace(expression, "");
}

function synchronizeFile(relativePath, partial, options = {}) {
  const filePath = path.join(ROOT, ...relativePath.split("/"));
  const before = fs.readFileSync(filePath, "utf8");
  const eol = before.includes("\r\n") ? "\r\n" : "\n";
  const replacement = partial.replace(/\r\n/g, "\n").replace(/\n/g, eol);
  let after = before;

  if (!isCanonicalIndexable(relativePath, before)) {
    const start = after.indexOf(START);
    const end = after.indexOf(END);
    if (start !== -1 && end !== -1 && end > start) after = `${after.slice(0, start)}${after.slice(end + END.length)}`;
    after = removeManagedAsset(after, /<link\b(?=[^>]*\brel=["']stylesheet["'])(?=[^>]*\bhref=["']\/assets\/preferred-source\.css(?:\?[^"']*)?["'])[^>]*>\s*/giu);
    after = removeManagedAsset(after, /<script\b(?=[^>]*\bsrc=["']https:\/\/news\.google\.com\/swg\/js\/v1\/publisher\.js["'])[^>]*><\/script>\s*/giu);
    after = removeManagedAsset(after, /<script\b(?=[^>]*\bsrc=["']\/assets\/preferred-source\.js(?:\?[^"']*)?["'])[^>]*><\/script>\s*/giu);
    after = after.replace(new RegExp(`${HEAD_START}[\\s\\S]*?${HEAD_END}\\s*`, "g"), "");
    after = after.replace(new RegExp(`${SCRIPT_START}[\\s\\S]*?${SCRIPT_END}\\s*`, "g"), "");
    if (after === before) return false;
    if (!options.check) fs.writeFileSync(filePath, after, "utf8");
    return true;
  }

  const start = after.indexOf(START);
  const end = after.indexOf(END);
  if ((start === -1) !== (end === -1) || count(after, START) > 1 || count(after, END) > 1) throw new Error(`${relativePath}: delimitatori Preferred Sources invalizi.`);
  if (start !== -1) {
    after = `${after.slice(0, start)}${replacement}${after.slice(end + END.length)}`;
  } else {
    const footer = /<footer\b/i.exec(after);
    const bodyEnd = /<\/body>/i.exec(after);
    const insertion = footer?.index ?? bodyEnd?.index;
    if (insertion === undefined) throw new Error(`${relativePath}: lipsește footer/body pentru inserare.`);
    after = `${after.slice(0, insertion)}${replacement}${eol}${after.slice(insertion)}`;
  }

  after = removeManagedAsset(after, /<link\b(?=[^>]*\brel=["']stylesheet["'])(?=[^>]*\bhref=["']\/assets\/preferred-source\.css(?:\?[^"']*)?["'])[^>]*>\s*/giu);
  after = removeManagedAsset(after, /<script\b(?=[^>]*\bsrc=["']https:\/\/news\.google\.com\/swg\/js\/v1\/publisher\.js["'])[^>]*><\/script>\s*/giu);
  after = removeManagedAsset(after, /<script\b(?=[^>]*\bsrc=["']\/assets\/preferred-source\.js(?:\?[^"']*)?["'])[^>]*><\/script>\s*/giu);
  after = after.replace(new RegExp(`${HEAD_START}[\\s\\S]*?${HEAD_END}\\s*`, "g"), "");
  after = after.replace(new RegExp(`${SCRIPT_START}[\\s\\S]*?${SCRIPT_END}\\s*`, "g"), "");

  const headStart = /<head\b[^>]*>/i.exec(after);
  if (!headStart) throw new Error(`${relativePath}: lipsește <head>.`);
  const headInsertion = headStart.index + headStart[0].length;
  const headTail = after.slice(headInsertion)
    .replace(/^(?:[ \t]*\r?\n)+/, "")
    .replace(/^[ \t]+(?=<)/, "");
  const headBlock = `${HEAD_START}${eol}${STYLESHEET}${eol}${GOOGLE_SCRIPT}${eol}${LOCAL_SCRIPT}${eol}${HEAD_END}`;
  after = `${after.slice(0, headInsertion)}${eol}${headBlock}${eol}${headTail}`;

  if (after === before) return false;
  if (!options.check) fs.writeFileSync(filePath, after, "utf8");
  return true;
}

function main() {
  const check = process.argv.includes("--check");
  const partial = partialSource();
  const files = findPublicHtmlFiles();
  let eligible = 0;
  let changed = 0;
  const changedFiles = [];
  const canonicalRoutes = new Set();
  for (const relativePath of files) {
    const html = fs.readFileSync(path.join(ROOT, ...relativePath.split("/")), "utf8");
    if (isCanonicalIndexable(relativePath, html)) {
      eligible += 1;
      canonicalRoutes.add(normalizedPathname(canonicalUrl(html)));
    }
    if (synchronizeFile(relativePath, partial, { check })) {
      changed += 1;
      changedFiles.push(relativePath);
    }
  }
  if (check && changed) throw new Error(`Preferred Sources nu este sincronizat în ${changed} din ${eligible} fișiere canonice indexabile:\n- ${changedFiles.join("\n- ")}`);
  console.log(check
    ? `PASS: Google Preferred Sources este sincronizat în ${eligible} fișiere pentru ${canonicalRoutes.size} rute canonice indexabile.`
    : `Google Preferred Sources: ${changed} fișiere modificate, ${eligible} fișiere pentru ${canonicalRoutes.size} rute canonice indexabile verificate.`);
}

if (require.main === module) main();

module.exports = { END, GOOGLE_SCRIPT, HEAD_END, HEAD_START, LOCAL_SCRIPT, PARTIAL_PATH, START, STYLESHEET, canonicalUrl, isCanonicalIndexable, routeForFile, sitemapRoutes, synchronizeFile };
