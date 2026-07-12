#!/usr/bin/env node
"use strict";

const cp = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const HOST = "atelierdeconsultanta.ro";
const SITE = `https://${HOST}`;
const DEFAULT_KEY_FILE = "indexnow-key.txt";
const DEFAULT_ENDPOINT = "https://api.indexnow.org/indexnow";
const MAX_BATCH_SIZE = 10000;
const KEY_PATTERN = /^[A-Za-z0-9-]{8,128}$/;

function usage() {
  console.log(`Utilizare:
  node tools/submit-indexnow.js --url https://atelierdeconsultanta.ro/pagina
  node tools/submit-indexnow.js --changed
  node tools/submit-indexnow.js --sitemap

Optiuni:
  --url <url>          trimite un URL catre IndexNow; se poate repeta
  --urls <file>        citeste URL-uri dintr-un fisier text, cate unul pe linie
  --changed            trimite URL-urile noi, actualizate sau sterse fata de HEAD~1
  --changed-from <ref> compara fisierele publice cu ref-ul indicat (implicit HEAD~1)
  --sitemap            trimite toate URL-urile din sitemap.xml
  --list               afiseaza doar URL-urile selectate, cate unul pe linie
  --dry-run            afiseaza payload-ul fara submit
  --skip-key-check     nu verifica live fisierul keyLocation inainte de submit
  --endpoint <url>     endpoint IndexNow alternativ
  --help               afiseaza ajutorul

Variabile:
  INDEXNOW_KEY_FILE       fisierul local cu cheia; implicit indexnow-key.txt
  INDEXNOW_KEY_LOCATION   URL public pentru fisierul cheii
  INDEXNOW_ENDPOINT       endpoint API; implicit https://api.indexnow.org/indexnow
`);
}

function parseArgs(argv) {
  const args = {
    urls: [],
    urlFiles: [],
    changed: false,
    changedFrom: "HEAD~1",
    sitemap: false,
    list: false,
    dryRun: false,
    skipKeyCheck: false,
    endpoint: process.env.INDEXNOW_ENDPOINT || DEFAULT_ENDPOINT,
    help: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") args.help = true;
    else if (arg === "--url") args.urls.push(argv[++i] || "");
    else if (arg === "--urls") args.urlFiles.push(argv[++i] || "");
    else if (arg === "--changed") args.changed = true;
    else if (arg === "--changed-from") args.changedFrom = argv[++i] || "HEAD~1";
    else if (arg === "--sitemap") args.sitemap = true;
    else if (arg === "--list") args.list = true;
    else if (arg === "--dry-run") args.dryRun = true;
    else if (arg === "--skip-key-check") args.skipKeyCheck = true;
    else if (arg === "--endpoint") args.endpoint = argv[++i] || DEFAULT_ENDPOINT;
    else throw new Error(`Argument necunoscut: ${arg}`);
  }

  return args;
}

function keyFileName() {
  return process.env.INDEXNOW_KEY_FILE || DEFAULT_KEY_FILE;
}

function keyPath() {
  const value = keyFileName();
  return path.isAbsolute(value) ? value : path.join(ROOT, value);
}

function readKey() {
  const key = fs.readFileSync(keyPath(), "utf8").trim();
  if (!KEY_PATTERN.test(key)) {
    throw new Error(`Cheie IndexNow invalida in ${keyFileName()}. Cheia trebuie sa aiba 8-128 caractere: litere, cifre sau cratima.`);
  }
  return key;
}

function publicKeyLocation() {
  if (process.env.INDEXNOW_KEY_LOCATION) return process.env.INDEXNOW_KEY_LOCATION;
  return `${SITE}/${DEFAULT_KEY_FILE}`;
}

function parseSitemapXml(xml) {
  const entries = new Map();
  const pattern = /<url>\s*<loc>\s*([^<]+)\s*<\/loc>\s*(?:<lastmod>\s*([^<]+)\s*<\/lastmod>)?[\s\S]*?<\/url>/g;
  for (const match of xml.matchAll(pattern)) {
    entries.set(match[1].trim(), (match[2] || "").trim());
  }
  return entries;
}

function currentSitemapEntries() {
  const file = path.join(ROOT, "sitemap.xml");
  return parseSitemapXml(fs.readFileSync(file, "utf8"));
}

function previousSitemapEntries(ref) {
  try {
    const xml = cp.execFileSync("git", ["show", `${ref}:sitemap.xml`], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return parseSitemapXml(xml);
  } catch {
    return null;
  }
}

function sitemapUrls() {
  return [...currentSitemapEntries().keys()];
}

function changedSitemapUrls(ref) {
  const current = currentSitemapEntries();
  const previous = previousSitemapEntries(ref);
  if (!previous) return [];

  const urls = [];
  for (const url of current.keys()) if (!previous.has(url)) urls.push(url);
  for (const url of previous.keys()) {
    if (!current.has(url)) urls.push(url);
  }
  return urls;
}

function canonicalFromHtml(html) {
  for (const match of String(html || "").matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    if (href) return href[1].trim();
  }
  return null;
}

function gitText(args) {
  try {
    return cp.execFileSync("git", args, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

function htmlChanges(ref) {
  const output = gitText(["diff", "--name-status", "-M", ref, "HEAD", "--", "*.html"]);
  if (output === null) return [];
  return output.split(/\r?\n/).filter(Boolean).map((line) => {
    const fields = line.split("\t");
    const status = fields[0];
    if (/^[RC]/.test(status)) return { status, before: fields[1], after: fields[2] };
    return { status, before: fields[1], after: fields[1] };
  });
}

function htmlAtRef(ref, file) {
  return gitText(["show", `${ref}:${file}`]);
}

function changedCanonicalUrls(ref) {
  const current = currentSitemapEntries();
  const previous = previousSitemapEntries(ref);
  if (!previous) return [];
  const urls = new Set(changedSitemapUrls(ref));

  for (const change of htmlChanges(ref)) {
    if (!change.status.startsWith("D") && change.after && fs.existsSync(path.join(ROOT, change.after))) {
      const canonical = canonicalFromHtml(fs.readFileSync(path.join(ROOT, change.after), "utf8"));
      if (canonical && current.has(canonical)) urls.add(canonical);
    }
    if (!change.status.startsWith("A") && change.before) {
      const canonical = canonicalFromHtml(htmlAtRef(ref, change.before));
      if (canonical && previous.has(canonical)) urls.add(canonical);
    }
  }
  return [...urls];
}

function urlsFromFile(file) {
  return fs.readFileSync(path.resolve(ROOT, file), "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function normalizeUrl(value) {
  const url = new URL(value, SITE);
  if (url.hostname !== HOST && url.hostname !== `www.${HOST}`) {
    throw new Error(`URL in afara domeniului ${HOST}: ${value}`);
  }
  url.protocol = "https:";
  url.hostname = HOST;
  url.hash = "";
  if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/g, "");
  return url.toString();
}

function unique(values) {
  return [...new Set(values.filter(Boolean).map(normalizeUrl))];
}

function chunks(values, size) {
  const result = [];
  for (let i = 0; i < values.length; i += size) result.push(values.slice(i, i + size));
  return result;
}

async function verifyKey(key, keyLocation) {
  const response = await fetch(`${keyLocation}?v=${Date.now()}`, { redirect: "manual" });
  const text = (await response.text()).trim();
  if (!response.ok || text !== key) {
    throw new Error(`Cheia IndexNow nu este accesibila corect la ${keyLocation} (status ${response.status}).`);
  }
}

async function submitBatch({ endpoint, key, keyLocation, urls }) {
  const body = {
    host: HOST,
    key,
    keyLocation,
    urlList: urls,
  };
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { ok: response.status === 200 || response.status === 202, status: response.status, text };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    usage();
    return;
  }
  if (!args.urls.length && !args.urlFiles.length && !args.changed && !args.sitemap) {
    usage();
    process.exit(1);
  }

  const urls = unique([
    ...args.urls,
    ...args.urlFiles.flatMap(urlsFromFile),
    ...(args.changed ? changedCanonicalUrls(args.changedFrom) : []),
    ...(args.sitemap ? sitemapUrls() : []),
  ]);

  if (args.list) {
    for (const url of urls) console.log(url);
    return;
  }

  if (!urls.length) {
    console.log("IndexNow: nu exista URL-uri de trimis.");
    return;
  }

  const key = readKey();
  const keyLocation = publicKeyLocation();

  if (args.dryRun) {
    console.log("IndexNow dry-run:");
    console.log(`Endpoint: ${args.endpoint}`);
    console.log(`Host: ${HOST}`);
    console.log(`KeyLocation: ${keyLocation}`);
    console.log(`URL-uri: ${urls.length}`);
    for (const url of urls) console.log(url);
    return;
  }

  if (!args.skipKeyCheck) await verifyKey(key, keyLocation);

  let submitted = 0;
  for (const batch of chunks(urls, MAX_BATCH_SIZE)) {
    const result = await submitBatch({ endpoint: args.endpoint, key, keyLocation, urls: batch });
    console.log(`IndexNow submit: HTTP ${result.status}; batch=${batch.length}`);
    if (!result.ok) {
      if (result.text) console.error(result.text);
      process.exit(1);
    }
    submitted += batch.length;
  }
  console.log(`URL-uri trimise: ${submitted}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
