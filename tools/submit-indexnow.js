#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const HOST = "atelierdeconsultanta.ro";
const SITE = `https://${HOST}`;
const KEY = "a54d3e71f7854ddd9b9fc4cb91c7d681";
const KEY_LOCATION = `${SITE}/${KEY}.txt`;
const ENDPOINT = "https://api.indexnow.org/indexnow";

function usage() {
  console.log(`Utilizare:
  node tools/submit-indexnow.js --url https://atelierdeconsultanta.ro/pagina.html
  node tools/submit-indexnow.js --sitemap

Optiuni:
  --url <url>       trimite un URL catre IndexNow
  --sitemap         trimite toate URL-urile din sitemap.xml
  --dry-run         afiseaza URL-urile fara submit
  --help            afiseaza ajutorul
`);
}

function parseArgs(argv) {
  const args = { urls: [], sitemap: false, dryRun: false, help: false };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") args.help = true;
    else if (arg === "--url") args.urls.push(argv[++i] || "");
    else if (arg === "--sitemap") args.sitemap = true;
    else if (arg === "--dry-run") args.dryRun = true;
    else throw new Error(`Argument necunoscut: ${arg}`);
  }
  return args;
}

function sitemapUrls() {
  const file = path.join(ROOT, "sitemap.xml");
  const xml = fs.readFileSync(file, "utf8");
  return [...xml.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/g)].map((match) => match[1].trim());
}

function normalizeUrl(value) {
  const url = new URL(value);
  if (url.hostname !== HOST && url.hostname !== `www.${HOST}`) {
    throw new Error(`URL in afara domeniului ${HOST}: ${value}`);
  }
  url.hash = "";
  return url.toString();
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

async function verifyKey() {
  const response = await fetch(`${KEY_LOCATION}?v=${Date.now()}`, { redirect: "manual" });
  const text = (await response.text()).trim();
  if (!response.ok || text !== KEY) {
    throw new Error(`Cheia IndexNow nu este accesibila corect la ${KEY_LOCATION} (status ${response.status}).`);
  }
}

async function submitBatch(urls) {
  const body = {
    host: HOST,
    key: KEY,
    keyLocation: KEY_LOCATION,
    urlList: urls,
  };
  const response = await fetch(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { ok: response.ok, status: response.status, text };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || (!args.urls.length && !args.sitemap)) {
    usage();
    process.exit(args.help ? 0 : 1);
  }

  const urls = unique([
    ...args.urls,
    ...(args.sitemap ? sitemapUrls() : []),
  ]).map(normalizeUrl);

  if (args.dryRun) {
    console.log("IndexNow dry-run:");
    for (const url of urls) console.log(url);
    return;
  }

  await verifyKey();
  const result = await submitBatch(urls);
  console.log(`IndexNow submit: HTTP ${result.status}`);
  console.log(`URL-uri trimise: ${urls.length}`);
  if (!result.ok) {
    if (result.text) console.error(result.text);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
