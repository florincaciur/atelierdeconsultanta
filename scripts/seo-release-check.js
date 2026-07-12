#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const NODE = process.execPath;
const NPM_CLI = process.env.npm_execpath;

if (!NPM_CLI || !fs.existsSync(NPM_CLI)) {
  throw new Error("npm CLI path is unavailable; run this check through npm run seo:check");
}

const commands = [
  [NODE, [NPM_CLI, "run", "build"], "build"],
  [NODE, ["tools/audit-content-depth.js"], "content depth"],
  [NODE, ["tools/audit-site-links.js"], "site links"],
  [NODE, ["tools/audit-gsc-routes.js"], "GSC routes"],
  [NODE, ["tools/verify-sitemap.js"], "sitemap"],
  [NODE, ["tools/validate-seo-local.js"], "SEO local"],
  [NODE, ["tools/audit-structured-data.js"], "structured data"],
  [NODE, ["tools/audit-indexing.js"], "indexing"],
  [NODE, ["scripts/verify-canonical-consistency.js"], "canonical consistency"],
  [NODE, ["scripts/verify-redirect-map.js"], "redirect map"],
  [NODE, ["scripts/audit-search-intent.js"], "search intent"],
  [NODE, [NPM_CLI, "run", "check:copy"], "copy normalization"],
  [NODE, [NPM_CLI, "run", "verify:seo"], "SEO integrity"],
  [NODE, ["verify-and-fix.js"], "functional static verification"],
  [NODE, [NPM_CLI, "run", "validate:cloudflare"], "Cloudflare output"],
  [NODE, [NPM_CLI, "run", "test:functional"], "browser functional tests"],
  [NODE, [NPM_CLI, "run", "verify:visual"], "visual integrity"]
];

function run(executable, args, label) {
  console.log(`\n[seo:check] ${label}`);
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    stdio: "inherit",
    shell: false,
    env: process.env
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    console.error(`[seo:check] FAIL: ${label} (exit ${result.status})`);
    process.exit(result.status || 1);
  }
}

function validateFeed() {
  const feedPath = path.join(ROOT, "feed.xml");
  const sitemap = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
  const sitemapUrls = new Set([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim()));
  const feed = fs.readFileSync(feedPath, "utf8");
  if (!/<rss\b[^>]*version=["']2\.0["']/.test(feed) || !/<channel>/.test(feed)) {
    throw new Error("feed.xml is not an RSS 2.0 channel");
  }
  const items = [...feed.matchAll(/<item>([\s\S]*?)<\/item>/g)].map((match) => match[1]);
  if (items.length > 50) throw new Error(`feed.xml contains ${items.length} items; maximum is 50`);
  if (items.length === 0) throw new Error("feed.xml contains no items");
  for (const [index, item] of items.entries()) {
    for (const tag of ["title", "description", "link", "guid", "pubDate", "author"]) {
      if (!new RegExp(`<${tag}\\b[^>]*>[\\s\\S]+?<\\/${tag}>`).test(item)) {
        throw new Error(`feed item ${index + 1} is missing ${tag}`);
      }
    }
    const link = item.match(/<link>([^<]+)<\/link>/)?.[1].trim();
    if (!sitemapUrls.has(link)) throw new Error(`feed item ${index + 1} uses noncanonical link ${link}`);
  }
  console.log(`[seo:check] RSS PASS: ${items.length} canonical items.`);
}

function validateLlms() {
  const sitemap = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
  const sitemapUrls = new Set([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim()));
  const llms = fs.readFileSync(path.join(ROOT, "llms.txt"), "utf8");
  const urls = [...llms.matchAll(/https:\/\/atelierdeconsultanta\.ro(?:\/[A-Za-z0-9_./-]*)?/g)].map((match) => match[0].replace(/[.,;]+$/, ""));
  for (const url of urls) {
    if (!sitemapUrls.has(url)) throw new Error(`llms.txt contains URL outside sitemap: ${url}`);
    if (/\.html(?:$|[?#])|[?#]/.test(url)) throw new Error(`llms.txt contains legacy or parameter URL: ${url}`);
  }
  console.log(`[seo:check] llms.txt PASS: ${new Set(urls).size} canonical URLs.`);
}

for (const [executable, args, label] of commands) run(executable, args, label);

try {
  validateFeed();
  validateLlms();
} catch (error) {
  console.error(`[seo:check] FAIL: ${error.message}`);
  process.exit(1);
}

console.log("\nSEO RELEASE CHECK: PASS");
