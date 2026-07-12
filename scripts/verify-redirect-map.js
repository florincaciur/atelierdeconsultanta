#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";

function read(relative) {
  return fs.readFileSync(path.join(ROOT, relative), "utf8");
}

function normalizePath(value) {
  try {
    const url = new URL(value, SITE);
    if (url.origin !== SITE) return null;
    return url.pathname || "/";
  } catch {
    return null;
  }
}

function dynamicPattern(value) {
  return value.includes("*") || /(^|\/):[A-Za-z][A-Za-z0-9_-]*/.test(value);
}

function sourceRegex(source) {
  const escaped = source
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/(^|\/):[A-Za-z][A-Za-z0-9_-]*/g, (match) => `${match.startsWith("/") ? "/" : ""}[^/]+`);
  return new RegExp(`^${escaped}$`);
}

const rules = read("_redirects").split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((line, index) => {
    const [source, destination, status = "302"] = line.split(/\s+/);
    return { line: index + 1, source, destination, status, dynamic: dynamicPattern(source) };
  })
  .filter((rule) => /^3\d\d$/.test(rule.status));

const explicit = new Map(rules.filter((rule) => !rule.dynamic).map((rule) => [rule.source, rule]));
const dynamic = rules.filter((rule) => rule.dynamic).map((rule) => ({ ...rule, regex: sourceRegex(rule.source) }));
const sitemapUrls = [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
const sitemapPaths = new Set(sitemapUrls.map((url) => new URL(url).pathname));
const errors = [];

function matchingRule(pathname) {
  return explicit.get(pathname) || dynamic.find((rule) => rule.regex.test(pathname));
}

function fileFor(pathname) {
  const clean = pathname === "/" ? "" : pathname.replace(/^\/+|\/+$/g, "");
  const candidates = clean ? [`${clean}/index.html`, `${clean}.html`] : ["index.html"];
  return candidates.find((file) => fs.existsSync(path.join(ROOT, file))) || null;
}

for (const rule of rules) {
  if (rule.status !== "301") errors.push(`line ${rule.line}: redirectul trebuie să fie 301 (${rule.source})`);
  if (rule.dynamic) continue;
  const seen = new Set([rule.source]);
  let destination = normalizePath(rule.destination);
  if (!destination) continue;
  let next = matchingRule(destination);
  if (next) {
    if (seen.has(destination)) errors.push(`redirect loop: ${[...seen, destination].join(" -> ")}`);
    else errors.push(`redirect chain: ${rule.source} -> ${destination} -> ${next.destination}`);
  }
  if (!sitemapPaths.has(destination)) {
    const destinationFile = fileFor(destination);
    if (!destinationFile) errors.push(`destinație inexistentă: ${rule.source} -> ${destination}`);
    else {
      const html = read(destinationFile);
      if (/\bnoindex\b/i.test((html.match(/<meta[^>]+name=["']robots["'][^>]*>/i) || [""])[0])) {
        errors.push(`destinație noindex: ${rule.source} -> ${destination}`);
      }
      const canonical = html.match(/<link[^>]+rel=["'][^"']*canonical[^"']*["'][^>]+href=["']([^"']+)["']/i)?.[1]
        || html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*canonical/i)?.[1];
      if (canonical && normalizePath(canonical) !== destination) errors.push(`destinație necanonică: ${rule.source} -> ${destination}`);
    }
  }
}

for (const pathname of sitemapPaths) {
  const redirect = matchingRule(pathname);
  if (redirect) errors.push(`URL din sitemap este sursă de redirect: ${pathname} (line ${redirect.line})`);
}

for (const url of sitemapUrls) {
  const pathname = new URL(url).pathname;
  const file = fileFor(pathname);
  if (!file) continue;
  const $ = cheerio.load(read(file));
  $("a[href]").each((_, element) => {
    const raw = String($(element).attr("href") || "").trim();
    if (!raw || raw.startsWith("#") || /^(?:mailto:|tel:|javascript:)/i.test(raw)) return;
    const target = normalizePath(raw);
    if (!target) return;
    const redirect = matchingRule(target);
    if (redirect) errors.push(`link intern către redirect în ${file}: ${raw} (line ${redirect.line})`);
  });
}

const uniqueErrors = [...new Set(errors)];
if (uniqueErrors.length) {
  console.error(`Redirect map failed with ${uniqueErrors.length} error(s):`);
  for (const error of uniqueErrors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Redirect map PASS: ${rules.length} rules, 0 loops, 0 chains, 0 sitemap redirects, 0 internal links to redirects.`);
