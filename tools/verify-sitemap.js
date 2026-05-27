#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");

function extractTagAttr(tag, attr) {
  const match = tag.match(new RegExp(`\\b${attr}=["']([^"']+)["']`, "i"));
  return match ? match[1].trim() : "";
}

function extractCanonical(html) {
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) {
      return extractTagAttr(tag, "href");
    }
  }
  return "";
}

function extractRobots(html) {
  for (const match of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = match[0];
    if (/\bname=["']robots["']/i.test(tag)) return extractTagAttr(tag, "content");
  }
  return "";
}

function sourceCandidates(pathname) {
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  if (!clean) return [path.join(ROOT, "index.html")];
  return [
    path.join(ROOT, `${clean}.html`),
    path.join(ROOT, clean, "index.html"),
  ];
}

function sourceFor(url) {
  const parsed = new URL(url);
  const candidates = sourceCandidates(parsed.pathname).filter((candidate) => fs.existsSync(candidate));
  const checked = [];

  for (const file of candidates) {
    const html = fs.readFileSync(file, "utf8");
    const canonical = extractCanonical(html);
    const robots = extractRobots(html);
    const noindex = /\bnoindex\b/i.test(robots);
    checked.push({ file, canonical, robots, noindex });
    if (canonical === url && !noindex) return { file, canonical, robots, candidates: checked };
  }

  return { file: "", canonical: "", robots: "", candidates: checked };
}

function validateUrl(url, index, seen, problems) {
  if (seen.has(url)) problems.push(`Duplicate in sitemap: ${url}`);
  seen.add(url);

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    problems.push(`Invalid sitemap URL at position ${index + 1}: ${url}`);
    return;
  }

  if (parsed.origin !== SITE) problems.push(`Non-site URL in sitemap: ${url}`);
  if (parsed.search) problems.push(`Query string in sitemap: ${url}`);
  if (parsed.hash) problems.push(`Hash in sitemap: ${url}`);
  if (parsed.pathname !== "/" && parsed.pathname.endsWith("/")) problems.push(`Trailing slash in sitemap: ${url}`);
  if (parsed.pathname.endsWith(".html")) problems.push(`.html URL in sitemap: ${url}`);
  if (parsed.pathname.endsWith("/index.html")) problems.push(`/index.html URL in sitemap: ${url}`);

  const source = sourceFor(url);
  if (!source.file) {
    if (!source.candidates.length) {
      problems.push(`No source HTML file found for sitemap URL: ${url}`);
      return;
    }
    const details = source.candidates
      .map((candidate) => {
        const relative = path.relative(ROOT, candidate.file).replace(/\\/g, "/");
        const flags = [candidate.canonical ? `canonical=${candidate.canonical}` : "missing canonical"];
        if (candidate.noindex) flags.push("noindex");
        return `${relative} (${flags.join(", ")})`;
      })
      .join("; ");
    problems.push(`No indexable source file with matching canonical for ${url}: ${details}`);
    return;
  }

  if (source.canonical !== url) problems.push(`Canonical mismatch for ${url} -> ${source.canonical || "(missing)"}`);
  if (/\bnoindex\b/i.test(source.robots)) problems.push(`noindex page present in sitemap: ${url}`);
}

function main() {
  if (!fs.existsSync(SITEMAP_PATH)) {
    console.error("sitemap.xml not found; run npm run generate:sitemap first.");
    process.exitCode = 1;
    return;
  }

  const xml = fs.readFileSync(SITEMAP_PATH, "utf8");
  const urls = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
  const problems = [];
  const seen = new Set();

  urls.forEach((url, index) => validateUrl(url, index, seen, problems));

  if (problems.length) {
    for (const problem of problems) console.error(`ERROR ${problem}`);
    process.exitCode = 1;
    return;
  }

  console.log(`sitemap.xml valid with ${urls.length} canonical URLs.`);
}

if (require.main === module) main();
