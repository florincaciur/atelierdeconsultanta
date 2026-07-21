#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  SITE,
  canonicalUrl,
} = require("./schema-helpers");
const {
  collectSiteState,
  loadPolicy,
} = require("./generate-sitemap");
const {
  parseSitemapIndex,
  readSitemapEntries,
} = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const ROBOTS_PATH = path.join(ROOT, "robots.txt");
const LLMS_PATH = path.join(ROOT, "llms.txt");
const ALLOWED_LLMS_TECHNICAL_URLS = new Set([`${SITE}/robots.txt`, `${SITE}/sitemap.xml`]);

function fail(message, details = []) {
  console.error(message);
  for (const detail of details.slice(0, 30)) console.error(`- ${detail}`);
  if (details.length > 30) console.error(`- ...and ${details.length - 30} more`);
  process.exitCode = 1;
}

function isW3cDate(value) {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const date = new Date(`${value}T00:00:00Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return false;
  return !Number.isNaN(new Date(value).getTime());
}

function isCleanCanonicalUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin === SITE && !parsed.search && !parsed.hash && !/\.html$/i.test(parsed.pathname) && canonicalUrl(parsed.pathname) === url;
  } catch {
    return false;
  }
}

function parseRobotsGroups(text) {
  const groups = [];
  let current = null;
  let hasDirectives = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/u, "").trim();
    if (!line) continue;
    const match = line.match(/^(User-agent|Allow|Disallow):\s*(.*)$/iu);
    if (!match) continue;
    const directive = match[1].toLowerCase();
    const value = match[2].trim();
    if (directive === "user-agent") {
      if (!current || hasDirectives) {
        current = { agents: [], rules: [] };
        groups.push(current);
        hasDirectives = false;
      }
      current.agents.push(value.toLowerCase());
      continue;
    }
    if (!current) continue;
    current.rules.push({ directive, value });
    hasDirectives = true;
  }
  return groups;
}

function rulesForAgent(groups, agent) {
  return groups.filter((group) => group.agents.includes(agent.toLowerCase())).flatMap((group) => group.rules);
}

function validateRobots(actualUrls) {
  if (!fs.existsSync(ROBOTS_PATH)) return ["robots.txt is missing"];
  const text = fs.readFileSync(ROBOTS_PATH, "utf8");
  const sitemapLines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => /^sitemap:/i.test(line));
  const errors = [];
  if (sitemapLines.length !== 1 || sitemapLines[0] !== `Sitemap: ${SITE}/sitemap.xml`) {
    errors.push(`robots.txt must contain exactly one declaration: Sitemap: ${SITE}/sitemap.xml`);
  }
  const groups = parseRobotsGroups(text);
  for (const agent of ["oai-searchbot", "claude-searchbot"]) {
    const rules = rulesForAgent(groups, agent);
    if (!rules.some((rule) => rule.directive === "allow" && rule.value === "/")) errors.push(`${agent} must be explicitly allowed at /`);
    if (rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) errors.push(`${agent} must not be blocked at /`);
  }
  for (const agent of ["gptbot", "claudebot", "anthropic-ai", "google-extended", "ccbot"]) {
    if (!rulesForAgent(groups, agent).some((rule) => rule.directive === "disallow" && rule.value === "/")) errors.push(`${agent} must be blocked at /`);
  }
  const wildcardDisallows = rulesForAgent(groups, "*").filter((rule) => rule.directive === "disallow" && rule.value).map((rule) => rule.value);
  for (const url of actualUrls) {
    const pathname = new URL(url).pathname;
    if (wildcardDisallows.some((rule) => pathname.startsWith(rule))) errors.push(`${url} is blocked by robots.txt`);
  }
  return errors;
}

function validateLlms(actualSet) {
  if (!fs.existsSync(LLMS_PATH)) return ["llms.txt is missing"];
  const text = fs.readFileSync(LLMS_PATH, "utf8");
  const urls = [...text.matchAll(/https:\/\/atelierdeconsultanta\.ro\/?[^\s<>)\]]*/g)]
    .map((match) => match[0].replace(/[.,;:!?]+$/g, ""));
  const errors = [];
  for (const url of urls) {
    if (ALLOWED_LLMS_TECHNICAL_URLS.has(url)) continue;
    if (!isCleanCanonicalUrl(url)) errors.push(`${url} in llms.txt is not a clean canonical URL`);
    else if (!actualSet.has(url)) errors.push(`${url} in llms.txt is absent from sitemap URL sets`);
  }
  return errors;
}

function validateLastmodDistribution(entries, threshold) {
  const counts = new Map();
  for (const entry of entries.filter((item) => item.lastmod)) counts.set(entry.lastmod, (counts.get(entry.lastmod) || 0) + 1);
  return [...counts.entries()]
    .filter(([, count]) => count >= threshold)
    .map(([date, count]) => `${count} URLs share lastmod ${date}; probable global build/deploy stamp`);
}

function validateLocal() {
  const errors = [];
  const policy = loadPolicy();
  const state = collectSiteState(policy);
  let parsed;
  try {
    parsed = readSitemapEntries(ROOT, policy.indexFile, SITE);
  } catch (error) {
    return { errors: [error.message], entries: [], policy };
  }

  const rootXml = fs.readFileSync(path.join(ROOT, policy.indexFile), "utf8");
  const expectedChildren = policy.families.map((family) => `${SITE}/${family.file}`);
  const actualChildren = parseSitemapIndex(rootXml);
  if (JSON.stringify(actualChildren) !== JSON.stringify(expectedChildren)) {
    errors.push(`sitemap.xml children differ: expected ${expectedChildren.join(", ")}; got ${actualChildren.join(", ")}`);
  }
  const expectedDocuments = new Set([policy.indexFile, ...policy.families.map((family) => family.file)]);
  const actualDocuments = new Set(parsed.documents.map((document) => document.file));
  if (expectedDocuments.size !== actualDocuments.size || [...expectedDocuments].some((file) => !actualDocuments.has(file))) {
    errors.push(`sitemap document set differs: ${[...actualDocuments].join(", ")}`);
  }

  const actualUrls = parsed.entries.map((entry) => entry.url);
  const actualSet = new Set(actualUrls);
  const expectedByUrl = new Map(state.entries.map((entry) => [entry.url, entry]));
  const duplicates = actualUrls.filter((url, index) => actualUrls.indexOf(url) !== index);
  if (duplicates.length) errors.push(...duplicates.map((url) => `duplicate URL: ${url}`));
  for (const url of actualUrls) if (!isCleanCanonicalUrl(url)) errors.push(`invalid/legacy/parameter URL: ${url}`);
  for (const entry of state.entries) if (!actualSet.has(entry.url)) errors.push(`missing canonical URL: ${entry.url}`);
  for (const url of actualUrls) if (!expectedByUrl.has(url)) errors.push(`unexpected sitemap URL: ${url}`);

  const familyByFile = new Map(policy.families.map((family) => [family.file, family.id]));
  for (const entry of parsed.entries) {
    const expected = expectedByUrl.get(entry.url);
    if (!expected) continue;
    if (familyByFile.get(entry.sourceFile) !== expected.family) errors.push(`${entry.url}: wrong sitemap family ${entry.sourceFile}`);
    if (entry.lastmod && !isW3cDate(entry.lastmod)) errors.push(`${entry.url}: invalid W3C lastmod ${entry.lastmod}`);
    if ((entry.lastmod || null) !== (expected.lastmod || null)) {
      errors.push(`${entry.url}: lastmod must be ${expected.lastmod || "omitted"}, got ${entry.lastmod || "omitted"}`);
    }
  }

  errors.push(...validateLastmodDistribution(parsed.entries, policy.suspiciousSharedLastmodThreshold));
  errors.push(...validateRobots(actualUrls));
  errors.push(...validateLlms(actualSet));
  for (const report of ["reports/sitemap-inventory.csv", "reports/sitemap-inventory.md"]) {
    if (!fs.existsSync(path.join(ROOT, report))) errors.push(`missing generated report: ${report}`);
  }
  return { errors, entries: parsed.entries, policy };
}

async function validateLive(entries) {
  const errors = [];
  for (let offset = 0; offset < entries.length; offset += 8) {
    const batch = entries.slice(offset, offset + 8);
    const results = await Promise.all(batch.map(async (entry) => {
      try {
        const response = await fetch(entry.url, { redirect: "manual", headers: { "user-agent": "FABER-Sitemap-QA/1.0" } });
        if (response.status !== 200) return `${entry.url}: live HTTP ${response.status}`;
        const html = await response.text();
        if (/<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*\bnoindex\b/i.test(html)) return `${entry.url}: live page is noindex`;
        const canonical = [...html.matchAll(/<link\b[^>]*>/gi)].map((match) => match[0]).find((tag) => /\brel=["'][^"']*canonical/i.test(tag))?.match(/\bhref=["']([^"']+)["']/i)?.[1];
        if (canonical !== entry.url) return `${entry.url}: live canonical is ${canonical || "missing"}`;
        return null;
      } catch (error) {
        return `${entry.url}: live request failed (${error.message})`;
      }
    }));
    errors.push(...results.filter(Boolean));
  }
  return errors;
}

async function main() {
  const result = validateLocal();
  if (result.errors.length) {
    fail("Sitemap validation failed.", result.errors);
    return;
  }
  if (process.argv.includes("--live")) {
    const liveErrors = await validateLive(result.entries);
    if (liveErrors.length) {
      fail("Live sitemap validation failed.", liveErrors);
      return;
    }
  }
  console.log(`Verified sitemap index with ${result.entries.length} canonical URLs; ${result.entries.filter((entry) => entry.lastmod).length} verified lastmod values.`);
}

if (require.main === module) main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

module.exports = {
  isW3cDate,
  validateLastmodDistribution,
  validateLocal,
  validateLive,
};
