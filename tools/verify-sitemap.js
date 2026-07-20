#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const ROBOTS_PATH = path.join(ROOT, "robots.txt");
const LLMS_PATH = path.join(ROOT, "llms.txt");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const HEADERS_PATH = path.join(ROOT, "_headers");
const {
  SITE,
  canonicalUrl,
  normalizeCanonicalPath
} = require("./schema-helpers");
const ALLOWED_LLMS_TECHNICAL_URLS = new Set([
  `${SITE}/robots.txt`,
  `${SITE}/sitemap.xml`
]);

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);

const DRAFT_PATH_PATTERN = /(^|\/)(?:draft|drafts|_draft|_drafts)(?:\/|$)/i;
const ALTERNATE_CANONICAL_PATHS = new Set([
  "/blog?post=blog-1",
]);

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function fail(message, details = []) {
  console.error(message);
  for (const detail of details.slice(0, 20)) console.error(`- ${detail}`);
  if (details.length > 20) console.error(`- ...and ${details.length - 20} more`);
  process.exit(1);
}

function isDraftPath(filePath) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  const basename = path.posix.basename(relativePath).toLowerCase();
  return DRAFT_PATH_PATTERN.test(relativePath) || basename.startsWith("draft-") || basename.endsWith(".draft.html");
}

function walkHtml(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkHtml(fullPath, files);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html") && !isDraftPath(fullPath)) {
      files.push(fullPath);
    }
  }
  return files;
}

function hasNoindexOrRedirect(html) {
  return (
    /<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*\bnoindex\b/i.test(html) ||
    /<meta[^>]+http-equiv=["']refresh["']/i.test(html)
  );
}

function containsDynamicToken(value) {
  return value.includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/.test(value);
}

function patternToRegex(pattern) {
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/(^|\/):[A-Za-z][A-Za-z0-9_]*/g, (match) => `${match.startsWith("/") ? "/" : ""}[^/]+`);
  return new RegExp(`^${escaped}$`);
}

function parseRedirectRules() {
  if (!fs.existsSync(REDIRECTS_PATH)) return [];
  return fs.readFileSync(REDIRECTS_PATH, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [source, destination, status = "302"] = line.split(/\s+/);
      return { source, destination, status };
    })
    .filter((rule) => /^3\d\d$/.test(rule.status))
    .map((rule) => ({
      ...rule,
      dynamic: containsDynamicToken(rule.source),
      regex: containsDynamicToken(rule.source) ? patternToRegex(rule.source) : null
    }));
}

function isRedirectSource(pathname, redirectRules) {
  return redirectRules.some((rule) => (
    rule.dynamic ? rule.regex.test(pathname) : rule.source === pathname
  ));
}

function parseHeaderRules() {
  if (!fs.existsSync(HEADERS_PATH)) return [];
  const rules = [];
  let current = null;
  for (const line of fs.readFileSync(HEADERS_PATH, "utf8").split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      current = { pattern: line.trim(), headers: {} };
      rules.push(current);
      continue;
    }
    if (!current) continue;
    const [name, ...rest] = line.trim().split(":");
    current.headers[name.toLowerCase()] = rest.join(":").trim();
  }
  return rules;
}

function headerPatternToRegex(pattern) {
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function headerRuleMatches(pattern, pathname) {
  return pattern === pathname || (pattern.includes("*") && headerPatternToRegex(pattern).test(pathname));
}

function hasNoindexHeader(pathname, headerRules) {
  return headerRules.some((rule) => (
    headerRuleMatches(rule.pattern, pathname) &&
    /\bnoindex\b/i.test(rule.headers["x-robots-tag"] || "")
  ));
}

function extractCanonical(html) {
  const linkMatches = html.matchAll(/<link\b[^>]*>/gi);
  for (const match of linkMatches) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    if (href) return href[1].trim();
  }
  return "";
}

function isInternalCanonical(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin === SITE && !parsed.search && !parsed.hash && canonicalUrl(parsed.pathname) === url;
  } catch {
    return false;
  }
}

function canonicalRouteForFile(filePath) {
  const relativePath = toPosix(path.relative(ROOT, filePath));
  if (relativePath === "index.html") return "/";
  if (relativePath.endsWith("/index.html")) return `/${relativePath.replace(/\/index\.html$/i, "")}`;
  if (relativePath.endsWith(".html")) return `/${relativePath.replace(/\.html$/i, "")}`;
  return "";
}

function isAlternateCanonicalPath(pathname) {
  const clean = pathname === "/" ? "/" : pathname.replace(/\/+$/g, "");
  return ALTERNATE_CANONICAL_PATHS.has(clean);
}

function normalizeUrl(url) {
  const parsed = new URL(url);
  return canonicalUrl(parsed.pathname);
}

function sitemapUrls() {
  if (!fs.existsSync(SITEMAP_PATH)) fail("sitemap.xml is missing.");
  const xml = fs.readFileSync(SITEMAP_PATH, "utf8");
  const urls = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
  if (!urls.length) fail("sitemap.xml has no <loc> entries.");
  return urls;
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
  const normalized = agent.toLowerCase();
  return groups
    .filter((group) => group.agents.includes(normalized))
    .flatMap((group) => group.rules);
}

function robotsRules() {
  if (!fs.existsSync(ROBOTS_PATH)) fail("robots.txt is missing.");
  const text = fs.readFileSync(ROBOTS_PATH, "utf8");
  if (!new RegExp(`^\\s*Sitemap:\\s*${SITE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\/sitemap\\.xml\\s*$`, "im").test(text)) {
    fail("robots.txt must declare the canonical sitemap URL.", [`expected: Sitemap: ${SITE}/sitemap.xml`]);
  }

  const groups = parseRobotsGroups(text);
  const requiredSearchBots = ["oai-searchbot", "claude-searchbot"];
  const requiredTrainingBots = ["gptbot", "claudebot", "anthropic-ai", "google-extended", "ccbot"];
  const policyErrors = [];

  for (const agent of requiredSearchBots) {
    const rules = rulesForAgent(groups, agent);
    if (!rules.some((rule) => rule.directive === "allow" && rule.value === "/")) {
      policyErrors.push(`${agent} must be explicitly allowed at /`);
    }
    if (rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) {
      policyErrors.push(`${agent} must not be blocked at /`);
    }
  }

  for (const agent of requiredTrainingBots) {
    const rules = rulesForAgent(groups, agent);
    if (!rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) {
      policyErrors.push(`${agent} must be blocked at /`);
    }
  }

  if (policyErrors.length) fail("robots.txt does not match the AI search/training policy.", policyErrors);

  return rulesForAgent(groups, "*")
    .filter((rule) => rule.directive === "disallow")
    .map((rule) => rule.value)
    .filter(Boolean);
}

function isBlockedByRobots(pathname, disallowRules) {
  return disallowRules.some((rule) => pathname.startsWith(rule));
}

function llmsUrls() {
  if (!fs.existsSync(LLMS_PATH)) fail("llms.txt is missing.");
  const text = fs.readFileSync(LLMS_PATH, "utf8");
  return [...text.matchAll(/https:\/\/atelierdeconsultanta\.ro\/?[^\s<>)\]]*/g)]
    .map((match) => match[0].replace(/[.,;:!?]+$/g, ""))
    .filter(Boolean);
}

function expectedUrls(redirectRules, headerRules) {
  const urls = new Set();
  for (const filePath of walkHtml(ROOT)) {
    const html = fs.readFileSync(filePath, "utf8");
    if (hasNoindexOrRedirect(html)) continue;
    const canonical = extractCanonical(html);
    if (!canonical || !isInternalCanonical(canonical)) continue;
    const normalized = normalizeUrl(canonical);
    const canonicalPath = new URL(normalized).pathname;
    if (isAlternateCanonicalPath(canonicalPath)) continue;
    if (isRedirectSource(canonicalPath, redirectRules)) continue;
    if (hasNoindexHeader(canonicalPath, headerRules)) continue;
    if (canonicalPath !== canonicalRouteForFile(filePath)) continue;
    urls.add(normalized);
  }
  return urls;
}

function validateRobots(actualList) {
  const disallowRules = robotsRules();
  const blockedCanonicalUrls = actualList.filter((url) => isBlockedByRobots(new URL(url).pathname, disallowRules));
  if (blockedCanonicalUrls.length) {
    fail("robots.txt blocks canonical sitemap URLs.", blockedCanonicalUrls);
  }
}

function validateLlms(actual, redirectRules) {
  const urls = llmsUrls();
  const invalid = [];
  for (const url of urls) {
    if (ALLOWED_LLMS_TECHNICAL_URLS.has(url)) continue;
    if (!isInternalCanonical(url)) {
      invalid.push(`${url} is not a clean canonical URL`);
      continue;
    }
    const pathname = normalizeCanonicalPath(new URL(url).pathname);
    if (isRedirectSource(pathname, redirectRules)) {
      invalid.push(`${url} is a redirect source`);
      continue;
    }
    if (!actual.has(canonicalUrl(pathname))) {
      invalid.push(`${url} is not present in sitemap.xml`);
    }
  }
  if (invalid.length) {
    fail("llms.txt contains non-canonical, redirected or non-sitemap URLs.", invalid);
  }
}

const actualList = sitemapUrls();
const actual = new Set(actualList);
const redirectRules = parseRedirectRules();
const headerRules = parseHeaderRules();
const expected = expectedUrls(redirectRules, headerRules);

const duplicates = actualList.filter((url, index) => actualList.indexOf(url) !== index);
if (duplicates.length) fail("sitemap.xml contains duplicate URLs.", duplicates);

const invalidUrls = actualList.filter((url) => !isInternalCanonical(url));
if (invalidUrls.length) fail("sitemap.xml contains invalid canonical URLs.", invalidUrls);

const redirectedUrls = actualList.filter((url) => isRedirectSource(new URL(url).pathname, redirectRules));
if (redirectedUrls.length) fail("sitemap.xml contains redirect source URLs.", redirectedUrls);

const missing = [...expected].filter((url) => !actual.has(url)).sort();
const extra = [...actual].filter((url) => !expected.has(url)).sort();
if (missing.length || extra.length) {
  fail("sitemap.xml does not match indexable canonical HTML pages.", [
    ...missing.map((url) => `missing: ${url}`),
    ...extra.map((url) => `extra: ${url}`),
  ]);
}

validateRobots(actualList);
validateLlms(actual, redirectRules);

console.log(`Verified sitemap.xml with ${actual.size} canonical URLs.`);
