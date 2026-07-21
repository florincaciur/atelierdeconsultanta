#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const POLICY_PATH = path.join(ROOT, "config", "sitemap-policy.json");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const HEADERS_PATH = path.join(ROOT, "_headers");
const REPORT_CSV_PATH = path.join(ROOT, "reports", "sitemap-inventory.csv");
const REPORT_MD_PATH = path.join(ROOT, "reports", "sitemap-inventory.md");
const {
  SITE,
  canonicalUrl,
  normalizeCanonicalPath,
} = require("./schema-helpers");
const {
  isCompleteRecord,
  isIsoDate,
  loadEditorialGovernance,
} = require("./editorial-governance");
const { parseUrlsetEntries } = require("./sitemap-utils");

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);
const DRAFT_PATH_PATTERN = /(^|\/)(?:draft|drafts|_draft|_drafts)(?:\/|$)/i;
const ALTERNATE_CANONICAL_PATHS = new Set(["/blog?post=blog-1"]);

function loadPolicy() {
  const policy = JSON.parse(fs.readFileSync(POLICY_PATH, "utf8"));
  if (policy.site !== SITE) throw new Error(`config/sitemap-policy.json must use ${SITE}`);
  if (!Array.isArray(policy.families) || policy.families.filter((family) => family.fallback).length !== 1) {
    throw new Error("Sitemap policy must define exactly one fallback family.");
  }
  return policy;
}

function toPosix(value) {
  return value.split(path.sep).join("/");
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
    if (entry.isDirectory()) walkHtml(fullPath, files);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html") && !isDraftPath(fullPath)) files.push(fullPath);
  }
  return files;
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
      regex: containsDynamicToken(rule.source) ? patternToRegex(rule.source) : null,
    }));
}

function isRedirectSource(pathname, redirectRules) {
  return redirectRules.some((rule) => (rule.dynamic ? rule.regex.test(pathname) : rule.source === pathname));
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
  const escaped = String(pattern).replace(/[|\\{}()[\]^$+?.]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function hasNoindexHeader(pathname, headerRules) {
  return headerRules.some((rule) => {
    const matches = rule.pattern === pathname || (rule.pattern.includes("*") && headerPatternToRegex(rule.pattern).test(pathname));
    return matches && /\bnoindex\b/i.test(rule.headers["x-robots-tag"] || "");
  });
}

function extractCanonical(html) {
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (!/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i);
    if (href) return href[1].trim();
  }
  return null;
}

function extractBodyAttribute(html, name) {
  const body = html.match(/<body\b[^>]*>/i)?.[0] || "";
  return body.match(new RegExp(`\\b${name}=["']([^"']+)["']`, "i"))?.[1]?.trim() || "";
}

function hasNoindex(html) {
  return /<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*\bnoindex\b/i.test(html);
}

function hasMetaRefresh(html) {
  return /<meta[^>]+http-equiv=["']refresh["']/i.test(html);
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

function editorialRecords() {
  const { records } = loadEditorialGovernance();
  return new Map(records.map((record) => [normalizeCanonicalPath(record.route), record]));
}

function editorialLastmods(recordsByRoute = editorialRecords()) {
  const result = new Map();
  for (const record of recordsByRoute.values()) {
    if (!isCompleteRecord(record) || !isIsoDate(record.lastMeaningfulUpdate)) continue;
    result.set(canonicalUrl(record.route), record.lastMeaningfulUpdate);
  }
  return result;
}

function lastmodForFile(_filePath, url, _previousLastmods, meaningfulLastmods) {
  return meaningfulLastmods.get(url) || null;
}

function familyFor(route, html, governanceRecord, policy) {
  const pageType = extractBodyAttribute(html, "data-analytics-page-type");
  for (const family of policy.families.filter((candidate) => !candidate.fallback)) {
    if (governanceRecord && (family.governanceContentTypes || []).includes(governanceRecord.contentType)) return family.id;
    if ((family.pageTypes || []).includes(pageType)) return family.id;
    if ((family.routePrefixes || []).some((prefix) => route === prefix || route.startsWith(prefix))) return family.id;
  }
  return policy.families.find((family) => family.fallback).id;
}

function priority(url) {
  const pathname = new URL(url).pathname;
  if (pathname === "/") return 0;
  if (["/consultanta-fonduri-europene", "/fonduri-europene", "/dr12-afir", "/dr14", "/digitalizare-imm", "/pro-infra"].includes(pathname)) return 1;
  if (["/despre-faber", "/metodologie-verificare-eligibilitate", "/surse-oficiale-fonduri-europene", "/blog"].includes(pathname)) return 2;
  return 4;
}

function collectSiteState(policy = loadPolicy()) {
  const recordsByRoute = editorialRecords();
  const meaningfulLastmods = editorialLastmods(recordsByRoute);
  const redirectRules = parseRedirectRules();
  const headerRules = parseHeaderRules();
  const included = new Map();
  const excluded = [];

  function exclude(sourceFile, route, url, reason, detail = "") {
    excluded.push({ sourceFile, route, url, reason, detail });
  }

  for (const filePath of walkHtml(ROOT).sort()) {
    const sourceFile = toPosix(path.relative(ROOT, filePath));
    const sourceRoute = canonicalRouteForFile(filePath);
    const html = fs.readFileSync(filePath, "utf8");
    const canonical = extractCanonical(html);
    if (hasNoindex(html)) {
      exclude(sourceFile, sourceRoute, canonical || "", "noindex_meta");
      continue;
    }
    if (hasMetaRefresh(html)) {
      exclude(sourceFile, sourceRoute, canonical || "", "meta_refresh");
      continue;
    }
    if (!canonical) {
      exclude(sourceFile, sourceRoute, "", "missing_canonical");
      continue;
    }
    if (!isInternalCanonical(canonical)) {
      exclude(sourceFile, sourceRoute, canonical, "invalid_or_non_https_canonical");
      continue;
    }
    const parsed = new URL(canonical);
    const route = normalizeCanonicalPath(parsed.pathname);
    const url = canonicalUrl(route);
    if (isAlternateCanonicalPath(route)) {
      exclude(sourceFile, route, url, "alternate_canonical");
      continue;
    }
    if (sourceRoute !== route) {
      exclude(sourceFile, sourceRoute, url, "noncanonical_file_variant", `canonical route: ${route}`);
      continue;
    }
    if (isRedirectSource(route, redirectRules)) {
      exclude(sourceFile, route, url, "redirect_source");
      continue;
    }
    if (hasNoindexHeader(route, headerRules)) {
      exclude(sourceFile, route, url, "noindex_header");
      continue;
    }
    if (policy.excludedRoutes?.[route]) {
      const rule = policy.excludedRoutes[route];
      exclude(sourceFile, route, url, rule.reason, rule.note || "");
      continue;
    }
    const governanceRecord = recordsByRoute.get(route);
    included.set(url, {
      url,
      route,
      sourceFile,
      family: familyFor(route, html, governanceRecord, policy),
      lastmod: lastmodForFile(filePath, url, new Map(), meaningfulLastmods),
    });
  }

  for (const rule of redirectRules.filter((candidate) => !candidate.dynamic)) {
    if (excluded.some((item) => item.route === rule.source)) continue;
    exclude("_redirects", rule.source, rule.destination, "redirect_source", `HTTP ${rule.status}`);
  }

  const entries = [...included.values()].sort((a, b) => priority(a.url) - priority(b.url) || a.url.localeCompare(b.url));
  excluded.sort((a, b) => a.reason.localeCompare(b.reason) || a.route.localeCompare(b.route) || a.sourceFile.localeCompare(b.sourceFile));
  return { entries, excluded, meaningfulLastmods, policy };
}

function escapeXml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function renderUrlset(entries) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries.map((entry) => {
    const lastmod = entry.lastmod ? `\n    <lastmod>${escapeXml(entry.lastmod)}</lastmod>` : "";
    return `  <url>\n    <loc>${escapeXml(entry.url)}</loc>${lastmod}\n  </url>`;
  }).join("\n")}\n</urlset>\n`;
}

function renderIndex(policy) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${policy.families.map((family) => `  <sitemap>\n    <loc>${escapeXml(`${SITE}/${family.file}`)}</loc>\n  </sitemap>`).join("\n")}\n</sitemapindex>\n`;
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function writeReports(state) {
  fs.mkdirSync(path.dirname(REPORT_CSV_PATH), { recursive: true });
  const rows = [["state", "family", "url_or_route", "source_file", "lastmod", "reason", "detail"]];
  for (const entry of state.entries) rows.push(["included", entry.family, entry.url, entry.sourceFile, entry.lastmod || "", "", ""]);
  for (const item of state.excluded) rows.push(["excluded", "", item.url || item.route, item.sourceFile, "", item.reason, item.detail]);
  fs.writeFileSync(REPORT_CSV_PATH, `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`, "utf8");

  const counts = new Map(state.policy.families.map((family) => [family.id, state.entries.filter((entry) => entry.family === family.id).length]));
  const withLastmod = state.entries.filter((entry) => entry.lastmod).length;
  const reasons = new Map();
  for (const item of state.excluded) reasons.set(item.reason, (reasons.get(item.reason) || 0) + 1);
  const markdown = `# Inventar sitemap\n\n` +
    `Generatorul include numai rute locale 200, indexabile si self-canonical. \`lastmod\` exista numai cand provine din \`lastMeaningfulUpdate\` al unei inregistrari editoriale publice si complete.\n\n` +
    `## Rezumat\n\n` +
    `- URL-uri raportate in auditul initial: ${state.policy.reportedAuditUrlCount}\n` +
    `- URL-uri in baseline-ul repository la inceputul P0.11: ${state.policy.repositoryBaselineUrlCount}\n` +
    `- URL-uri incluse acum: ${state.entries.length}\n` +
    `- URL-uri cu lastmod editorial verificabil: ${withLastmod}\n` +
    `- URL-uri fara lastmod (omis intentionat): ${state.entries.length - withLastmod}\n` +
    state.policy.families.map((family) => `- ${family.file}: ${counts.get(family.id)} (${family.label})`).join("\n") +
    `\n\n## Excluderi dupa motiv\n\n` +
    [...reasons.entries()].sort().map(([reason, count]) => `- ${reason}: ${count}`).join("\n") +
    `\n\n## Lista excluderilor\n\n| Ruta/URL | Fisier sursa | Motiv | Detaliu |\n|---|---|---|---|\n` +
    state.excluded.map((item) => `| ${item.url || item.route || "-"} | ${item.sourceFile} | ${item.reason} | ${String(item.detail || "-").replace(/\|/g, "\\|")} |`).join("\n") +
    `\n`;
  fs.writeFileSync(REPORT_MD_PATH, markdown, "utf8");
}

function parseSitemapLastmods(xml) {
  return new Map(parseUrlsetEntries(xml).filter((entry) => entry.lastmod).map((entry) => [entry.url, entry.lastmod]));
}

function generate() {
  const state = collectSiteState();
  for (const family of state.policy.families) {
    const entries = state.entries.filter((entry) => entry.family === family.id);
    fs.writeFileSync(path.join(ROOT, family.file), renderUrlset(entries), "utf8");
  }
  fs.writeFileSync(path.join(ROOT, state.policy.indexFile), renderIndex(state.policy), "utf8");
  writeReports(state);
  const familySummary = state.policy.families.map((family) => `${family.id}=${state.entries.filter((entry) => entry.family === family.id).length}`).join(", ");
  console.log(`Generated sitemap index with ${state.entries.length} canonical URLs (${familySummary}); ${state.entries.filter((entry) => entry.lastmod).length} verified lastmod values.`);
  return state;
}

if (require.main === module) generate();

module.exports = {
  collectSiteState,
  editorialLastmods,
  familyFor,
  generate,
  lastmodForFile,
  loadPolicy,
  parseHeaderRules,
  parseRedirectRules,
  parseSitemapLastmods,
};
