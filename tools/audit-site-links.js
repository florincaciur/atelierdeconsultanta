#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const cheerio = require("cheerio");
const {
  DOCUMENT_CATEGORIES,
  classificationCounts,
  classifyHtmlFile,
  toPosix
} = require("./site-document-classifier");

const DEFAULT_ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITE_HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const TEXT_EXTENSIONS = new Set([".html", ".json", ".xml", ".txt"]);
const INTERNAL_PATH_PREFIXES = ["tools/", "scripts/", "tests/", "config/", "reports/", "dist/"];
const SKIP_PREFIXES = ["mailto:", "tel:", "sms:", "javascript:", "data:", "blob:", "whatsapp:"];
const PROGRAM_ROUTES = [
  "dr12-afir", "dr14", "por-adr-nord-est", "fonduri-regionale", "fonduri-europene-nord-est",
  "investitii-modernizarea-microintreprinderilor-apel-2", "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice", "digitalizare-imm", "femeia-antreprenor-2026",
  "apeluri-gal", "fondul-modernizare-energie-regenerabila-2026", "pro-infra", "start-up-nation-2026",
  "instrumente", "resurse", "portofoliu", "testimoniale", "webinarii"
];

function isAuditFile(file) {
  const normalized = toPosix(file);
  return !INTERNAL_PATH_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function trackedFiles(root = DEFAULT_ROOT) {
  try {
    return cp.execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
      cwd: root,
      encoding: "utf8"
    })
      .split("\0")
      .filter(Boolean)
      .filter(isAuditFile)
      .filter((file) => TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()));
  } catch {
    const result = [];
    function walk(directory) {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if ([".git", ".github", ".wrangler", "node_modules", "reports", "dist"].includes(entry.name)) continue;
        const full = path.join(directory, entry.name);
        const relative = toPosix(path.relative(root, full));
        if (!isAuditFile(relative)) continue;
        if (entry.isDirectory()) walk(full);
        else if (TEXT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) result.push(relative);
      }
    }
    walk(root);
    return result;
  }
}

function htmlFileForRoute(root, route) {
  let decodedRoute = route;
  try {
    decodedRoute = decodeURIComponent(route);
  } catch {
    // Keep the raw route: an invalid encoded fragment is reported by the fragment validator.
  }
  const clean = decodedRoute.replace(/^\/+/, "");
  if (!clean) return "index.html";
  if (decodedRoute.endsWith("/")) return `${clean}index.html`;
  if (path.posix.extname(clean)) return clean;
  const directoryIndex = `${clean}/index.html`;
  if (fs.existsSync(path.join(root, directoryIndex))) return directoryIndex;
  return `${clean}.html`;
}

function sourceUrlForFile(sourceFile) {
  const normalized = toPosix(sourceFile);
  if (normalized.endsWith("index.html")) {
    const directory = path.posix.dirname(normalized).replace(/^\.$/, "");
    return `${SITE}/${directory ? `${directory}/` : ""}`;
  }
  return `${SITE}/${normalized}`;
}

function normalizeTarget(root, rawValue, sourceFile) {
  if (!rawValue) return null;
  const value = String(rawValue).replace(/&amp;/g, "&").trim();
  if (!value || /^TODO(?:_|$)/u.test(value) || value.includes("${") || value.includes("{{")) return null;
  if (SKIP_PREFIXES.some((prefix) => value.toLowerCase().startsWith(prefix))) return null;
  try {
    const url = new URL(value, sourceUrlForFile(sourceFile));
    if (!/^https?:$/iu.test(url.protocol) || !SITE_HOSTS.has(url.hostname)) return null;
    return {
      route: url.pathname || "/",
      hash: url.hash || "",
      hasFragmentMarker: value.includes("#"),
      targetFile: htmlFileForRoute(root, url.pathname || "/")
    };
  } catch {
    return null;
  }
}

function lineNumber(text, index) {
  return text.slice(0, Math.max(0, index)).split(/\r?\n/u).length;
}

function attributeOffset(text, attribute, value, startAt = 0) {
  for (const quote of ['"', "'"]) {
    const token = `${attribute}=${quote}${value}${quote}`;
    const index = text.indexOf(token, startAt);
    if (index !== -1) return index;
  }
  return text.indexOf(value, startAt);
}

function elementFragmentMetadata($, element) {
  const ariaControls = $(element).attr("aria-controls") || "";
  const ariaHaspopup = $(element).attr("aria-haspopup") || "";
  const dataInteractive = Object.keys(element.attribs || {}).some((name) => /^data-[a-z0-9-]*(?:open|toggle)$/iu.test(name));
  return {
    fragmentType: ariaControls || ariaHaspopup || dataInteractive ? "interactive" : "anchor",
    ariaControls,
    ariaHaspopup
  };
}

function extractHtmlLinks(root, file, text) {
  const $ = cheerio.load(text, { decodeEntities: false });
  const links = [];
  let cursor = 0;
  const selectors = [
    ["[href]", "href", "navigation"],
    ["[src]", "src", "asset"],
    ["form[action]", "action", "form"]
  ];
  for (const [selector, attribute, kind] of selectors) {
    $(selector).each((_, element) => {
      const value = $(element).attr(attribute) || "";
      const target = normalizeTarget(root, value, file);
      if (!target) return;
      const index = attributeOffset(text, attribute, value, cursor);
      if (index >= 0) cursor = index + value.length;
      links.push({
        sourceFile: file,
        sourceCategory: classifyHtmlFile(root, path.join(root, file)),
        line: lineNumber(text, index),
        value,
        kind,
        ...target,
        ...elementFragmentMetadata($, element)
      });
    });
  }
  return links;
}

function extractResourceLinks(root, file, text) {
  const links = [];
  const patterns = [
    /"(?:ctaLink|canonicalUrl|url)"\s*:\s*"([^"]+)"/giu,
    /<loc>\s*(https?:\/\/[^<]+)\s*<\/loc>/giu
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text))) {
      const target = normalizeTarget(root, match[1], file);
      if (target) links.push({ sourceFile: file, sourceCategory: "public-resource", line: lineNumber(text, match.index), value: match[1], kind: "resource", fragmentType: "anchor", ariaControls: "", ariaHaspopup: "", ...target });
    }
  }
  return links;
}

function extractLinks(root, file, text) {
  return path.extname(file).toLowerCase() === ".html"
    ? extractHtmlLinks(root, file, text)
    : extractResourceLinks(root, file, text);
}

function decodedFragmentId(hash, hasFragmentMarker = false) {
  if (!hash) return hasFragmentMarker ? "" : null;
  try {
    return decodeURIComponent(hash.slice(1));
  } catch {
    return "";
  }
}

function targetData(root, file, cache) {
  if (cache.has(file)) return cache.get(file);
  const full = path.join(root, file);
  if (!fs.existsSync(full) || path.extname(file).toLowerCase() !== ".html") {
    const empty = { ids: new Set(), roles: new Map() };
    cache.set(file, empty);
    return empty;
  }
  const $ = cheerio.load(fs.readFileSync(full, "utf8"), { decodeEntities: false });
  const ids = new Set();
  const roles = new Map();
  $("[id], a[name]").each((_, element) => {
    const id = $(element).attr("id") || $(element).attr("name");
    if (!id) return;
    ids.add(id);
    roles.set(id, $(element).attr("role") || "");
  });
  const data = { ids, roles };
  cache.set(file, data);
  return data;
}

function parseRedirects(root = DEFAULT_ROOT) {
  const redirectsPath = path.join(root, "_redirects");
  if (!fs.existsSync(redirectsPath)) return [];
  return fs.readFileSync(redirectsPath, "utf8").split(/\r?\n/u)
    .map((line, index) => ({ line: index + 1, raw: line.trim() }))
    .filter((entry) => entry.raw && !entry.raw.startsWith("#"))
    .map((entry) => {
      const [from, to, status = "301"] = entry.raw.split(/\s+/u);
      return { ...entry, from, to, status: Number(status) || 301 };
    });
}

function containsDynamicToken(value) {
  return String(value || "").includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/u.test(String(value || ""));
}

function compileRedirectPattern(pattern) {
  const names = [];
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_, name) => {
      names.push(name);
      return "([^/]+)";
    });
  return { regex: new RegExp(`^${escaped}$`), names };
}

function redirectDestination(redirect, pathname) {
  if (redirect.from === pathname) return redirect.to;
  if (!containsDynamicToken(redirect.from)) return "";
  if (!redirect.compiled) redirect.compiled = compileRedirectPattern(redirect.from);
  const match = pathname.match(redirect.compiled.regex);
  if (!match) return "";
  let destination = redirect.to;
  redirect.compiled.names.forEach((name, index) => {
    destination = destination.replace(new RegExp(`:${name}\\b`, "g"), match[index + 1]);
  });
  return destination;
}

function issueKey(issue) {
  return [issue.type, issue.sourceFile, issue.line, issue.value, issue.targetFile, issue.id, issue.reason, issue.from, issue.to].join("|");
}

function dedupe(issues) {
  const seen = new Set();
  return issues.filter((issue) => {
    const key = issueKey(issue);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function auditSiteLinks(options = {}) {
  const root = path.resolve(options.root || DEFAULT_ROOT);
  const files = options.files || trackedFiles(root);
  const links = files.flatMap((file) => extractLinks(root, file, fs.readFileSync(path.join(root, file), "utf8")));
  const redirects = options.redirects || parseRedirects(root);
  const targetCache = new Map();
  const issues = [];
  let interactiveFragmentsChecked = 0;
  let anchorFragmentsChecked = 0;

  for (const link of links) {
    const sourceRoute = new URL(sourceUrlForFile(link.sourceFile)).pathname.replace(/\/$/u, "") || "/";
    const sourceRedirect = redirects.find((rule) => rule.status >= 300 && rule.status < 400 && redirectDestination(rule, sourceRoute));
    if (sourceRedirect) continue;
    if (link.kind === "form" && link.route.startsWith("/api/")) continue;
    const full = path.join(root, link.targetFile);
    if (!fs.existsSync(full)) {
      issues.push({ type: "missing-target", ...link, reason: "target local missing" });
      continue;
    }

    const fragmentOnly = String(link.value).trim().startsWith("#");
    if (!fragmentOnly && (link.kind === "navigation" || link.kind === "form")) {
      const redirect = redirects.find((rule) => rule.status >= 300 && rule.status < 400 && redirectDestination(rule, link.route));
      if (redirect) issues.push({ type: "link-to-redirect", ...link, reason: `route redirects through _redirects:${redirect.line}` });
    }

    if (!link.hasFragmentMarker) continue;
    const id = decodedFragmentId(link.hash, link.hasFragmentMarker);
    const data = targetData(root, link.targetFile, targetCache);
    if (link.fragmentType === "interactive") interactiveFragmentsChecked += 1;
    else anchorFragmentsChecked += 1;

    if (!id) {
      issues.push({ type: link.fragmentType === "interactive" ? "interactive-invalid-fragment" : "invalid-bare-fragment", ...link, id: "", reason: "empty or invalid fragment" });
      continue;
    }
    if (!data.ids.has(id)) {
      issues.push({ type: link.fragmentType === "interactive" ? "interactive-missing-target" : "missing-anchor", ...link, id, reason: "fragment target missing from destination document" });
    }
    if (link.fragmentType === "interactive") {
      if (link.ariaControls && link.ariaControls !== id) issues.push({ type: "interactive-control-mismatch", ...link, id, reason: `aria-controls points to #${link.ariaControls}` });
      if (String(link.ariaHaspopup).toLowerCase() === "dialog" && !link.ariaControls) issues.push({ type: "interactive-dialog-controls", ...link, id, reason: "dialog trigger lacks aria-controls" });
      if (data.ids.has(id) && String(link.ariaHaspopup).toLowerCase() === "dialog" && data.roles.get(id) !== "dialog") {
        issues.push({ type: "interactive-dialog-role", ...link, id, reason: "dialog target lacks role=dialog" });
      }
    }
  }

  for (const redirect of redirects) {
    if (containsDynamicToken(redirect.from) || containsDynamicToken(redirect.to)) continue;
    const target = normalizeTarget(root, redirect.to, "_redirects");
    if (target && !fs.existsSync(path.join(root, target.targetFile))) issues.push({ type: "redirect-missing-target", ...redirect, targetFile: target.targetFile });
  }

  if (options.enforceProgramRoutes !== false) {
    for (const slug of PROGRAM_ROUTES) {
      const cleanRoute = `/${slug}`;
      const fileRoute = `/${slug}.html`;
      const hasCleanRewrite = redirects.some((redirect) => redirect.from === cleanRoute && redirect.to === fileRoute && redirect.status === 200);
      const hasHtmlRedirect = redirects.some((redirect) => redirect.status === 301 && redirectDestination(redirect, fileRoute) && normalizeTarget(root, redirectDestination(redirect, fileRoute), "_redirects")?.route === cleanRoute);
      const hasAsset = fs.existsSync(path.join(root, `${slug}.html`)) || fs.existsSync(path.join(root, slug, "index.html"));
      if (!hasCleanRewrite && !hasAsset) issues.push({ type: "program-route-missing", value: cleanRoute, reason: "canonical program route has no HTML source" });
      if (!hasHtmlRedirect) issues.push({ type: "program-html-redirect-missing", value: fileRoute, reason: `legacy HTML route must redirect to ${cleanRoute}` });
    }
  }

  const uniqueIssues = dedupe(issues);
  const htmlDocuments = files
    .filter((file) => path.extname(file).toLowerCase() === ".html")
    .map((file) => ({ category: classifyHtmlFile(root, path.join(root, file)) }));
  return {
    root,
    files,
    links,
    issues: uniqueIssues,
    interactiveFragmentsChecked,
    anchorFragmentsChecked,
    classification: classificationCounts(htmlDocuments)
  };
}

function printReport(result) {
  console.log("Functional link audit");
  console.log(`Files scanned: ${result.files.length}`);
  console.log(`HTML classification: ${Object.entries(result.classification).map(([key, value]) => `${key}=${value}`).join(", ")}`);
  console.log(`Local links scanned: ${result.links.length}`);
  console.log(`Anchor fragments checked: ${result.anchorFragmentsChecked}`);
  console.log(`Interactive fragments checked: ${result.interactiveFragmentsChecked}`);
  console.log(`Issues: ${result.issues.length}`);
  if (!result.issues.length) return;
  for (const issue of result.issues.slice(0, 80)) {
    console.error(`- [${issue.type}] ${issue.sourceFile || "_redirects"}:${issue.line || "-"} -> ${issue.value || `${issue.from || ""} ${issue.to || ""}`}${issue.reason ? ` (${issue.reason})` : ""}`);
  }
  if (result.issues.length > 80) console.error(`- ...and ${result.issues.length - 80} more`);
}

function main() {
  const rootArgument = process.argv.find((argument) => argument.startsWith("--root="));
  const root = rootArgument ? rootArgument.slice("--root=".length) : DEFAULT_ROOT;
  const result = auditSiteLinks({ root });
  printReport(result);
  if (result.issues.length) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = {
  auditSiteLinks,
  decodedFragmentId,
  extractLinks,
  htmlFileForRoute,
  normalizeTarget,
  parseRedirects,
  redirectDestination,
  trackedFiles
};
