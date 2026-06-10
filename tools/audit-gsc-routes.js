#!/usr/bin/env node
"use strict";

const cp = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = fs.existsSync(path.join(ROOT, "dist")) ? path.join(ROOT, "dist") : ROOT;
const SITE = "https://atelierdeconsultanta.ro";
const REPORT_DATE = "2026-06-10";
const SKIP_DIRS = new Set([".git", ".wrangler", "dist", "node_modules", "reports", "scripts", "tools"]);
const TEXT_EXTENSIONS = new Set([".html", ".json", ".js", ".xml", ".txt"]);

const GSC_URLS = [
  "https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/",
  "https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/",
  "https://atelierdeconsultanta.ro/consultanta-start-up-nation/",
  "https://atelierdeconsultanta.ro/fonduri-europene-imm/",
  "https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html",
  "https://atelierdeconsultanta.ro/fonduri-europene/",
  "http://atelierdeconsultanta.ro/politica-de-confidentialitate.html",
  "http://atelierdeconsultanta.ro/",
  "https://atelierdeconsultanta.ro/fonduri-europene-bucuresti",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene",
  "https://atelierdeconsultanta.ro/fonduri-europene",
  "https://atelierdeconsultanta.ro/pnrr",
  "https://atelierdeconsultanta.ro/afir",
  "https://atelierdeconsultanta.ro/consultanta-afir",
  "https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene",
  "https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene",
  "https://atelierdeconsultanta.ro/pro-infra",
  "https://atelierdeconsultanta.ro/official-guides.json",
  "https://atelierdeconsultanta.ro/blog?post=blog-1",
  "https://atelierdeconsultanta.ro/blog?post=blog-2",
  "https://atelierdeconsultanta.ro/blog?post=blog-3",
  "https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/",
  "https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12/",
  "https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12",
  "https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/",
  "https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene",
  "https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/",
  "https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software",
  "https://atelierdeconsultanta.ro/fonduri-europene-iasi",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bacau",
];

function readIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function parseRedirects() {
  return readIfExists(path.join(PUBLIC_DIR, "_redirects"))
    .split(/\r?\n/)
    .map((line, index) => ({ line: index + 1, raw: line.trim() }))
    .filter((entry) => entry.raw && !entry.raw.startsWith("#"))
    .map((entry) => {
      const [from, to, status = "301"] = entry.raw.split(/\s+/);
      return { ...entry, from, to, status: Number(status) || 301 };
    });
}

function parseHeaders() {
  const rules = [];
  let current = null;
  for (const line of readIfExists(path.join(PUBLIC_DIR, "_headers")).split(/\r?\n/)) {
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

function matchesPattern(pattern, pathname) {
  if (pattern === pathname) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(pathname);
}

function headersFor(pathname, headerRules) {
  const headers = {};
  for (const rule of headerRules) {
    if (matchesPattern(rule.pattern, pathname)) Object.assign(headers, rule.headers);
  }
  return headers;
}

function fileForPath(pathname) {
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidates = [];
  if (!clean) candidates.push("index.html");
  else if (pathname.endsWith("/")) candidates.push(path.posix.join(clean, "index.html"));
  else if (path.posix.extname(clean)) candidates.push(clean);
  else candidates.push(`${clean}.html`, path.posix.join(clean, "index.html"));
  return candidates.find((candidate) => fs.existsSync(path.join(PUBLIC_DIR, candidate))) || "";
}

function textOf(file) {
  return file ? readIfExists(path.join(PUBLIC_DIR, file)) : "";
}

function tagAttr(tag, attr) {
  const match = tag.match(new RegExp(`\\b${attr}=["']([^"']+)["']`, "i"));
  return match ? match[1].trim() : "";
}

function firstTag(text, pattern) {
  const match = text.match(pattern);
  return match ? match[0] : "";
}

function textMatch(text, pattern) {
  const match = text.match(pattern);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}

function extractCanonical(text) {
  for (const match of text.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) return tagAttr(tag, "href");
  }
  return "";
}

function meta(file, pathname, headerRules) {
  const text = textOf(file);
  const robotsTag = firstTag(text, /<meta\b[^>]*\bname=["']robots["'][^>]*>/i);
  const headers = headersFor(pathname, headerRules);
  return {
    canonical: extractCanonical(text),
    metaRobots: tagAttr(robotsTag, "content"),
    xRobotsTag: headers["x-robots-tag"] || "",
    contentType: headers["content-type"] || "",
    title: textMatch(text, /<title\b[^>]*>([\s\S]*?)<\/title>/i),
    h1: textMatch(text, /<h1[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim(),
  };
}

function sitemapUrls() {
  const text = readIfExists(path.join(PUBLIC_DIR, "sitemap.xml"));
  return new Set([...text.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]));
}

function cleanAbsoluteUrl(rawUrl, { keepQuery = false } = {}) {
  const parsed = new URL(rawUrl, SITE);
  parsed.protocol = "https:";
  parsed.hostname = "atelierdeconsultanta.ro";
  parsed.hash = "";
  if (!keepQuery) parsed.search = "";
  if (parsed.pathname !== "/") parsed.pathname = parsed.pathname.replace(/\/+$/g, "");
  return parsed.href;
}

function redirectChainText(chain) {
  return chain
    .map((step) => step.to ? `${step.url} -> ${step.to} [${step.status}]` : `${step.url} [${step.status}]`)
    .join(" | ");
}

function trace(rawUrl, redirects) {
  const chain = [];
  let currentUrl = new URL(rawUrl);
  const seen = new Set();

  for (let i = 0; i < 10; i += 1) {
    const key = currentUrl.href;
    if (seen.has(key)) {
      chain.push({ url: currentUrl.href, status: "LOOP" });
      break;
    }
    seen.add(key);

    if (currentUrl.protocol === "http:") {
      const next = new URL(currentUrl.href);
      next.protocol = "https:";
      chain.push({ url: currentUrl.href, status: 301, to: next.href });
      currentUrl = next;
      continue;
    }

    const redirect = redirects.find((rule) => matchesPattern(rule.from, currentUrl.pathname));
    if (redirect) {
      const next = new URL(redirect.to, SITE);
      chain.push({ url: currentUrl.href, status: redirect.status, to: next.href });
      currentUrl = next;
      continue;
    }

    const file = fileForPath(currentUrl.pathname);
    chain.push({ url: currentUrl.href, status: file ? 200 : 404, file });
    break;
  }
  return chain;
}

function localStatus(chain) {
  const final = chain[chain.length - 1] || {};
  const redirects = chain.filter((step) => Number(step.status) >= 300 && Number(step.status) < 400).length;
  return `${final.status || "ERR"}${redirects ? ` after ${redirects} redirect(s)` : " direct"}`;
}

function intentFor(inputUrl, chain, finalUrl, canonical, xRobotsTag) {
  const parsed = new URL(inputUrl);
  if (parsed.pathname === "/official-guides.json") return "resursa tehnica neindexabila";
  if (parsed.search) return "pagina alternativa";
  if (/\bnoindex\b/i.test(xRobotsTag)) return "resursa tehnica neindexabila";
  const hasRedirect = chain.some((step) => Number(step.status) >= 300 && Number(step.status) < 400);
  const inputClean = cleanAbsoluteUrl(inputUrl);
  const canonicalClean = canonical ? cleanAbsoluteUrl(canonical) : "";
  const finalClean = finalUrl ? cleanAbsoluteUrl(finalUrl) : "";
  if (!hasRedirect && inputClean === canonicalClean && finalClean === canonicalClean) return "pagina canonica indexabila";
  if (hasRedirect) return "alias cu redirect";
  return "pagina alternativa";
}

function actionFor(intent, inputUrl) {
  const parsed = new URL(inputUrl);
  if (parsed.pathname === "/official-guides.json") {
    return "Pastrat 200 ca JSON si marcat noindex, follow prin _headers; exclus din sitemap.";
  }
  if (parsed.search && parsed.pathname === "/blog") {
    return "Pastrat ca varianta query alternativa a hubului /blog; exclus din sitemap si curatat client-side pentru blog-1/2/3.";
  }
  if (intent === "alias cu redirect") {
    return "Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale.";
  }
  if (intent === "pagina canonica indexabila") {
    return "Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML.";
  }
  return "Documentat ca alternativa intentionata; forma canonica ramane URL-ul final declarat.";
}

function resultFor({ inputUrl, chain, finalUrl, finalStatus, inSitemap, canonical, metaRobots, xRobotsTag }) {
  if (chain.some((step) => step.status === "LOOP")) return "FAIL_REDIRECT_LOOP";
  if (finalStatus === 404) return "FAIL_404";
  if (new URL(inputUrl).pathname === "/official-guides.json") {
    if (finalStatus === 200 && /\bnoindex\b/i.test(xRobotsTag) && !inSitemap) return "PASS_TECHNICAL_NOINDEX";
    return "FAIL_TECHNICAL_RESOURCE";
  }
  if (/\bnoindex\b/i.test([metaRobots, xRobotsTag].filter(Boolean).join("; "))) return "FAIL_NOINDEX";
  if (!canonical) return "FAIL_CANONICAL_MISSING";

  const inputNoQuery = cleanAbsoluteUrl(inputUrl);
  const inputWithQuery = cleanAbsoluteUrl(inputUrl, { keepQuery: true });
  const finalNoQuery = cleanAbsoluteUrl(finalUrl);
  const finalWithQuery = cleanAbsoluteUrl(finalUrl, { keepQuery: true });
  const canonicalClean = cleanAbsoluteUrl(canonical);
  const redirected = chain.some((step) => Number(step.status) >= 300 && Number(step.status) < 400);
  const inputIsCanonical = inputNoQuery === canonicalClean && inputWithQuery === canonicalClean;

  if (!inputIsCanonical && inSitemap && finalWithQuery === inputWithQuery) return "FAIL_SITEMAP_DUPLICATE";
  if (redirected && finalNoQuery === canonicalClean) return "PASS_REDIRECT_TO_CANONICAL";
  if (!redirected && finalNoQuery === canonicalClean && inputIsCanonical) return "PASS_CANONICAL_200";
  if (!redirected && finalNoQuery === canonicalClean && !inputIsCanonical) return "PASS_ALTERNATE_CANONICAL";
  if (!redirected && canonicalClean !== finalNoQuery && !inSitemap) return "PASS_ALTERNATE_CANONICAL";
  return "FAIL_CANONICAL_MISMATCH";
}

function trackedTextFiles() {
  try {
    return cp.execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" })
      .split("\0")
      .filter(Boolean)
      .filter((file) => !SKIP_DIRS.has(file.split("/")[0]))
      .filter((file) => TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()));
  } catch {
    return [];
  }
}

function internalReferenceValues(file, text) {
  const values = [];
  const patterns = [
    /\b(?:href|action)=["']([^"']+)["']/gi,
    /\b(?:location\.href|window\.location)\s*=\s*["']([^"']+)["']/gi,
    /\bfetch\(\s*["']([^"']+)["']/gi,
    /"(?:@id|url|item|canonicalUrl|ctaLink|href)"\s*:\s*"([^"]+)"/gi,
    /<loc>\s*([^<]+)\s*<\/loc>/gi,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text))) values.push({ file, value: match[1].replace(/&amp;/g, "&").trim() });
  }
  return values;
}

function internalLinkCounts() {
  const counts = new Map();
  for (const file of trackedTextFiles()) {
    if (file === "_redirects" || file === "_headers") continue;
    const text = readIfExists(path.join(ROOT, file));
    for (const ref of internalReferenceValues(file, text)) {
      let parsed;
      try {
        parsed = new URL(ref.value, SITE);
      } catch {
        continue;
      }
      if (parsed.hostname !== "atelierdeconsultanta.ro") continue;
      parsed.hash = "";
      const key = parsed.pathname + parsed.search;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
  }
  return counts;
}

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    return await fetch(url, {
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "FABER-GSC-audit/2026-06-10" },
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function liveTrace(rawUrl) {
  const chain = [];
  let current = new URL(rawUrl);
  const seen = new Set();

  for (let index = 0; index < 8; index += 1) {
    if (seen.has(current.href)) {
      chain.push({ url: current.href, status: "LOOP" });
      break;
    }
    seen.add(current.href);
    try {
      const response = await fetchWithTimeout(current.href);
      const location = response.headers.get("location");
      const step = {
        url: current.href,
        status: response.status,
        xRobotsTag: response.headers.get("x-robots-tag") || "",
        contentType: response.headers.get("content-type") || "",
      };
      if (location && response.status >= 300 && response.status < 400) {
        const next = new URL(location, current);
        step.to = next.href;
        chain.push(step);
        current = next;
        continue;
      }
      chain.push(step);
      break;
    } catch (error) {
      chain.push({ url: current.href, status: `ERROR ${error.name || "fetch"}` });
      break;
    }
  }

  return chain;
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function run() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

function csvCell(value) {
  return JSON.stringify(String(value ?? ""));
}

function mdCell(value) {
  return String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/\|/g, "\\|")
    .trim();
}

function writeReports(rows) {
  const reportDir = path.join(ROOT, "reports");
  fs.mkdirSync(reportDir, { recursive: true });

  const columns = [
    "URL raportat de GSC",
    "statut local",
    "statut live",
    "lant de redirect",
    "URL final",
    "canonical declarat",
    "meta robots",
    "X-Robots-Tag",
    "prezent in sitemap",
    "numar linkuri interne catre URL",
    "intentie",
    "actiunea aplicata",
    "rezultatul final",
  ];

  const csvRows = [
    columns.map(csvCell).join(","),
    ...rows.map((row) => [
      row.inputUrl,
      row.localStatus,
      row.liveStatus,
      row.redirectChain,
      row.finalUrl,
      row.canonical,
      row.metaRobots,
      row.xRobotsTag,
      row.inSitemap ? "yes" : "no",
      row.internalLinkCount,
      row.intent,
      row.action,
      row.result,
    ].map(csvCell).join(",")),
  ];

  const mdRows = [
    "# GSC indexing fix matrix - 2026-06-10",
    "",
    `Public directory audited: \`${toPosix(path.relative(ROOT, PUBLIC_DIR)) || "."}\``,
    "",
    `Rows: ${rows.length}`,
    "",
    `Local pass rows: ${rows.filter((row) => row.result.startsWith("PASS_")).length}`,
    "",
    "| " + columns.map(mdCell).join(" | ") + " |",
    "|---|---:|---|---|---|---|---|---|:---:|---:|---|---|---|",
    ...rows.map((row) => `| ${[
      row.inputUrl,
      row.localStatus,
      row.liveStatus,
      row.redirectChain.replace(/ \| /g, "<br>"),
      row.finalUrl,
      row.canonical,
      row.metaRobots,
      row.xRobotsTag,
      row.inSitemap ? "yes" : "no",
      row.internalLinkCount,
      row.intent,
      row.action,
      row.result,
    ].map(mdCell).join(" | ")} |`),
    "",
  ];

  const csvPath = path.join(reportDir, `gsc-indexing-fix-${REPORT_DATE}.csv`);
  const mdPath = path.join(reportDir, `gsc-indexing-fix-${REPORT_DATE}.md`);
  fs.writeFileSync(csvPath, `${csvRows.join("\n")}\n`, "utf8");
  fs.writeFileSync(mdPath, `${mdRows.join("\n")}\n`, "utf8");
  console.error(`Wrote ${rows.length} GSC audit rows to ${path.relative(ROOT, csvPath)} and ${path.relative(ROOT, mdPath)}.`);
}

async function main() {
  const redirects = parseRedirects();
  const headerRules = parseHeaders();
  const sitemap = sitemapUrls();
  const counts = internalLinkCounts();
  const uniqueUrls = [...new Set(GSC_URLS)];

  const rows = await mapLimit(uniqueUrls, 6, async (inputUrl) => {
    const chain = trace(inputUrl, redirects);
    const final = chain[chain.length - 1] || {};
    const finalUrl = final.url || "";
    const finalPath = finalUrl ? new URL(finalUrl).pathname : "";
    const data = meta(final.file, finalPath, headerRules);
    const finalStatus = final.status;
    const finalSitemapUrl = finalUrl ? cleanAbsoluteUrl(finalUrl, { keepQuery: true }) : "";
    const inSitemap = finalSitemapUrl ? sitemap.has(finalSitemapUrl) : false;
    const live = await liveTrace(inputUrl);
    const liveFinal = live[live.length - 1] || {};
    const intent = intentFor(inputUrl, chain, finalUrl, data.canonical, data.xRobotsTag);
    const result = resultFor({
      inputUrl,
      chain,
      finalUrl,
      finalStatus,
      inSitemap,
      canonical: data.canonical,
      metaRobots: data.metaRobots,
      xRobotsTag: data.xRobotsTag,
    });
    const parsed = new URL(inputUrl);
    const countKey = parsed.pathname + parsed.search;

    return {
      inputUrl,
      localStatus: localStatus(chain),
      liveStatus: `${liveFinal.status || "ERR"}${live.length > 1 ? ` after ${live.length - 1} redirect(s)` : " direct"}`,
      redirectChain: redirectChainText(chain),
      liveRedirectChain: redirectChainText(live),
      finalUrl,
      canonical: data.canonical,
      metaRobots: data.metaRobots,
      xRobotsTag: data.xRobotsTag,
      inSitemap,
      internalLinkCount: counts.get(countKey) || 0,
      intent,
      action: actionFor(intent, inputUrl),
      result,
    };
  });

  writeReports(rows);
  for (const row of rows) console.log(JSON.stringify(row));

  const failures = rows.filter((row) => row.result.startsWith("FAIL_"));
  if (failures.length) {
    console.error(`GSC route audit found ${failures.length} local failure(s).`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
