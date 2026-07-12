#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const REPORTS = path.join(ROOT, "reports");
const INTENT_REPORT = path.join(REPORTS, "search-intent-map.csv");
const LINK_REPORT = path.join(REPORTS, "internal-link-map.csv");

const PRIORITY_PATHS = [
  "/",
  "/consultanta-fonduri-europene",
  "/proiectare-fonduri-europene",
  "/studiu-fezabilitate-fonduri-europene",
  "/plan-de-afaceri-fonduri-europene",
  "/management-proiecte-fonduri-europene",
  "/fonduri-europene",
  "/afir",
  "/pnrr",
  "/blog",
  "/resurse-utile"
];

function read(relative) {
  return fs.readFileSync(path.join(ROOT, relative), "utf8");
}

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function normalize(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\b(?:faber|atelier de consultanta)\b/g, " ")
    .replace(/\b20\d{2}\b/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function clusterFor(pathname) {
  if (pathname === "/") return "brand-home";
  if (/consultant|consultanta|proiectare|studiu-fezabilitate|plan-de-afaceri|management-proiecte|eligibilitate/.test(pathname)) return "servicii";
  if (/afir|dr12|dr14|ferme|agricultur|calculator-soc/.test(pathname)) return "afir-agricultura";
  if (/start-up-nation|startup-nation/.test(pathname)) return "start-up-nation";
  if (/digitalizare|pnrr|pocidif/.test(pathname)) return "digitalizare-pnrr";
  if (/modernizare|fotovolta|autoconsum|energie|e-move|pro-infra/.test(pathname)) return "energie";
  if (/gal|leader/.test(pathname)) return "gal-leader";
  if (/regional|nord-est|bucuresti|iasi|bacau|suceava|por-adr/.test(pathname)) return "regional-local";
  if (/despre|metodologie|surse-oficiale|resurse-utile|studii-de-caz|glosar/.test(pathname)) return "incredere-resurse";
  if (/gdpr|confidentialitate|termeni/.test(pathname)) return "legal";
  return "fonduri-europene-editorial";
}

function kindFor(pathname) {
  if (/consultant|consultanta|proiectare|studiu-fezabilitate|plan-de-afaceri|management-proiecte|verificare-eligibilitate/.test(pathname)) return "commercial";
  if (/blog|cum-|ce-|greseli|intrebari\//.test(pathname)) return "article";
  return "hub";
}

function fileFor(pathname) {
  const clean = pathname === "/" ? "" : pathname.replace(/^\/+|\/+$/g, "");
  const candidates = clean ? [`${clean}/index.html`, `${clean}.html`] : ["index.html"];
  return candidates.find((file) => fs.existsSync(path.join(ROOT, file))) || null;
}

function canonicalHref($) {
  const values = [];
  $("link[rel]").each((_, element) => {
    const rel = String($(element).attr("rel") || "").toLowerCase().split(/\s+/);
    if (rel.includes("canonical")) values.push(String($(element).attr("href") || "").trim());
  });
  return values[0] || "";
}

function internalPath(raw) {
  if (!raw || raw.startsWith("#") || /^(?:mailto:|tel:|javascript:)/i.test(raw)) return null;
  try {
    const url = new URL(raw, SITE);
    if (url.origin !== SITE) return null;
    return url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

const sitemapUrls = [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].trim());
const pages = [];
const outbound = new Map();

for (const url of sitemapUrls) {
  const pathname = new URL(url).pathname;
  const normalizedPath = pathname === "/" ? "/" : pathname.replace(/\/+$/, "");
  const file = fileFor(pathname);
  if (!file) continue;
  const $ = cheerio.load(read(file));
  const title = $("title").first().text().trim();
  const description = $('meta[name="description"]').first().attr("content")?.trim() || "";
  const h1 = $("h1").first().text().replace(/\s+/g, " ").trim();
  const firstH2 = $("h2").first().text().replace(/\s+/g, " ").trim();
  const canonical = canonicalHref($);
  const cluster = clusterFor(normalizedPath);
  const primaryIntent = normalize(h1 || title);
  pages.push({
    url,
    pathname: normalizedPath,
    file,
    title,
    description,
    h1,
    firstH2,
    canonical,
    cluster,
    primaryIntent,
    kind: kindFor(normalizedPath),
    indexable: true,
    status: "200"
  });
  const links = [];
  $("a[href]").each((_, element) => {
    const raw = String($(element).attr("href") || "").trim();
    const target = internalPath(raw);
    if (!target) return;
    links.push({
      target,
      anchor: $(element).text().replace(/\s+/g, " ").trim(),
      breadcrumb: $(element).closest(".breadcrumb, [aria-label*='breadcrumb' i]").length > 0
    });
  });
  outbound.set(normalizedPath, links);
}

fs.mkdirSync(REPORTS, { recursive: true });
const intentHeader = ["url", "title", "h1", "primary_intent", "cluster", "indexable", "canonical", "status"];
const intentRows = pages.map((page) => [page.url, page.title, page.h1, page.primaryIntent, page.cluster, "true", page.canonical, page.status]);
fs.writeFileSync(INTENT_REPORT, [intentHeader, ...intentRows].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");

const errors = [];
function duplicates(key, label, scope = () => "global") {
  const seen = new Map();
  for (const page of pages) {
    const value = normalize(page[key]);
    if (!value) {
      errors.push(`${page.pathname}: ${label} lipsă`);
      continue;
    }
    const compound = `${scope(page)}::${value}`;
    if (!seen.has(compound)) seen.set(compound, []);
    seen.get(compound).push(page);
  }
  for (const group of seen.values()) {
    if (group.length > 1) errors.push(`${label} duplicat: ${group.map((page) => page.pathname).join(", ")}`);
  }
}

duplicates("title", "title");
duplicates("description", "meta description");
duplicates("h1", "H1", (page) => page.cluster);

const intentGroups = new Map();
for (const page of pages) {
  const key = `${page.cluster}::${page.primaryIntent}`;
  if (!intentGroups.has(key)) intentGroups.set(key, []);
  intentGroups.get(key).push(page);
}
for (const group of intentGroups.values()) {
  if (group.length < 2) continue;
  errors.push(`intenție primară duplicată în cluster: ${group.map((page) => `${page.pathname} (${page.kind})`).join(", ")}`);
}

for (const page of pages) {
  if (/^fonduri europene(?: \|)?$/i.test(page.title.replace(/\bFABER\b/gi, "").trim())) {
    errors.push(`${page.pathname}: title generic neacceptat`);
  }
  if (!page.firstH2) errors.push(`${page.pathname}: primul H2 lipsește`);
}

const linkHeader = ["target_url", "inbound_links", "unique_sources", "contextual_links", "has_breadcrumb", "links_to_service", "links_to_methodology_or_sources", "status"];
const linkRows = [];
for (const target of PRIORITY_PATHS) {
  const targetPage = pages.find((page) => page.pathname === target);
  if (!targetPage) {
    errors.push(`${target}: pagina prioritară nu este în sitemap`);
    continue;
  }
  const inboundSources = [];
  for (const [source, links] of outbound) {
    if (source === target) continue;
    if (links.some((link) => link.target === target)) inboundSources.push(source);
  }
  const ownLinks = outbound.get(target) || [];
  const uniqueOwnTargets = new Set(ownLinks.filter((link) => link.target !== target).map((link) => link.target));
  const hasBreadcrumb = target === "/" || targetPage.file === "index.html" || /breadcrumb|BreadcrumbList/i.test(read(targetPage.file));
  const linksToService = ownLinks.some((link) => ["/consultanta-fonduri-europene", "/proiectare-fonduri-europene"].includes(link.target));
  const linksToSources = ownLinks.some((link) => ["/metodologie-verificare-eligibilitate", "/surse-oficiale-fonduri-europene", "/resurse-utile"].includes(link.target));
  const status = inboundSources.length >= 5 && uniqueOwnTargets.size >= 3 && hasBreadcrumb && linksToService && linksToSources ? "PASS" : "FAIL";
  linkRows.push([`${SITE}${target}`, inboundSources.length, new Set(inboundSources).size, uniqueOwnTargets.size, hasBreadcrumb, linksToService, linksToSources, status]);
  if (status === "FAIL") {
    errors.push(`${target}: linking insuficient (inbound=${inboundSources.length}, own=${uniqueOwnTargets.size}, breadcrumb=${hasBreadcrumb}, service=${linksToService}, sources=${linksToSources})`);
  }
}
fs.writeFileSync(LINK_REPORT, [linkHeader, ...linkRows].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");

const uniqueErrors = [...new Set(errors)];
if (uniqueErrors.length) {
  console.error(`Search intent audit failed with ${uniqueErrors.length} error(s):`);
  for (const error of uniqueErrors) console.error(`- ${error}`);
  console.error(`Reports written: ${path.relative(ROOT, INTENT_REPORT)}, ${path.relative(ROOT, LINK_REPORT)}`);
  process.exit(1);
}

console.log(`Search intent PASS: ${pages.length} pages; internal-link matrix PASS for ${linkRows.length} priority pages.`);
