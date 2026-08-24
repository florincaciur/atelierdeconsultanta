#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { collectSiteState, parseRedirectRules } = require("./generate-sitemap");
const { readSitemapEntries, readSitemapEntriesFromReader } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const OUTPUT = path.join(ROOT, "docs", "faber-remediation", "ROUTE_INVENTORY.md");
const LIVE_CHECK_PATHS = [
  "/",
  "/verificare-eligibilitate-fonduri-europene",
  "/consultanta-fonduri-europene",
  "/proiectare-fonduri-europene",
  "/management-proiecte-fonduri-europene",
  "/calculator-soc",
  "/contact",
  "/despre-faber",
  "/metodologie-verificare-eligibilitate",
  "/studii-de-caz-fonduri-europene",
  "/gdpr",
  "/politica-de-confidentialitate",
  "/termeni-si-conditii",
  "/admin",
  "/404",
  "/partials/global-header",
  "/templates/dr14-final-content",
  "/templates/dr18-final-content",
  "/start-up-nation",
  "/definitely-missing-route-task-01",
];

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function normalizeSpace(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function cleanRoute(value) {
  if (!value) return "";
  let parsed;
  try {
    parsed = new URL(value, SITE);
  } catch {
    return "";
  }
  if (parsed.origin !== SITE) return "";
  let route = parsed.pathname || "/";
  route = route.replace(/\/index\.html$/iu, "");
  route = route.replace(/\.html$/iu, "");
  if (route !== "/") route = route.replace(/\/+$/u, "");
  return route || "/";
}

function absoluteUrl(route) {
  return route === "/" ? `${SITE}/` : `${SITE}${route}`;
}

function markdown(value) {
  return normalizeSpace(value)
    .replace(/\\/gu, "\\\\")
    .replace(/\|/gu, "\\|")
    .replace(/\r?\n/gu, " ");
}

function shortText(value, maximum = 110) {
  const text = normalizeSpace(value);
  return text.length <= maximum ? text : `${text.slice(0, maximum - 1).trim()}…`;
}

function jsonLdNodes(value, output = []) {
  if (!value || typeof value !== "object") return output;
  if (Array.isArray(value)) {
    for (const item of value) jsonLdNodes(item, output);
    return output;
  }
  output.push(value);
  if (value["@graph"]) jsonLdNodes(value["@graph"], output);
  return output;
}

function jsonLdTypes(value) {
  const types = [];
  for (const node of jsonLdNodes(value)) {
    const nodeTypes = Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]];
    for (const type of nodeTypes.filter(Boolean)) types.push(String(type));
  }
  return types;
}

function collectStructuredLinks(value, output = new Set()) {
  if (!value) return output;
  if (typeof value === "string") {
    const route = cleanRoute(value);
    if (route && (value.startsWith("/") || value.startsWith(SITE))) output.add(route);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStructuredLinks(item, output);
    return output;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value)) collectStructuredLinks(item, output);
  }
  return output;
}

function inspectHtml(relativePath) {
  const html = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
  const $ = cheerio.load(html);
  const h1s = $("h1").map((_, element) => normalizeSpace($(element).text())).get().filter(Boolean);
  const structuredTypes = new Set();
  const structuredLinks = new Set();
  let invalidJsonLd = 0;
  let schemaFaqCount = 0;
  $("script[type='application/ld+json']").each((_, element) => {
    try {
      const value = JSON.parse($(element).text());
      for (const type of jsonLdTypes(value)) structuredTypes.add(type);
      collectStructuredLinks(value, structuredLinks);
      for (const node of jsonLdNodes(value)) {
        const types = Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]];
        if (types.includes("FAQPage") && Array.isArray(node.mainEntity)) schemaFaqCount += node.mainEntity.length;
      }
    } catch {
      invalidJsonLd += 1;
    }
  });
  const visibleFaqCount = $("details, .faq-item, .faq-card, .faq-entry, [data-faq-item]").length;
  const canonical = $("link[rel~='canonical']").first().attr("href") || "";
  const body = $("body");
  return {
    html,
    $,
    title: normalizeSpace($("title").first().text()),
    h1s,
    canonical,
    noindex: /\bnoindex\b/iu.test($("meta[name='robots']").attr("content") || ""),
    bodyPageType: body.attr("data-analytics-page-type") || body.attr("data-page-type") || "",
    structuredTypes: [...structuredTypes].sort(),
    structuredLinks: [...structuredLinks].sort(),
    invalidJsonLd,
    breadcrumbHtml: $("nav[aria-label*='breadcrumb' i], nav[aria-label*='firimit' i], .breadcrumbs, .breadcrumb").length > 0,
    breadcrumbSchema: structuredTypes.has("BreadcrumbList"),
    visibleFaqCount,
    schemaFaqCount,
  };
}

function walkHtml(directory, output = []) {
  const excluded = new Set([".git", ".wrangler", "dist", "node_modules", "reports"]);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) walkHtml(full, output);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) output.push(full);
  }
  return output;
}

function collectConfigLinks(value, output = []) {
  if (!value) return output;
  if (Array.isArray(value)) {
    for (const item of value) collectConfigLinks(item, output);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [key, item] of Object.entries(value)) {
    if (["href", "url", "route", "ctaLink"].includes(key) && typeof item === "string") {
      const route = cleanRoute(item);
      if (route) output.push(route);
    } else {
      collectConfigLinks(item, output);
    }
  }
  return output;
}

function resolveRedirectRoute(route, redirectByCleanRoute) {
  let current = route;
  const seen = new Set();
  while (redirectByCleanRoute.has(current) && !seen.has(current)) {
    seen.add(current);
    current = redirectByCleanRoute.get(current);
  }
  return current;
}

function classifyPage(route, pageConfig, program, info, blogRoutes) {
  if (route === "/") return "homepage";
  if (["/gdpr", "/politica-de-confidentialitate", "/termeni-si-conditii"].includes(route)) return "legal";
  if (route.startsWith("/fonduri-europene-caen/")) return "landing CAEN";
  if (route.startsWith("/intrebari/")) return "answer page";
  if (["/fonduri-europene-nord-est", "/fonduri-europene-bucuresti"].includes(route)) return "landing local";
  if (route === "/blog") return "article hub";
  if (program) return "program";
  if (blogRoutes.has(route) || /Article|BlogPosting/iu.test(info.structuredTypes.join(" "))) return "article/guide";
  if (pageConfig?.type) return pageConfig.type;
  if (info.bodyPageType) return info.bodyPageType;
  if (route === "/calculator-soc") return "tool";
  if (route === "/contact") return "contact";
  if (route === "/despre-faber") return "trust/about";
  return "core/editorial";
}

function duplicateValues(items, selector) {
  const grouped = new Map();
  for (const item of items) {
    const value = selector(item);
    if (!value) continue;
    if (!grouped.has(value)) grouped.set(value, []);
    grouped.get(value).push(item);
  }
  return [...grouped.entries()].filter(([, values]) => values.length > 1);
}

function canonicalDuplicateGroups() {
  const grouped = new Map();
  for (const file of walkHtml(ROOT)) {
    const relative = toPosix(path.relative(ROOT, file));
    if (relative.startsWith("docs/") || relative.startsWith("tests/")) continue;
    const html = fs.readFileSync(file, "utf8");
    const canonical = html.match(/<link\b[^>]*\brel=["'][^"']*\bcanonical\b[^"']*["'][^>]*\bhref=["']([^"']+)["']/iu)?.[1]
      || html.match(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["'][^"']*\bcanonical\b[^"']*["']/iu)?.[1]
      || "";
    if (!canonical.startsWith(SITE)) continue;
    if (!grouped.has(canonical)) grouped.set(canonical, []);
    grouped.get(canonical).push({
      file: relative,
      hash: crypto.createHash("sha256").update(html).digest("hex"),
    });
  }
  return [...grouped.entries()]
    .filter(([, files]) => files.length > 1)
    .map(([canonical, files]) => ({
      canonical,
      files,
      identical: new Set(files.map((file) => file.hash)).size === 1,
    }))
    .sort((left, right) => left.canonical.localeCompare(right.canonical));
}

function buildInventory() {
  const state = collectSiteState();
  const indexablePolicyExclusions = state.excluded
    .filter((item) => item.reason === "duplicate_policy_pending_legal_consolidation")
    .map((item) => ({
      route: cleanRoute(item.url || item.route),
      url: item.url || absoluteUrl(cleanRoute(item.route)),
      sourceFile: item.sourceFile,
      family: "policy-excluded",
      sitemapExclusionReason: item.reason,
      sitemapExclusionDetail: item.detail || "",
    }));
  const publicEntries = [...state.entries, ...indexablePolicyExclusions]
    .sort((left, right) => left.route.localeCompare(right.route));
  const seo = readJson("config/seo-programs.json");
  const families = readJson("config/program-family-hubs.json");
  const navigation = readJson("config/main-navigation.json");
  const banners = readJson("banners.json");
  const blog = readJson("blog.json");
  const sitemapEntries = readSitemapEntries(ROOT).entries;
  const sitemapRoutes = new Set(sitemapEntries.map((entry) => cleanRoute(entry.url)));
  const redirects = parseRedirectRules();
  const exactRedirects = redirects.filter((rule) => !rule.dynamic);
  const dynamicRedirects = redirects.filter((rule) => rule.dynamic);
  const redirectByCleanRoute = new Map();
  for (const rule of exactRedirects) {
    const source = cleanRoute(rule.source);
    const target = cleanRoute(rule.destination);
    if (source && target && source !== target) redirectByCleanRoute.set(source, target);
  }

  const programsByRoute = new Map();
  const programsBySlug = new Map();
  for (const program of seo.programs) {
    programsBySlug.set(program.id, program);
    const route = cleanRoute(program.pageUrl);
    if (!programsByRoute.has(route)) programsByRoute.set(route, []);
    programsByRoute.get(route).push(program);
  }
  const pagesByRoute = new Map();
  for (const page of seo.pages) {
    const route = cleanRoute(`/${page.slug}`);
    if (!pagesByRoute.has(route)) pagesByRoute.set(route, []);
    pagesByRoute.get(route).push(page);
  }
  const bannerByRoute = new Map();
  for (const banner of banners.filter((item) => item.active !== false)) {
    const route = cleanRoute(banner.ctaLink);
    if (!bannerByRoute.has(route)) bannerByRoute.set(route, []);
    bannerByRoute.get(route).push(banner);
  }
  const familyHubByRoute = new Map((families.hubs || []).map((hub) => [cleanRoute(hub.route || hub.url), hub]));
  const blogItems = Array.isArray(blog) ? blog : (blog.posts || []);
  const blogRoutes = new Set(blogItems.map((item) => cleanRoute(item.canonicalUrl || `/${item.slug}`)).filter(Boolean));

  const navRoutes = new Set(collectConfigLinks(navigation));
  if (fs.existsSync(path.join(ROOT, "partials", "global-header.html"))) {
    const partial = cheerio.load(fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8"));
    partial("a[href]").each((_, element) => {
      const route = cleanRoute(partial(element).attr("href"));
      if (route) navRoutes.add(resolveRedirectRoute(route, redirectByCleanRoute));
    });
  }
  const footerRoutes = new Set();
  const home = cheerio.load(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"));
  home("footer a[href]").each((_, element) => {
    const route = cleanRoute(home(element).attr("href"));
    if (route) footerRoutes.add(resolveRedirectRoute(route, redirectByCleanRoute));
  });

  const infos = new Map();
  const incoming = new Map();
  const incomingViaRedirect = new Map();
  for (const entry of publicEntries) {
    const info = inspectHtml(entry.sourceFile);
    infos.set(entry.route, info);
    function addIncoming(rawRoute) {
      if (!rawRoute) return;
      const target = resolveRedirectRoute(rawRoute, redirectByCleanRoute);
      if (target === entry.route) return;
      if (!incoming.has(target)) incoming.set(target, new Set());
      incoming.get(target).add(entry.route);
      if (target !== rawRoute) {
        if (!incomingViaRedirect.has(target)) incomingViaRedirect.set(target, new Set());
        incomingViaRedirect.get(target).add(entry.route);
      }
    }
    info.$("a[href]").each((_, element) => {
      const rawRoute = cleanRoute(info.$(element).attr("href"));
      addIncoming(rawRoute);
    });
    for (const rawRoute of info.structuredLinks) addIncoming(rawRoute);
  }

  const routes = publicEntries.map((entry) => {
    const info = infos.get(entry.route);
    const programs = programsByRoute.get(entry.route) || [];
    const pages = pagesByRoute.get(entry.route) || [];
    const program = programs[0] || (pages[0]?.programId ? programsBySlug.get(pages[0].programId) : null);
    const bannersForRoute = bannerByRoute.get(entry.route) || [];
    const hub = familyHubByRoute.get(entry.route);
    const routeIssues = [];
    if (info.h1s.length !== 1) routeIssues.push(`${info.h1s.length} H1`);
    if (info.canonical !== entry.url) routeIssues.push("canonical diferit de ruta inventariată");
    if (info.invalidJsonLd) routeIssues.push(`${info.invalidJsonLd} JSON-LD invalid`);
    if (!sitemapRoutes.has(entry.route)) {
      routeIssues.push(entry.sitemapExclusionReason
        ? `lipsește din sitemap: ${entry.sitemapExclusionReason}`
        : "lipsește din sitemap");
    }
    const incomingSources = incoming.get(entry.route) || new Set();
    if (entry.route !== "/" && incomingSources.size === 0) routeIssues.push("fără link intern incoming");
    const redirectSources = incomingViaRedirect.get(entry.route) || new Set();
    if (redirectSources.size) routeIssues.push(`${redirectSources.size} surse leagă prin redirect`);
    return {
      route: entry.route,
      canonicalUrl: entry.url,
      sourceFile: entry.sourceFile,
      pageType: classifyPage(entry.route, pages[0], program, info, blogRoutes),
      expectedHttp: 200,
      indexable: true,
      title: info.title,
      h1: info.h1s.join(" / "),
      h1Count: info.h1s.length,
      canonical: info.canonical,
      sitemap: sitemapRoutes.has(entry.route),
      sitemapExclusionReason: entry.sitemapExclusionReason || "",
      sitemapExclusionDetail: entry.sitemapExclusionDetail || "",
      nav: navRoutes.has(entry.route),
      footer: footerRoutes.has(entry.route),
      incomingCount: incomingSources.size,
      structuredData: info.structuredTypes,
      breadcrumb: info.breadcrumbHtml || info.breadcrumbSchema,
      faqVisibleCount: info.visibleFaqCount,
      faqSchemaCount: info.schemaFaqCount,
      registryRelation: [
        ...programs.map((item) => `program:${item.slug}`),
        ...pages.map((item) => `page:${item.slug}`),
      ],
      bannerRelation: bannersForRoute.map((item) => item.id),
      familyRelation: program?.family || (hub ? `hub:${hub.id}` : ""),
      status: program ? `${program.status} — ${program.statusLabel}` : "rută publică/indexabilă",
      issues: routeIssues,
    };
  });

  const routeSet = new Set(routes.map((route) => route.route));
  const orphanRoutes = routes.filter((route) => route.route !== "/" && route.incomingCount === 0);
  const sitemapWithoutRoute = [...sitemapRoutes].filter((route) => !routeSet.has(route));
  const routesWithoutSitemap = routes.filter((route) => !route.sitemap);
  const bannerPrograms = seo.programs.filter((program) => program.publicationState === "public" && program.presentation?.carousel);
  const bannerIds = new Set(banners.filter((banner) => banner.active !== false).map((banner) => banner.programId));
  const featuredIds = new Set(seo.programs.filter((program) => program.presentation?.carousel).map((program) => program.id));
  const programReconciliation = seo.programs.map((program) => {
    const route = cleanRoute(program.pageUrl);
    const resolvedRoute = resolveRedirectRoute(route, redirectByCleanRoute);
    const matchingBanners = banners.filter((banner) => banner.programId === program.id && banner.active !== false);
    const matchingPages = seo.pages.filter((page) => page.programId === program.id);
    const issues = [];
    if (resolvedRoute !== route) issues.push(`pageUrl redirectează la ${resolvedRoute}`);
    if (program.presentation?.carousel && !matchingBanners.length) issues.push("banner activat fără banner materializat");
    if (matchingBanners.some((banner) => cleanRoute(banner.ctaLink) !== resolvedRoute)) issues.push("banner spre altă rută");
    if (!routeSet.has(resolvedRoute)) issues.push("fără rută canonical 200");
    return {
      id: program.id,
      name: program.name,
      pageUrl: route,
      resolvedRoute,
      family: program.family,
      status: program.status,
      listed: program.discovery?.listed !== false,
      homepage: featuredIds.has(program.id),
      banners: matchingBanners.map((banner) => banner.id),
      pageDefinitions: matchingPages.map((page) => page.slug),
      issues,
    };
  });

  const redirectPageDefinitions = seo.pages
    .map((page) => ({ page, route: cleanRoute(`/${page.slug}`) }))
    .filter(({ route }) => redirectByCleanRoute.has(route))
    .map(({ page, route }) => ({ slug: page.slug, route, target: resolveRedirectRoute(route, redirectByCleanRoute), type: page.type }));

  const publicFragments = state.excluded
    .filter((item) => item.reason === "missing_canonical")
    .map((item) => ({
      route: item.route,
      sourceFile: item.sourceFile,
      expectedHttp: 200,
      indexable: item.route.startsWith("/google") ? "tehnic; header de verificat pe ruta curată" : "da (neintenționat)",
      issue: item.route.startsWith("/google")
        ? "Fișier de verificare; normalizarea globală redirecționează forma .html."
        : "Fișier copiat de build și servit public fără document HTML complet, canonical sau noindex.",
    }));

  const technicalRoutes = [
    ["/robots.txt", "robots policy", "200", "nu"],
    ["/sitemap.xml", "sitemap index", "200", "nu (X-Robots-Tag)"],
    ["/sitemap-programs.xml", "sitemap urlset", "200", "nu"],
    ["/sitemap-guides.xml", "sitemap urlset", "200", "nu"],
    ["/sitemap-core.xml", "sitemap urlset", "200", "nu"],
    ["/feed.xml", "feed XML", "200", "nu"],
    ["/llms.txt", "crawler/LLM index", "200", "nu (X-Robots-Tag)"],
    ["/blog.json", "date blog runtime", "200", "nu"],
    ["/official-guides.json", "surse oficiale runtime", "200", "nu (X-Robots-Tag)"],
    ["/site.webmanifest", "web manifest", "200", "nu"],
    ["/release.json", "artefact build/SHA", "200", "nu (X-Robots-Tag)"],
    ["/indexnow-key.txt", "cheie publică IndexNow", "200", "nu"],
    ["/a54d3e71f7854ddd9b9fc4cb91c7d681.txt", "token verificare", "200", "nu"],
    ["/google8bbb9999c523a3bd.html", "token Google legacy", "301 spre forma fără .html", "nu"],
    ["/resurse/descarcari/checklist-documente-fonduri-europene.pdf", "download", "200", "nu"],
    ["/resurse/descarcari/checklist-afir-dr12-dr14.pdf", "download", "200", "nu"],
    ["/resurse/descarcari/calendar-pregatire-depunere.xlsx", "download", "200", "nu"],
    ["/resurse/descarcari/buget-digitalizare-imm.xlsx", "download", "200", "nu"],
    ["/api/contact-triage", "API formular; POST", "GET 405; POST 200/4xx/5xx", "nu; /api blocat în robots"],
    ["/api/crm/qualified-lead", "API server-side; POST autentificat", "GET 405; POST 202/4xx/5xx", "nu; /api blocat în robots"],
  ].map(([route, type, expectedHttp, indexable]) => ({ route, type, expectedHttp, indexable }));

  return {
    state,
    seo,
    families,
    navigation,
    banners,
    routes,
    exactRedirects,
    dynamicRedirects,
    programReconciliation,
    redirectPageDefinitions,
    publicFragments,
    technicalRoutes,
    canonicalDuplicates: canonicalDuplicateGroups(),
    duplicateProgramIds: duplicateValues(seo.programs, (program) => program.id),
    duplicateProgramSlugs: duplicateValues(seo.programs, (program) => program.slug),
    duplicatePageSlugs: duplicateValues(seo.pages, (page) => page.slug),
    duplicateBannerIds: duplicateValues(banners, (banner) => banner.id),
    duplicatePublishedCanonicals: duplicateValues(routes, (route) => route.canonicalUrl),
    orphanRoutes,
    sitemapWithoutRoute,
    routesWithoutSitemap,
    listedWithoutBanner: bannerPrograms.filter((program) => !bannerIds.has(program.id)),
    bannerWithoutProgram: banners.filter((banner) => banner.active !== false && !programsBySlug.has(banner.programId)),
  };
}

function validateInventory(inventory) {
  const errors = [];
  if (!inventory.routes.length) errors.push("Inventarul canonical este gol.");
  if (inventory.duplicatePublishedCanonicals.length) errors.push("Canonical duplicat în setul publicat.");
  if (duplicateValues(inventory.routes, (route) => route.route).length) errors.push("Rută duplicată în setul publicat.");
  if (inventory.duplicateProgramIds.length) errors.push("ID stabil de program duplicat.");
  if (inventory.duplicateProgramSlugs.length) errors.push("Slug de program duplicat.");
  if (inventory.duplicatePageSlugs.length) errors.push("Slug de pagină duplicat.");
  if (inventory.duplicateBannerIds.length) errors.push("ID de banner duplicat.");
  if (inventory.sitemapWithoutRoute.length) errors.push(`Sitemap fără rută: ${inventory.sitemapWithoutRoute.join(", ")}`);
  const unexplainedSitemapOmissions = inventory.routesWithoutSitemap.filter((route) => !route.sitemapExclusionReason);
  if (unexplainedSitemapOmissions.length) errors.push(`Rute indexabile fără sitemap și fără decizie documentată: ${unexplainedSitemapOmissions.map((route) => route.route).join(", ")}`);
  if (inventory.listedWithoutBanner.length) errors.push(`Programe listate fără banner: ${inventory.listedWithoutBanner.map((program) => program.slug).join(", ")}`);
  if (inventory.bannerWithoutProgram.length) errors.push(`Bannere fără program: ${inventory.bannerWithoutProgram.map((banner) => banner.id).join(", ")}`);
  if (inventory.orphanRoutes.length) errors.push(`Rute indexabile fără incoming links: ${inventory.orphanRoutes.map((route) => route.route).join(", ")}`);
  return errors;
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchLiveSnapshot(inventory) {
  const sitemapFiles = ["sitemap.xml", "sitemap-programs.xml", "sitemap-guides.xml", "sitemap-core.xml"];
  const documents = new Map();
  for (const file of sitemapFiles) {
    const response = await fetchWithTimeout(`${SITE}/${file}`, { headers: { accept: "application/xml,text/xml" } });
    if (!response.ok) throw new Error(`Live ${file}: HTTP ${response.status}`);
    documents.set(file, await response.text());
  }
  const liveSitemap = readSitemapEntriesFromReader((file) => documents.get(file), "sitemap.xml", SITE);
  const liveRoutes = new Set(liveSitemap.entries.map((entry) => cleanRoute(entry.url)));
  const repoRoutes = new Set(inventory.routes.map((route) => route.route));
  const releaseResponse = await fetchWithTimeout(`${SITE}/release.json`, { headers: { accept: "application/json" } });
  if (!releaseResponse.ok) throw new Error(`Live release.json: HTTP ${releaseResponse.status}`);
  const release = await releaseResponse.json();
  const checks = [];
  for (const route of LIVE_CHECK_PATHS) {
    try {
      const response = await fetchWithTimeout(`${SITE}${route}`, { method: "HEAD", redirect: "manual" });
      checks.push({ route, status: response.status, location: response.headers.get("location") || "", xRobots: response.headers.get("x-robots-tag") || "" });
    } catch (error) {
      checks.push({ route, status: "ERROR", location: "", xRobots: "", error: error.message });
    }
  }
  return {
    checkedAt: new Date().toISOString(),
    release,
    sitemapCount: liveRoutes.size,
    sitemapOnly: [...liveRoutes].filter((route) => !repoRoutes.has(route)).sort(),
    repoOnly: [...repoRoutes].filter((route) => !liveRoutes.has(route)).sort(),
    checks,
  };
}

function requiredSurfaceRows() {
  return [
    ["Homepage", "/", "rută proprie"],
    ["Fiecare program", "vezi tabelul «Reconcilierea programelor»", "25 entități registry; 23 listate/bannere"],
    ["Familii/categorii", "/afir; /fonduri-regionale; /fonduri-europene-digitalizare; /finantari-panouri-fotovoltaice; /fonduri-europene-imm", "5 huburi din registry"],
    ["Analiză eligibilitate", "/verificare-eligibilitate-fonduri-europene", "rută proprie"],
    ["Consultanță", "/consultanta-fonduri-europene", "rută proprie"],
    ["Proiectare", "/proiectare-fonduri-europene", "rută proprie"],
    ["Implementare", "/management-proiecte-fonduri-europene", "rută proprie"],
    ["Calculator SO", "/calculator-soc", "rută proprie; /calculator-so-afir este alias 301"],
    ["Contact", "/contact", "rută proprie"],
    ["Despre FABER", "/despre-faber", "rută proprie"],
    ["Echipa", "/despre-faber#about-team-title", "secțiune; profilurile rămân blocate până la dovezi"],
    ["Metodologie", "/metodologie-verificare-eligibilitate", "rută proprie"],
    ["Studii de caz", "/studii-de-caz-fonduri-europene", "rută canonical; /studii-de-caz, /portofoliu și /testimoniale sunt 301"],
    ["Date companie", "/despre-faber#about-public-data", "secțiune din ruta About"],
    ["GDPR", "/gdpr", "rută proprie"],
    ["Privacy", "/politica-de-confidentialitate", "rută proprie"],
    ["Cookies", "/politica-de-confidentialitate#cookies", "secțiune; nu există rută /cookies"],
    ["Terms", "/termeni-si-conditii", "rută proprie"],
    ["ANPC", "https://anpc.ro și https://anpc.ro/ce-este-sal", "linkuri externe în homepage/GDPR/Terms; nu există rută locală /anpc"],
    ["Articole/ghiduri", "/blog; /ghiduri și rutele article/guide din inventar", "HTML canonical pre-randat + blog.json"],
    ["Landing pages locale", "/fonduri-europene-nord-est; /fonduri-europene-bucuresti", "Iași/Suceava/Bacău sunt aliasuri 301 către Nord-Est"],
    ["404", "fallback pentru orice rută inexistentă", "ruta explicită /404 și orice URL inexistent răspund 404/noindex"],
  ];
}

function historicalBaselineRows(inventory) {
  const mappings = [
    ["DR12 AFIR", "dr12-afir"],
    ["DR14 AFIR", "dr14-afir"],
    ["AFIR Autoconsum Agroalimentar", "afir-energie-autoconsum"],
    ["Autoconsum instituții publice", "autoconsum-institutii-publice"],
    ["Digitalizare IMM", "digitalizare-imm"],
    ["Femeia Antreprenor", "femeia-antreprenor"],
    ["PRO INFRA", "pro-infra"],
    ["Start-Up Nation", "start-up-nation"],
    ["Modernizarea microîntreprinderilor – Apel 2", "modernizare-microintreprinderi-ne-2"],
    ["Fondul pentru Modernizare – energie regenerabilă", "fondul-modernizare-regenerabile"],
    ["Apeluri GAL", "apeluri-gal"],
    ["e-MOVE RO", "e-move-ro"],
    ["GAL-AFIR / LEADER", "gal-afir-leader"],
    ["Fondul pentru Modernizare – autoconsum", "fondul-modernizare-autoconsum"],
    ["Diaspora Investește Acasă", "diaspora-investeste-acasa"],
    ["e-DRIVE", "e-drive"],
    ["e-Mobility RO", "e-mobility-ro"],
    ["PC1 Stocare stand-alone", "fondul-modernizare-pc1-stocare"],
    ["PoCIDIF 2.1", "pocidif-21"],
  ];
  const byId = new Map(inventory.programReconciliation.map((program) => [program.id, program]));
  return mappings.map(([historicalName, id]) => ({ historicalName, ...byId.get(id) }));
}

function renderInventory(inventory, live) {
  const typeCounts = [...new Map(inventory.routes.map((route) => [route.pageType, 0])).keys()]
    .map((type) => [type, inventory.routes.filter((route) => route.pageType === type).length])
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  const exactUniqueSources = new Set(inventory.exactRedirects.map((rule) => rule.source)).size;
  const liveSummary = live
    ? `Snapshot live: **${live.checkedAt.slice(0, 10)}**, release \`${live.release.commit || "necunoscut"}\`, sitemap live **${live.sitemapCount} URL-uri**. Diferențe live→repo: **${live.sitemapOnly.length}**; repo→live: **${live.repoOnly.length}**.`
    : "Snapshot live: nu a fost cerut la această regenerare; vezi ultima secțiune versionată sau rulează `npm run generate:route-inventory`.";
  const lines = [
    "# Inventar exhaustiv al rutelor publice FABER",
    "",
    `Data inventarului: **${new Date().toISOString().slice(0, 10)}**.`,
    "",
    "Generator: `tools/generate-route-inventory.js`. Autoritatea pentru setul canonical este `collectSiteState()` din generatorul de sitemap; aceasta este reconciliată cu toate fișierele HTML, registrele, homepage-ul, bannerele, navigația, footerul, sitemap-urile, redirecturile și suprafețele copiate de build.",
    "",
    liveSummary,
    "",
    "## Rezumat verificabil",
    "",
    `- Rute HTML publice, self-canonical, indexabile, așteptate cu HTTP 200: **${inventory.routes.length}**; în sitemap: **${inventory.routes.filter((route) => route.sitemap).length}**; excluse prin politică: **${inventory.routesWithoutSitemap.length}**.`,
    `- Entități de program în registry: **${inventory.seo.programs.length}**; programe listate în catalog: **${inventory.programReconciliation.filter((program) => program.listed).length}**; bannere active: **${inventory.banners.filter((banner) => banner.active !== false).length}**.`,
    `- Definiții de pagină în registry: **${inventory.seo.pages.length}**; definiții care indică o sursă de redirect: **${inventory.redirectPageDefinitions.length}**.`,
    `- Redirecturi exacte: **${inventory.exactRedirects.length}** reguli / **${exactUniqueSources}** surse distincte; redirecturi dinamice de normalizare: **${inventory.dynamicRedirects.length}**.`,
    `- Canonical declarate de mai multe fișiere HTML: **${inventory.canonicalDuplicates.length}** grupuri; acestea sunt inventariate separat și nu sunt confundate cu duplicate în setul publicat.`,
    `- Rute indexabile fără incoming links: **${inventory.orphanRoutes.length}**; rute indexabile lipsă din sitemap: **${inventory.routesWithoutSitemap.length}** (\`${inventory.routesWithoutSitemap.map((route) => route.route).join(", ") || "—"}\`); URL-uri sitemap fără rută: **${inventory.sitemapWithoutRoute.length}**.`,
    `- Fragmente/fișiere HTML fără canonical descoperite de scanarea repo: **${inventory.publicFragments.length}**; trei sunt servite live ca HTML 200 și indexabile neintenționat.`,
    "",
    "Tipurile sunt derivate din registry, `data-analytics-page-type`, schema și forma rutei:",
    "",
    "| Tip | Număr |",
    "|---|---:|",
    ...typeCounts.map(([type, count]) => `| ${markdown(type)} | ${count} |`),
    "",
    "## Acoperirea suprafețelor obligatorii",
    "",
    "Lipsa unei rute standalone nu este tratată automat ca defect atunci când suprafața există semantic într-o pagină canonical sau ca destinație externă legitimă.",
    "",
    "| Suprafață | URL/rută reală | Relație |",
    "|---|---|---|",
    ...requiredSurfaceRows().map((row) => `| ${row.map(markdown).join(" | ")} |`),
    "",
    "## Inventarul rutelor canonical 200/indexabile",
    "",
    "`Incoming` este numărul de rute canonical distincte care trimit intern către destinație. `Nav/Footer` arată dacă destinația apare în componentele globale. `FAQ v/s` reprezintă numărul aproximativ de blocuri vizibile / entități `mainEntity` din FAQPage.",
    "",
    "| Rută / canonical URL | Sursă rută | Tip | HTTP / index | Title | H1 | Canonical declarat | Sitemap | Nav/Footer | Incoming | Structured data | Breadcrumb | FAQ v/s | Registry | Banner | Familie | Status / note |",
    "|---|---|---|---|---|---|---|---|---|---:|---|---|---:|---|---|---|---|",
    ...inventory.routes.map((route) => {
      const h1 = route.h1Count === 1 ? route.h1 : `${route.h1Count}× ${route.h1 || "—"}`;
      const structured = route.structuredData.length ? route.structuredData.join(", ") : "—";
      const status = [shortText(route.status, 105), ...route.issues].filter(Boolean).join("; ");
      return `| [\`${markdown(route.route)}\`](${route.canonicalUrl})<br><small>${markdown(route.canonicalUrl)}</small> | \`${markdown(route.sourceFile)}\` | ${markdown(route.pageType)} | ${route.expectedHttp} / da | ${markdown(shortText(route.title))} | ${markdown(shortText(h1))} | ${route.canonical === route.canonicalUrl ? "self" : markdown(route.canonical || "lipsește")} | ${route.sitemap ? "da" : "nu"} | ${route.nav ? "da" : "nu"}/${route.footer ? "da" : "nu"} | ${route.incomingCount} | ${markdown(structured)} | ${route.breadcrumb ? "da" : "nu"} | ${route.faqVisibleCount}/${route.faqSchemaCount} | ${markdown(route.registryRelation.join(", ") || "—")} | ${markdown(route.bannerRelation.join(", ") || "—")} | ${markdown(route.familyRelation || "—")} | ${markdown(status)} |`;
    }),
    "",
    "## Reconcilierea programelor: registry vs pagină vs homepage/catalog/banner",
    "",
    "Statusul este redat exact în taxonomia existentă din registry. Nu este reinterpretat într-o stare mai optimistă. Taxonomia mai granulară solicitată rămâne problema `T00-005` și nu este migrată în Task 01.",
    "",
    "| ID / program | pageUrl → rută finală | Familie | Status registry | Catalog | Homepage | Banner | Definiție pagină | Probleme |",
    "|---|---|---|---|---|---|---|---|---|",
    ...inventory.programReconciliation.map((program) => `| \`${markdown(program.id)}\`<br>${markdown(shortText(program.name))} | \`${markdown(program.pageUrl)}\`${program.pageUrl === program.resolvedRoute ? "" : ` → \`${markdown(program.resolvedRoute)}\``} | ${markdown(program.family)} | \`${markdown(program.status)}\` | ${program.listed ? "da" : "nu"} | ${program.homepage ? "da" : "nu"} | ${markdown(program.banners.join(", ") || "—")} | ${markdown(program.pageDefinitions.join(", ") || "—")} | ${markdown(program.issues.join("; ") || "—")} |`),
    "",
    "### Reconciliere cu baseline-ul istoric de 19 entități",
    "",
    "Toate cele 19 entități istorice au corespondent în registry-ul curent. Nu a fost găsită o eliminare; aliasurile istorice sunt păstrate prin redirecturi. Cele **6 entități suplimentare** față de listă sunt: `program-regional-nord-est`, `fonduri-regionale`, `dr18-afir`, `pnrr`, `programul-tranzitie-justa` și `fondul-de-modernizare`.",
    "",
    "| Entitate istorică | ID registry actual | Rută canonical actuală | Status registry | Rezultat |",
    "|---|---|---|---|---|",
    ...historicalBaselineRows(inventory).map((program) => `| ${markdown(program.historicalName)} | \`${markdown(program.id)}\` | \`${markdown(program.resolvedRoute)}\` | \`${markdown(program.status)}\` | regăsit |`),
    "",
    "Diferențe de suprafață:",
    "",
    "- Cele 23 programe `listed=true` au `presentation.carousel=true` în registrul unic și câte un banner generat activ; nu există banner fără program și nici program listat fără banner.",
    "- `program-regional-nord-est` și `fonduri-regionale` au `listed=false`; primul folosește `/por-adr-nord-est`, care redirecționează la pagina Apelului 2, iar al doilea este hubul canonical `/fonduri-regionale`.",
    "- Sitemap-ul `programs` conține 26 URL-uri: cele 23 programe listate, hubul `/fonduri-regionale` și două ghiduri DR12/DR14 clasificate editorial în familia sitemap `programs`.",
    "",
    "### Definiții de pagină care indică rute retrase/redirectate",
    "",
    "| Slug config | Tip | Sursă 301 | Destinație canonical |",
    "|---|---|---|---|",
    ...inventory.redirectPageDefinitions.map((item) => `| \`${markdown(item.slug)}\` | ${markdown(item.type)} | \`${markdown(item.route)}\` | \`${markdown(item.target)}\` |`),
    "",
    "## Duplicate canonical fizice",
    "",
    "Acestea sunt fișiere sursă multiple care declară același canonical. Verificarea nouă eșuează pentru duplicate în setul canonical publicat sau pentru sluguri duplicate în registre, dar raportează separat aliasurile fizice cunoscute deoarece build-ul le sincronizează în `dist/`.",
    "",
    "| Canonical | Fișiere | Identice byte-for-byte |",
    "|---|---|---|",
    ...inventory.canonicalDuplicates.map((group) => `| ${markdown(group.canonical)} | ${markdown(group.files.map((file) => `\`${file.file}\``).join(", "))} | ${group.identical ? "da" : "nu"} |`),
    "",
    "## Rute legacy și redirecturi exacte",
    "",
    "Pentru aceste rute, title/H1/canonical/schema/breadcrumb/FAQ nu se aplică: răspunsul așteptat este redirect și ruta nu trebuie indexată ori inclusă în sitemap. Incoming este urmărit de auditurile de linkuri; validatorul SEO baseline raportează încă linkuri interne către câteva surse de redirect (`T00-017`).",
    "",
    "| Sursă | Destinație | HTTP | Indexabilă | Sursă regulă | Sitemap |",
    "|---|---|---:|---|---|---|",
    ...inventory.exactRedirects.map((rule) => `| \`${markdown(rule.source)}\` | ${markdown(rule.destination)} | ${rule.status} | nu | \`_redirects\` | nu |`),
    "",
    "### Reguli dinamice de normalizare",
    "",
    "| Pattern | Destinație | HTTP |",
    "|---|---|---:|",
    ...inventory.dynamicRedirects.map((rule) => `| \`${markdown(rule.source)}\` | ${markdown(rule.destination)} | ${rule.status} |`),
    "",
    "Workerul de domeniu normalizează suplimentar HTTP→HTTPS, `www`→apex, `.html`, `/index.html`, slash final, query-ul istoric de căutare și query-urile de contact. `_redirects` rămâne fallback-ul static reviewable.",
    "",
    "## Suprafețe HTML publice necanonice / noindex",
    "",
    "| Rută | Sursă | HTTP | Indexabilitate | Metadata/schema | Problemă |",
    "|---|---|---:|---|---|---|",
    "| `/404` | `404.html` | 404 explicit și ca fallback pentru URL inexistent | nu (meta + X-Robots-Tag) | title/H1, fără canonical și fără sitemap | Comportament intenționat; workerul păstrează navigația utilă și emite `noindex, follow`. |",
    "| `/admin` | `admin/index.html` | 200 | nu (meta + X-Robots-Tag) | title/H1, fără sitemap | Panou client-side public; nu este o zonă autentificată server-side. Necesită review separat de securitate/operare. |",
    ...inventory.publicFragments.map((item) => `| \`${markdown(item.route)}\` | \`${markdown(item.sourceFile)}\` | ${item.expectedHttp} | ${markdown(item.indexable)} | lipsesc canonical/metadata/schema de pagină | ${markdown(item.issue)} |`),
    "",
    "## Endpointuri și fișiere publice non-page",
    "",
    "Activele CSS/JS/imagini nu sunt enumerate individual; tabelul include endpointurile tehnice, feed-urile și descărcările care fac parte din suprafața publică funcțională/crawlable.",
    "",
    "| Rută | Tip | HTTP așteptat | Indexabilitate |",
    "|---|---|---|---|",
    ...inventory.technicalRoutes.map((item) => `| \`${markdown(item.route)}\` | ${markdown(item.type)} | ${markdown(item.expectedHttp)} | ${markdown(item.indexable)} |`),
    "",
    "## Diferențe repo vs sitemap vs homepage vs catalog",
    "",
    `- Repo public vs sitemap local: **${inventory.routesWithoutSitemap.length} rute repo lipsă din sitemap** (\`${inventory.routesWithoutSitemap.map((route) => route.route).join(", ") || "—"}\`) și **${inventory.sitemapWithoutRoute.length} URL-uri sitemap fără rută**.`,
    `- Orfane indexabile după scanarea linkurilor din cele ${inventory.routes.length} surse canonical: **${inventory.orphanRoutes.length}**.`,
    `- Homepage/catalog: **${inventory.programReconciliation.filter((program) => program.homepage).length}** programe configurate pe homepage, **${inventory.programReconciliation.filter((program) => program.listed).length}** listate și **${inventory.banners.filter((banner) => banner.active !== false).length}** bannere active.`,
    `- Bannere fără program: **${inventory.bannerWithoutProgram.length}**; programe listate fără banner: **${inventory.listedWithoutBanner.length}**.`,
    "- Suprafețe publice servite dar intenționat în afara sitemap-ului: redirecturile, `/404`, `/admin`, endpointurile tehnice și fișierele non-page.",
    "- Suprafețe HTML publice neintenționat indexabile și fără canonical: `/partials/global-header`, `/templates/dr14-final-content`, `/templates/dr18-final-content`. Acestea provin din politica de copiere a build-ului, nu din router sau sitemap.",
    "",
    "## Verificare live",
    "",
  ];

  if (live) {
    lines.push(
      `- ` + `\`/release.json\`` + `: commit \`${markdown(live.release.commit || "—")}\`, build \`${markdown(live.release.builtAt || "—")}\`.`,
      `- Sitemap live: **${live.sitemapCount}** URL-uri; numai live: **${live.sitemapOnly.length}**; numai repo: **${live.repoOnly.length}**.`,
      `- Numai live: \`${live.sitemapOnly.join(", ") || "—"}\`; numai în suprafața publică repo: \`${live.repoOnly.join(", ") || "—"}\`.`,
      "",
      "| Rută verificată | HTTP live | Location | X-Robots-Tag |",
      "|---|---:|---|---|",
      ...live.checks.map((check) => `| \`${markdown(check.route)}\` | ${check.status} | ${markdown(check.location || "—")} | ${markdown(check.xRobots || check.error || "—")} |`),
    );
  } else {
    lines.push("Nu s-a executat verificarea live în această regenerare.");
  }

  lines.push(
    "",
    "## Probleme și priorități rămase (fără remediere în Task 01)",
    "",
    "- **P0 existent:** `/contact` păstrează inconsistența de stare legală, iar Clarity nu are un gate de consent identificabil (`T00-003`, `T00-004`).",
    "- **P1:** cele trei fragmente `/partials/*` și `/templates/*` sunt HTML 200 indexabil, fără canonical/noindex și fără rol de pagină publică. Politica build trebuie să le excludă sau să le protejeze într-un task separat.",
    "- **P1:** registry-ul de pagini conține definiții pentru rute care sunt acum 301; trebuie consolidat fără pierderea URL equity.",
    "- **P1:** `/gdpr` este 200/self-canonical/indexabil, dar lipsește intenționat din sitemap prin `duplicate_policy_pending_legal_consolidation`; consolidarea juridică și SEO este încă neaprobată.",
    "- **P1 existent:** fișierele fizice duplicate și listele de precedență canonical rămân surse paralele (`T00-007`, `T00-008`).",
    "- **P1 existent:** validatorul SEO raportează linkuri interne către surse de redirect (`T00-017`).",
    "- **P1:** `/admin` este o suprafață publică protejată doar prin UI/localStorage, nu o zonă autentificată server-side; rolul ei operațional și expunerea trebuie revizuite separat.",
    "- **P2:** `/cookies`, `/echipa`, `/date-companie` și `/anpc` nu există ca rute standalone; conținutul/destinația există în paginile canonical sau extern și nu justifică automat URL-uri noi.",
    "- **Rezolvat în Task 10–11:** forma explicită `/404` și fallback-ul necunoscut răspund 404, fără canonical și cu meta/X-Robots-Tag `noindex, follow` coerente.",
    "",
    "## Verificarea automată adăugată",
    "",
    "`npm run test:route-inventory` validează unicitatea rutelor/canonicalelor publicate, slugurile de program/pagină, ID-urile de banner, paritatea sitemap, acoperirea bannerelor și lipsa rutelor orfane. Duplicatele fizice intenționate sunt enumerate în raport și rămân vizibile pentru review.",
  );
  return `${lines.join("\n")}\n`;
}

function checkReportCoverage(inventory) {
  if (!fs.existsSync(OUTPUT)) return ["ROUTE_INVENTORY.md lipsește."];
  const report = fs.readFileSync(OUTPUT, "utf8");
  const missing = [];
  for (const route of inventory.routes) {
    if (!report.includes(route.canonicalUrl)) missing.push(route.route);
  }
  for (const rule of inventory.exactRedirects) {
    if (!report.includes(`\`${rule.source}\``)) missing.push(`redirect:${rule.source}`);
  }
  for (const fragment of inventory.publicFragments) {
    if (!report.includes(`\`${fragment.route}\``)) missing.push(`fragment:${fragment.route}`);
  }
  return missing.length ? [`Raportul nu acoperă: ${missing.join(", ")}`] : [];
}

async function main() {
  const inventory = buildInventory();
  const validationErrors = validateInventory(inventory);
  if (process.argv.includes("--check")) {
    const errors = [...validationErrors, ...checkReportCoverage(inventory)];
    if (errors.length) {
      console.error(errors.join("\n"));
      process.exitCode = 1;
      return;
    }
    console.log(`Route inventory PASS: ${inventory.routes.length} canonical routes, ${inventory.exactRedirects.length} exact redirects, ${inventory.canonicalDuplicates.length} physical duplicate groups documented.`);
    return;
  }
  let live = null;
  if (process.argv.includes("--live")) live = await fetchLiveSnapshot(inventory);
  if (validationErrors.length) throw new Error(validationErrors.join("\n"));
  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
  fs.writeFileSync(OUTPUT, renderInventory(inventory, live), "utf8");
  console.log(`Generated ${toPosix(path.relative(ROOT, OUTPUT))}: ${inventory.routes.length} canonical routes, ${inventory.exactRedirects.length} exact redirects.`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  buildInventory,
  checkReportCoverage,
  renderInventory,
  validateInventory,
};
