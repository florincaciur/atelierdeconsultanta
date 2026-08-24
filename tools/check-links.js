#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { auditSiteLinks, parseRedirects } = require("./audit-site-links");
const { auditInternalLinkGraph } = require("./audit-internal-link-graph");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");
const { SITE, fileForRoute, sitemapRoutes, visibleFaqItems } = require("./structured-data-utils");

const DEFAULT_ROOT = path.resolve(__dirname, "..");
const DEFAULT_REPORT = path.join("docs", "faber-remediation", "LINK_AUDIT.md");
const SITE_HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const NETWORK_CATEGORIES = ["200", "permanent_redirect", "temporary_redirect", "404", "410", "5xx", "timeout", "blocked_external"];
const REGISTRY_FILES = [
  "config/seo-programs.json",
  "config/program-source-registry.json",
  "config/editorial-governance.json",
  "config/priority-pages.json",
  "config/legal-identity.json",
  "official-guides.json",
  "banners.json"
];
const DOCUMENT_PATTERN = /\.(?:pdf|docx?|xlsx?|zip)(?:$|[?#])/iu;
const GENERIC_DOCUMENT_LABEL = /^(?:ghid oficial|surs[ăa] oficial[ăa]?|document oficial|deschide sursa|deschide documentul|vezi documentul|click aici|aici|descarc[ăa])$/iu;

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function json(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function isExternalHttp(value) {
  try {
    const url = new URL(String(value || ""));
    return /^https?:$/iu.test(url.protocol) && !SITE_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function isDocumentUrl(value) {
  const url = String(value || "");
  return DOCUMENT_PATTERN.test(url) || (/\/api\/file(?:\/document)?\?/iu.test(url) && /(?:^|[?&])filetype=(?:pdf|docx?|xlsx?|zip)(?:&|$)/iu.test(url));
}

function descriptiveDocumentLabel(label, href) {
  const text = cleanText(label);
  if (!text || text === href || /^https?:\/\//iu.test(text) || GENERIC_DOCUMENT_LABEL.test(text)) return false;
  return text.split(/\s+/u).length >= 3;
}

function occurrenceSurface($, element, route, routeKind) {
  const surfaces = new Set([routeKind]);
  const anchor = $(element);
  if (route === "/") surfaces.add("homepage");
  if (anchor.closest("header, nav, .global-header").length) surfaces.add("navigation");
  if (anchor.closest("footer").length) surfaces.add("footer");
  if (anchor.closest("[data-breadcrumb], .breadcrumb, [aria-label*='breadcrumb' i]").length) surfaces.add("breadcrumbs");
  if (anchor.closest(".faq-item, .faq-section, [itemtype*='Question']").length) surfaces.add("faq");
  return [...surfaces];
}

function addHttpRecord(records, href, occurrence = {}) {
  if (!isExternalHttp(href)) return;
  if (!records.has(href)) {
    records.set(href, {
      url: href,
      occurrences: [],
      labels: new Set(),
      roles: new Set(),
      official: false,
      document: isDocumentUrl(href)
    });
  }
  const record = records.get(href);
  record.occurrences.push(occurrence);
  if (occurrence.label) record.labels.add(cleanText(occurrence.label));
  for (const role of occurrence.roles || []) record.roles.add(role);
  if (occurrence.official) record.official = true;
  if (occurrence.document) record.document = true;
}

function routeKindFor(route, sets) {
  if (sets.programs.has(route)) return "program";
  if (sets.families.has(route)) return "family";
  if (route === "/calculator-soc") return "calculator";
  if (sets.legal.has(route)) return "legal";
  if (sets.guides.has(route)) return "guide";
  return "core";
}

function walkJsonUrls(value, visit, currentPath = "", parent = null) {
  if (typeof value === "string") {
    if (/^https?:\/\//iu.test(value)) visit(value, currentPath, parent);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkJsonUrls(item, visit, `${currentPath}[${index}]`, value));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) walkJsonUrls(child, visit, currentPath ? `${currentPath}.${key}` : key, value);
}

function parentLabel(parent, jsonPath) {
  if (parent && !Array.isArray(parent)) {
    for (const key of ["title", "name", "label", "sourceName", "sourceVersion", "documentType", "authority", "institution"]) {
      if (typeof parent[key] === "string" && cleanText(parent[key])) return cleanText(parent[key]);
    }
  }
  return jsonPath.split(/[.[\]]/u).filter(Boolean).slice(-2).join(" ");
}

function collectOfficialSources(root, records) {
  const registry = loadProgramConfig(path.join(root, "config", "seo-programs.json"));
  const addOfficial = (url, label, source, jsonPath) => addHttpRecord(records, url, {
    source,
    jsonPath,
    label,
    roles: ["registry", "official_source"],
    official: true,
    document: isDocumentUrl(url)
  });

  for (const program of registry.programs) addOfficial(program.sourceUrl, `${program.sourceName} — ${program.sourceVersion}`, "config/seo-programs.json", `programs.${program.id}.sourceUrl`);
  for (const change of registry.config.factualChanges || []) addOfficial(change.sourceUrl, change.sourceLabel || change.reason, "config/seo-programs.json", `factualChanges.${change.programId}.${change.field}`);

  const guides = json(path.join(root, "official-guides.json"));
  for (const [key, source] of Object.entries(guides)) addOfficial(source.url, source.title || source.name, "official-guides.json", key);

  const supplemental = json(path.join(root, "config", "program-source-registry.json")).supplementalSources || {};
  for (const [key, source] of Object.entries(supplemental)) addOfficial(source.url, source.title, "config/program-source-registry.json", `supplementalSources.${key}`);

  const governance = json(path.join(root, "config", "editorial-governance.json"));
  for (const record of governance.records || []) addOfficial(record.officialSourceUrl, `${record.officialSourceName} — ${record.sourceVersion}`, "config/editorial-governance.json", `records.${record.id}.officialSourceUrl`);

  const priority = json(path.join(root, "config", "priority-pages.json"));
  for (const [slug, page] of Object.entries(priority.pages || {})) addOfficial(page.source?.url, page.source?.document || page.source?.institution, "config/priority-pages.json", `pages.${slug}.source.url`);

  const banners = json(path.join(root, "banners.json"));
  for (const banner of banners) addOfficial(banner.sourceUrl, banner.sourceLabel || banner.title, "banners.json", `${banner.id}.sourceUrl`);
}

function collectInventory(root) {
  const records = new Map();
  const special = { mailto: new Map(), tel: new Map(), whatsapp: new Map() };
  const localDocuments = [];
  const surfaceCounts = Object.fromEntries(["router", "homepage", "navigation", "footer", "registry", "program", "family", "guide", "faq", "breadcrumbs", "schema", "legal", "calculator", "core"].map((key) => [key, 0]));
  const seo = json(path.join(root, "config", "seo-programs.json"));
  const programRoutes = new Set(seo.programs.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget).map((program) => program.pageUrl));
  const familyRoutes = new Set(json(path.join(root, "config", "program-family-hubs.json")).hubs.map((hub) => hub.route));
  const pageType = new Map((seo.pages || []).filter((page) => !page.redirectTo).map((page) => [`/${page.slug}`, page.type]));
  const legalRoutes = new Set([...pageType].filter(([, type]) => type === "legal").map(([route]) => route));
  for (const route of ["/termeni-si-conditii", "/politica-de-confidentialitate", "/gdpr"]) legalRoutes.add(route);
  const guideRoutes = new Set([...pageType].filter(([, type]) => ["article", "guide", "resource", "faq"].includes(type)).map(([route]) => route));
  const sets = { programs: programRoutes, families: familyRoutes, legal: legalRoutes, guides: guideRoutes };
  let faqBlocks = 0;
  let schemaUrls = 0;

  for (const route of sitemapRoutes(root)) {
    const file = fileForRoute(root, route);
    const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
    const routeKind = routeKindFor(route, sets);
    faqBlocks += visibleFaqItems($).length;
    $("a[href]").each((_, element) => {
      const href = String($(element).attr("href") || "").trim();
      const label = cleanText($(element).text());
      const roles = occurrenceSurface($, element, route, routeKind);
      for (const role of roles) surfaceCounts[role] += 1;
      if (/^mailto:/iu.test(href)) {
        if (!special.mailto.has(href)) special.mailto.set(href, []);
        special.mailto.get(href).push({ route, label });
        return;
      }
      if (/^tel:/iu.test(href)) {
        if (!special.tel.has(href)) special.tel.set(href, []);
        special.tel.get(href).push({ route, label });
        return;
      }
      if (/^https?:\/\//iu.test(href)) {
        if (new URL(href).hostname.toLowerCase() === "wa.me") {
          if (!special.whatsapp.has(href)) special.whatsapp.set(href, []);
          special.whatsapp.get(href).push({ route, label });
        }
        addHttpRecord(records, href, {
          source: path.relative(root, file).split(path.sep).join("/"),
          route,
          label,
          roles,
          contextualDocumentLabel: $(element).closest(".official-sources__url").length > 0,
          document: isDocumentUrl(href)
        });
        return;
      }
      if (isDocumentUrl(href)) localDocuments.push({ route, href, label });
    });

    $("script[type='application/ld+json']").each((_, element) => {
      let data;
      try { data = JSON.parse($(element).text()); } catch { return; }
      walkJsonUrls(data, (url, jsonPath) => {
        schemaUrls += 1;
        surfaceCounts.schema += 1;
        addHttpRecord(records, url, { source: path.relative(root, file).split(path.sep).join("/"), route, jsonPath, label: jsonPath, roles: ["schema"] });
      });
    });
  }

  for (const relative of REGISTRY_FILES) {
    const file = path.join(root, relative);
    if (!fs.existsSync(file)) continue;
    walkJsonUrls(json(file), (url, jsonPath, parent) => {
      surfaceCounts.registry += 1;
      addHttpRecord(records, url, { source: relative, jsonPath, label: parentLabel(parent, jsonPath), roles: ["registry"] });
    });
  }
  collectOfficialSources(root, records);
  surfaceCounts.router = parseRedirects(root).length;
  surfaceCounts.faqBlocks = faqBlocks;
  surfaceCounts.schemaUrls = schemaUrls;
  return { records, special, localDocuments, surfaceCounts };
}

function validateSpecialLinks(inventory, root, externalPolicy) {
  const errors = [];
  for (const href of inventory.special.mailto.keys()) {
    const address = decodeURIComponent(href.slice("mailto:".length).split("?")[0]);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(address)) errors.push(`mailto invalid: ${href}`);
  }
  for (const href of inventory.special.tel.keys()) {
    const number = href.slice("tel:".length).replace(/[\s().-]/gu, "");
    if (!/^\+[1-9]\d{7,14}$/u.test(number)) errors.push(`tel invalid sau non-E.164: ${href}`);
  }
  const approvedChannels = new Set(externalPolicy.approvedChannelUrls || []);
  for (const href of inventory.special.whatsapp.keys()) {
    const url = new URL(href);
    if (!/^\/\d{8,15}$/u.test(url.pathname) || !approvedChannels.has(`${url.origin}${url.pathname}`)) errors.push(`WhatsApp neaprobat sau invalid: ${href}`);
  }
  for (const document of inventory.localDocuments) {
    let decoded;
    try { decoded = decodeURIComponent(new URL(document.href, SITE).pathname).replace(/^\/+/, ""); } catch { decoded = ""; }
    const full = path.resolve(root, decoded);
    if (!decoded || !full.startsWith(`${root}${path.sep}`) || !fs.existsSync(full)) errors.push(`${document.route}: document intern inexistent ${document.href}`);
    if (!descriptiveDocumentLabel(document.label, document.href)) errors.push(`${document.route}: text nondescriptiv pentru documentul ${document.href}`);
  }
  return errors;
}

function validateExternalPolicy(inventory, policy) {
  const errors = [];
  const exact = new Set((policy.allowedExactHosts || []).map((host) => host.toLowerCase()));
  const hostAllowed = (host) => exact.has(host) || (policy.allowedHostSuffixes || []).some((suffix) => host.endsWith(suffix));
  for (const record of inventory.records.values()) {
    const url = new URL(record.url);
    const publicOccurrences = record.occurrences.filter(
      (occurrence) => occurrence.route && !(occurrence.roles || []).includes("schema")
    );
    if (publicOccurrences.length && url.protocol !== "https:") errors.push(`link public extern fără HTTPS: ${record.url}`);
    if (publicOccurrences.length && !hostAllowed(url.hostname.toLowerCase())) errors.push(`domeniu public extern neaprobat: ${url.hostname}`);
    if (record.official && url.protocol !== "https:") errors.push(`sursă oficială fără HTTPS: ${record.url}`);
  }
  return errors;
}

function validateDocumentLabels(inventory) {
  const errors = [];
  for (const record of inventory.records.values()) {
    if (!record.document) continue;
    for (const occurrence of record.occurrences.filter((item) => item.route)) {
      if (occurrence.contextualDocumentLabel) continue;
      if (!descriptiveDocumentLabel(occurrence.label, record.url)) errors.push(`${occurrence.route}: text nondescriptiv «${occurrence.label || "gol"}» pentru documentul ${record.url}`);
    }
    if (record.official && ![...record.labels].some((label) => descriptiveDocumentLabel(label, record.url))) errors.push(`sursa oficială document nu are titlu descriptiv în registry: ${record.url}`);
  }
  return errors;
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      redirect: "manual",
      headers: {
        accept: "text/html,application/xhtml+xml,application/pdf,application/octet-stream;q=0.8,*/*;q=0.5",
        "accept-language": "ro-RO,ro;q=0.9,en;q=0.6",
        range: "bytes=0-2047",
        "user-agent": "FABER-link-integrity-audit/1.0 (+https://atelierdeconsultanta.ro/)"
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

function statusCategory(status, redirects) {
  if (status === 404) return "404";
  if (status === 410) return "410";
  if (status >= 500) return "5xx";
  if ([401, 403, 406, 407, 408, 409, 418, 423, 425, 426, 429, 451].includes(status) || (status >= 400 && status < 500)) return "blocked_external";
  if (status >= 200 && status < 400) {
    if (redirects.some((item) => [302, 303, 307].includes(item.status))) return "temporary_redirect";
    if (redirects.some((item) => [301, 308].includes(item.status))) return "permanent_redirect";
    return "200";
  }
  return "blocked_external";
}

async function probeExternal(url, options = {}) {
  const timeoutMs = options.timeoutMs || 12000;
  const chain = [];
  let current = url;
  try {
    for (let index = 0; index <= 5; index += 1) {
      const response = await fetchWithTimeout(current, timeoutMs);
      const location = response.headers.get("location") || "";
      chain.push({ url: current, status: response.status, location });
      if (response.body) await response.body.cancel().catch(() => {});
      if (response.status >= 300 && response.status < 400 && location) {
        current = new URL(location, current).href;
        continue;
      }
      const redirects = chain.slice(0, -1);
      return { url, category: statusCategory(response.status, redirects), status: response.status, finalUrl: current, chain };
    }
    return { url, category: "blocked_external", status: 0, finalUrl: current, chain, detail: "redirect chain exceeded 5 hops" };
  } catch (error) {
    const timeout = error?.name === "AbortError" || error?.name === "TimeoutError";
    return { url, category: timeout ? "timeout" : "blocked_external", status: 0, finalUrl: current, chain, detail: error.message };
  }
}

async function mapLimit(values, limit, mapper) {
  const results = new Array(values.length);
  let cursor = 0;
  async function worker() {
    while (cursor < values.length) {
      const index = cursor++;
      results[index] = await mapper(values[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, worker));
  return results;
}

async function auditLinkIntegrity(options = {}) {
  const root = path.resolve(options.root || DEFAULT_ROOT);
  const policy = json(path.join(root, "config", "external-link-policy.json"));
  const inventory = collectInventory(root);
  const siteAudit = auditSiteLinks({ root });
  const graphAudit = auditInternalLinkGraph({ root });
  const errors = [
    ...siteAudit.issues.map((issue) => `${issue.type}: ${issue.sourceFile || "_redirects"} -> ${issue.value || issue.from || ""}`),
    ...graphAudit.errors,
    ...validateSpecialLinks(inventory, root, policy),
    ...validateExternalPolicy(inventory, policy),
    ...validateDocumentLabels(inventory)
  ];
  let network = [];
  if (options.network) {
    network = await mapLimit([...inventory.records.values()], options.concurrency || 6, (record) => probeExternal(record.url, options));
  }
  const classification = Object.fromEntries(NETWORK_CATEGORIES.map((category) => [category, network.filter((result) => result.category === category).length]));
  const confirmedOfficialFailures = network.filter((result) => inventory.records.get(result.url)?.official && ["404", "410"].includes(result.category));
  return {
    generatedAt: options.generatedAt || new Date().toISOString(),
    root,
    inventory,
    siteAudit,
    graphAudit,
    network,
    classification,
    confirmedOfficialFailures,
    errors: [...new Set(errors)]
  };
}

function markdownEscape(value) {
  return cleanText(value).replace(/\|/gu, "\\|");
}

function reportMarkdown(report) {
  const records = report.inventory.records;
  const rows = report.network.map((result) => {
    const record = records.get(result.url);
    const roles = [...record.roles].sort().join(", ");
    const example = record.occurrences.find((item) => item.route)?.route || record.occurrences[0]?.source || "—";
    const status = result.status || "—";
    const finalUrl = result.finalUrl === result.url ? "—" : result.finalUrl;
    return `| ${result.category} | ${status} | [${markdownEscape(result.url)}](${result.url}) | ${markdownEscape(finalUrl)} | ${markdownEscape(roles)} | ${markdownEscape(example)} |`;
  });
  const classificationRows = NETWORK_CATEGORIES.map((category) => `| ${category} | ${report.classification[category]} |`);
  const blocked = report.network.filter((result) => ["blocked_external", "timeout"].includes(result.category));
  const official = [...records.values()].filter((record) => record.official);
  const publicExternal = [...records.values()].filter((record) => record.occurrences.some((item) => item.route));
  const publicDocuments = [...records.values()].filter((record) => record.document && record.occurrences.some((item) => item.route));
  const surfaceRows = Object.entries(report.inventory.surfaceCounts).map(([surface, count]) => `| ${surface} | ${count} |`);
  return [
    "# Task 20 — Audit reproducibil al linkurilor și surselor",
    "",
    `Generat: ${report.generatedAt}`,
    "",
    "## Rezultat",
    "",
    `- Audit structural: **${report.errors.length ? "FAIL" : "PASS"}** — ${report.siteAudit.files.length} fișiere, ${report.siteAudit.links.length} legături locale, ${report.siteAudit.anchorFragmentsChecked} fragmente, ${report.errors.length} erori.`,
    `- Graph canonical: **${report.graphAudit.errors.length ? "FAIL" : "PASS"}** — ${report.graphAudit.summary.canonicalPages} pagini, ${report.graphAudit.summary.canonicalEdges} muchii distincte, ${report.graphAudit.summary.zeroIncoming} pagini cu zero incoming.`,
    `- Inventar extern: **${records.size} URL-uri unice** (${publicExternal.length} publice, ${official.length} surse oficiale, ${publicDocuments.length} documente publice).`,
    `- Canale speciale: ${report.inventory.special.mailto.size} mailto, ${report.inventory.special.tel.size} tel, ${report.inventory.special.whatsapp.size} WhatsApp; documente locale: ${report.inventory.localDocuments.length}.`,
    `- Surse oficiale confirmate 404/410: **${report.confirmedOfficialFailures.length}**.`,
    "",
    "Un răspuns blocat, un timeout sau o provocare anti-bot nu justifică eliminarea unei surse oficiale. Aceste cazuri rămân separat ca `blocked_external`/`timeout` pentru verificare umană într-un browser obișnuit.",
    "",
    "## Clasificare HTTP externă",
    "",
    "| Clasificare | URL-uri |",
    "|---|---:|",
    ...classificationRows,
    "",
    "## Acoperirea suprafețelor",
    "",
    "| Suprafață inspectată | Referințe/blocuri |",
    "|---|---:|",
    ...surfaceRows,
    "",
    "FAQ-urile fără link nu sunt tratate ca eroare: toate blocurile vizibile sunt inspectate, iar orice link adăugat ulterior intră automat în inventar.",
    "",
    "## Integritate internă și surse",
    "",
    `- Linkuri interne rupte/redirectate: ${report.siteAudit.issues.length}.`,
    `- URL-uri interne legacy: ${report.graphAudit.summary.legacyLinks}.`,
    `- Pagini canonice orfane: ${report.graphAudit.summary.zeroIncoming}.`,
    `- Surse oficiale din registry: ${official.length}; surse prezente numai în registry: ${official.filter((record) => !record.occurrences.some((item) => item.route)).length}.`,
    `- Linkuri publice către documente oficiale/interne: ${publicDocuments.length + report.inventory.localDocuments.length}; textele descriptive sunt verificate contextual.`,
    "",
    "## URL-uri externe",
    "",
    "| Clasificare | HTTP | URL verificat | Destinație finală | Roluri | Exemplu sursă |",
    "|---|---:|---|---|---|---|",
    ...rows,
    "",
    "## Blocate sau neverificabile automat",
    "",
    ...(blocked.length ? blocked.map((result) => `- [${result.url}](${result.url}) — ${result.category}${result.status ? `, HTTP ${result.status}` : ""}${result.detail ? `, ${result.detail}` : ""}.`) : ["- Niciun caz în această rulare."]),
    "",
    "## Reproducere",
    "",
    "- `npm run check:links` — verificare deterministă pentru CI/build: canonicale, redirecturi, fragmente, mailto/tel/WhatsApp, documente și descrieri.",
    "- `npm run audit:links` — repetă verificarea și probează rețeaua externă, apoi rescrie acest raport.",
    "- Statusurile externe sunt un snapshot și trebuie interpretate împreună cu data raportului; `blocked_external` nu este echivalent cu 404.",
    ""
  ].join("\n");
}

function printSummary(report) {
  console.log(`Link integrity ${report.errors.length ? "FAIL" : "PASS"}: ${report.siteAudit.links.length} legături locale, ${report.inventory.records.size} URL-uri externe, ${report.siteAudit.anchorFragmentsChecked} fragmente.`);
  console.log(`Speciale: mailto=${report.inventory.special.mailto.size}, tel=${report.inventory.special.tel.size}, whatsapp=${report.inventory.special.whatsapp.size}, documente_locale=${report.inventory.localDocuments.length}.`);
  if (report.network.length) console.log(`HTTP extern: ${NETWORK_CATEGORIES.map((category) => `${category}=${report.classification[category]}`).join(", ")}.`);
  if (report.errors.length) console.error(report.errors.slice(0, 80).map((error) => `- ${error}`).join("\n"));
}

async function main() {
  const rootArgument = process.argv.find((argument) => argument.startsWith("--root="));
  const root = rootArgument ? rootArgument.slice("--root=".length) : DEFAULT_ROOT;
  const network = process.argv.includes("--network") && !process.argv.includes("--offline");
  const report = await auditLinkIntegrity({ root, network });
  printSummary(report);
  if (process.argv.includes("--report")) {
    const reportPath = path.join(root, DEFAULT_REPORT);
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, reportMarkdown(report), "utf8");
    console.log(path.relative(root, reportPath).split(path.sep).join("/"));
  }
  if (process.argv.includes("--check") && (report.errors.length || report.confirmedOfficialFailures.length)) process.exitCode = 1;
}

if (require.main === module) main().catch((error) => {
  console.error(`Link integrity audit failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = {
  DEFAULT_REPORT,
  NETWORK_CATEGORIES,
  auditLinkIntegrity,
  collectInventory,
  descriptiveDocumentLabel,
  isDocumentUrl,
  probeExternal,
  reportMarkdown
};
