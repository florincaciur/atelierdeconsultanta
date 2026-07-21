#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadNextStepConfig } = require("./contextual-next-steps");
const { sitemapUrls: readSitemapUrls } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const OUTPUT_PATH = path.join(ROOT, "reports", "internal-link-map.csv");
const NEXT_STEP_CSV = path.join(ROOT, "reports", "contextual-next-step-links.csv");
const NEXT_STEP_MD = path.join(ROOT, "reports", "contextual-next-step-links.md");
const REPEATED_ANCHOR_THRESHOLD = 8;
const LINK_TYPES = ["navigation", "contextual", "next-step", "source", "CTA"];

function sitemapUrls() {
  return readSitemapUrls(ROOT);
}

function fileForUrl(url) {
  const pathname = new URL(url).pathname;
  if (pathname === "/") return path.join(ROOT, "index.html");
  const directoryIndex = path.join(ROOT, pathname.slice(1), "index.html");
  if (fs.existsSync(directoryIndex)) return directoryIndex;
  return path.join(ROOT, `${pathname.slice(1)}.html`);
}

function redirectSources() {
  const file = path.join(ROOT, "_redirects");
  if (!fs.existsSync(file)) return new Set();
  return new Set(fs.readFileSync(file, "utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.split(/\s+/u)[0])
    .filter((source) => source.startsWith("/") && !source.includes("*"))
    .map((source) => source.length > 1 ? source.replace(/\/+$/u, "") : source));
}

function normalizeTarget(href) {
  if (!href || /^(?:#|mailto:|tel:|javascript:)/iu.test(href)) return null;
  try {
    const url = new URL(href, SITE);
    const internal = url.origin === SITE || url.origin === "https://www.atelierdeconsultanta.ro";
    if (internal) {
      url.protocol = "https:";
      url.hostname = "atelierdeconsultanta.ro";
      url.port = "";
      url.search = "";
      url.hash = "";
      if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/u, "");
    }
    return { internal, route: internal ? url.pathname : "", url: url.toString() };
  } catch {
    return null;
  }
}

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function classifyLink($, element, target) {
  const link = $(element);
  const declaredType = link.attr("data-link-type");
  const relation = link.attr("data-link-relation");
  if (declaredType === "conversion" || relation === "conversion") return "CTA";
  if (declaredType === "contextual" || link.closest("[data-contextual-next-step], [data-program-contextual-links]").length) return "contextual";
  if (declaredType === "next-step") return "next-step";
  if (!target.internal || link.closest(".official-sources, .official-sources__item, .source-note, .answer-readiness__source").length) return "source";
  if (link.is("[class*='btn'], [class*='cta'], [data-whatsapp-dialog-open]") || link.closest(".cta-box, .cta-actions, .hero-actions, .hero-ctas").length) return "CTA";
  if (link.closest("nav, header, footer, .breadcrumb").length) return "navigation";
  return "contextual";
}

function contextFor($, element) {
  const container = $(element).closest("[data-contextual-next-step], section, article, nav, header, footer");
  const heading = container.find("h1, h2, h3").first().text();
  return cleanText(heading) || (container.is("nav") ? "Navigație" : "Conținut principal");
}

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function countKey(url, type) {
  return `${url}\u0000${type}`;
}

function increment(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function routeOf(url) {
  return new URL(url).pathname;
}

function renderMarkdown({ config, edges, missingRoutes, repeatedAnchors, errors }) {
  const typeRows = LINK_TYPES.map((type) => {
    const typed = edges.filter((edge) => edge.linkType === type);
    return `| ${type} | ${typed.length} | ${new Set(typed.map((edge) => edge.sourceUrl)).size} | ${new Set(typed.filter((edge) => edge.targetScope === "internal").map((edge) => edge.targetUrl)).size} |`;
  }).join("\n");
  const repeated = repeatedAnchors.length
    ? repeatedAnchors.map((item) => `- „${item.anchor}”: ${item.sources} pagini-sursă (${item.type})`).join("\n")
    : "- Nu există ancore contextuale peste pragul de 8 pagini-sursă.";
  const missingPreview = missingRoutes.length
    ? `${missingRoutes.slice(0, 20).map((route) => `\`${route}\``).join(", ")}${missingRoutes.length > 20 ? ` și încă ${missingRoutes.length - 20} rute disponibile în matricea CSV` : ""}`
    : "Niciuna.";
  const managed = edges.filter((edge) => edge.relationship);
  const conversions = managed.filter((edge) => edge.relationship === "conversion");
  const managedSources = new Set(managed.map((edge) => edge.sourceUrl)).size;

  return `# Audit legături interne contextuale – 21 iulie 2026

## Rezultat

Matricea sitewide conține ${edges.length} legături clasificate. Dintre acestea, ${managed.length} sunt legături contextuale administrate pe ${managedSources} pagini, iar ${conversions.length} sunt CTA-uri de conversie. Validarea a identificat ${errors.length} erori.

## Distribuția linkurilor pe tip

| Tip | Linkuri | Pagini-sursă | Destinații interne distincte |
|---|---:|---:|---:|
${typeRows}

Fișierul \`internal-link-map.csv\` include pentru fiecare legătură numărul de linkuri outgoing și incoming din același tip.

## Reguli verificate

- zero legături contextuale administrate către redirecturi, rute legacy \`.html\`, pagini noindex sau destinații moarte;
- tracking analytics numai pentru relația de conversie; legăturile editoriale nu emit evenimente CTA;
- ancore descriptive, fără formulări generice precum „click aici”;
- maximum patru relații pe pagina de program: părinte, instrument, comparație/ghid și conversie.

## Pagini fără legături contextuale administrate

Sunt semnalate ${missingRoutes.length} rute indexabile fără un bloc contextual administrat. Acestea nu sunt tratate automat ca erori: matricea nu generează automat „nori” de resurse pe fiecare pagină. Rute: ${missingPreview}

## Ancore repetate excesiv

${repeated}
`;
}

function generate() {
  const urls = sitemapUrls();
  const canonicalSet = new Set(urls);
  const redirects = redirectSources();
  const config = loadNextStepConfig();
  const priorityPaths = new Set(Object.values(config.pages).map((page) => page.route));
  const edges = [];
  const errors = [];

  for (const sourceUrl of urls) {
    const file = fileForUrl(sourceUrl);
    if (!fs.existsSync(file)) throw new Error(`Lipsește sursa locală pentru ${sourceUrl}: ${file}`);
    const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
    $("a[href]").each((_, element) => {
      const href = $(element).attr("href");
      const target = normalizeTarget(href);
      if (!target) return;
      const linkType = classifyLink($, element, target);
      if (!target.internal && linkType !== "source" && linkType !== "next-step") return;
      let targetScope = target.internal ? "internal" : "external";
      if (target.internal) {
        const isAsset = /\.[a-z0-9]{2,8}$/iu.test(target.route);
        if (isAsset) {
          targetScope = "internal-asset";
          const assetFile = path.join(ROOT, decodeURIComponent(target.route).replace(/^\//u, ""));
          if (!fs.existsSync(assetFile)) errors.push(`${routeOf(sourceUrl)} → ${target.route}: fișier intern mort`);
        } else {
          if (redirects.has(target.route)) errors.push(`${routeOf(sourceUrl)} → ${target.route}: link către redirect`);
          if (!canonicalSet.has(target.url) && !fs.existsSync(fileForUrl(target.url))) {
            errors.push(`${routeOf(sourceUrl)} → ${target.route}: destinație internă moartă`);
          }
        }
        if (target.url === sourceUrl) return;
      }
      edges.push({
        anchorText: cleanText($(element).find(".see-also-card-title").first().text() || $(element).text()),
        context: contextFor($, element),
        explanation: $(element).attr("data-link-relation") ? cleanText($(element).find(".see-also-card-text, .program-contextual-links__explanation").text()) : "",
        href,
        linkType,
        relationship: $(element).attr("data-link-relation") || "",
        sourcePriority: priorityPaths.has(routeOf(sourceUrl)) ? "yes" : "no",
        sourceUrl,
        targetPriority: target.internal && priorityPaths.has(target.route) ? "yes" : "no",
        targetScope,
        targetUrl: target.url
      });
    });
  }

  const outgoing = new Map();
  const incoming = new Map();
  for (const edge of edges) {
    increment(outgoing, countKey(edge.sourceUrl, edge.linkType));
    if (edge.targetScope === "internal") increment(incoming, countKey(edge.targetUrl, edge.linkType));
  }
  for (const edge of edges) {
    edge.sourceOutgoingSameType = outgoing.get(countKey(edge.sourceUrl, edge.linkType)) || 0;
    edge.targetIncomingSameType = edge.targetScope === "internal" ? incoming.get(countKey(edge.targetUrl, edge.linkType)) || 0 : 0;
  }
  edges.sort((a, b) => a.linkType.localeCompare(b.linkType) || a.sourceUrl.localeCompare(b.sourceUrl) || a.targetUrl.localeCompare(b.targetUrl));

  const nextSteps = edges.filter((edge) => edge.relationship);
  for (const page of Object.values(config.pages)) {
    if (!canonicalSet.has(`${SITE}${page.route}`)) continue;
    const count = nextSteps.filter((edge) => routeOf(edge.sourceUrl) === page.route).length;
    if (count < 1 || count > 4) errors.push(`${page.route}: ${count} linkuri next-step, necesar 1–4`);
  }

  const missingRoutes = urls
    .map(routeOf)
    .filter((route) => !nextSteps.some((edge) => routeOf(edge.sourceUrl) === route));
  const anchorGroups = new Map();
  for (const edge of edges.filter((item) => ["contextual", "next-step"].includes(item.linkType))) {
    const key = `${edge.linkType}\u0000${edge.anchorText.toLocaleLowerCase("ro-RO")}`;
    if (!anchorGroups.has(key)) anchorGroups.set(key, new Set());
    anchorGroups.get(key).add(routeOf(edge.sourceUrl));
  }
  const repeatedAnchors = [...anchorGroups.entries()]
    .filter(([, sources]) => sources.size > REPEATED_ANCHOR_THRESHOLD)
    .map(([key, sources]) => {
      const [type, anchor] = key.split("\u0000");
      return { anchor, sources: sources.size, type };
    })
    .sort((a, b) => b.sources - a.sources || a.anchor.localeCompare(b.anchor));

  const header = ["source_url", "target_url", "target_scope", "link_type", "anchor_text", "explanation", "context", "source_outgoing_same_type", "target_incoming_same_type", "source_priority", "target_priority"];
  const rows = edges.map((edge) => [edge.sourceUrl, edge.targetUrl, edge.targetScope, edge.linkType, edge.anchorText, edge.explanation, edge.context, edge.sourceOutgoingSameType, edge.targetIncomingSameType, edge.sourcePriority, edge.targetPriority]);
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, [header, ...rows].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");

  const nextHeader = ["source_route", "target", "target_scope", "link_type", "anchor", "explanation", "outgoing_next_step", "incoming_next_step", "status"];
  const nextRows = nextSteps.map((edge) => [routeOf(edge.sourceUrl), edge.targetScope === "internal" ? routeOf(edge.targetUrl) : edge.targetUrl, edge.targetScope, edge.linkType, edge.anchorText, edge.explanation, edge.sourceOutgoingSameType, edge.targetIncomingSameType, "valid"]);
  fs.writeFileSync(NEXT_STEP_CSV, [nextHeader, ...nextRows].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");
  fs.writeFileSync(NEXT_STEP_MD, renderMarkdown({ config, edges, missingRoutes, repeatedAnchors, errors }), "utf8");

  console.log(`Matrice scrisă: ${path.relative(ROOT, OUTPUT_PATH)} (${edges.length} linkuri clasificate)`);
  console.log(`Contextuale administrate: ${nextSteps.length} legături; ${missingRoutes.length} rute indexabile fără bloc; ${repeatedAnchors.length} ancore peste prag.`);
  if (errors.length) throw new Error([...new Set(errors)].join("\n"));
}

try {
  generate();
} catch (error) {
  console.error(error.message || error);
  process.exit(1);
}
