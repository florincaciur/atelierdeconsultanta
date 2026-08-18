#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ORGANIZATION_ID,
  PAGE_KINDS,
  articleSchema,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  faqPageSchema,
  fundingProgramSchema,
  jsonLdGraph,
  organizationSchema,
  pageKindForPath,
  serviceSchema,
  webApplicationSchema,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const {
  loadProgramConfig,
  programForRoute
} = require("./program-factual-governance");
const { normalizeJsonLdValue } = require("./normalize-copy-ro");
const {
  SITE,
  cleanText,
  comparableText,
  fileForRoute,
  graphNodes,
  hasType,
  loadPageHints,
  sitemapRoutes,
  typesOf,
  visibleFaqItems
} = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const CONTENT_TYPES = new Set(["Article", "BlogPosting", "NewsArticle", "Service", "GovernmentService", "WebApplication"]);
const PROGRAMS = loadProgramConfig().programs;

function isBrandedOrganization(node) {
  if (!node || typeof node !== "object" || !hasType(node, "Organization")) return false;
  if (node["@id"] === ORGANIZATION_ID) return true;
  const name = comparableText(node.name || "");
  return name.includes("atelier de consultanta") || name === "faber" || name.startsWith("faber atelier de consultanta");
}

function canonicalizeReferences(value, topLevel = false) {
  if (Array.isArray(value)) return value.map((item) => canonicalizeReferences(item, false));
  if (!value || typeof value !== "object") return value;
  if (!topLevel && isBrandedOrganization(value)) return { "@id": ORGANIZATION_ID };
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, canonicalizeReferences(child, false)]));
}

function canonicalFromDocument($, route) {
  const href = $("link[rel='canonical']").first().attr("href");
  try {
    const parsed = new URL(href || route, SITE);
    if (parsed.origin === SITE) return `${SITE}${parsed.pathname === "/" ? "/" : parsed.pathname.replace(/\/$/u, "")}`;
  } catch {
    // Auditul va raporta separat un canonical invalid; sincronizarea folosește ruta.
  }
  return `${SITE}${route}`;
}

function firstNode(nodes, type) {
  return nodes.find((node) => hasType(node, type));
}

function firstContentNode(nodes) {
  return nodes.find((node) => typesOf(node).some((type) => CONTENT_TYPES.has(type)));
}

function inferPageKind(route, hints, nodes) {
  void nodes;
  return pageKindForPath(route, hints || {});
}

function editorialDates(nodes, hints) {
  void nodes;
  return {
    datePublished: hints?.publishedAt,
    dateModified: hints?.updatedAt
  };
}

function contentEntity(pageKind, options) {
  const { canonical, name, description, dates, existing } = options;
  if (pageKind === PAGE_KINDS.ARTICLE) {
    const schema = articleSchema({
      url: canonical,
      headline: existing?.headline || name,
      description,
      datePublished: dates.datePublished,
      dateModified: dates.dateModified
    });
    for (const key of ["about", "articleSection", "image", "keywords", "wordCount"]) {
      if (existing?.[key] !== undefined) schema[key] = existing[key];
    }
    if (Array.isArray(options.citation) && options.citation.length) schema.citation = options.citation;
    return schema;
  }

  if (pageKind === PAGE_KINDS.SERVICE) {
    const schema = serviceSchema({
      url: canonical,
      name,
      description,
      serviceType: existing?.serviceType || existing?.category || "Consultanță pentru fonduri europene"
    });
    if (Array.isArray(options.citation) && options.citation.length) schema.citation = options.citation;
    return schema;
  }

  if (pageKind === PAGE_KINDS.WEB_APPLICATION) {
    return webApplicationSchema({
      url: canonical,
      name,
      description,
      applicationCategory: "BusinessApplication",
      citation: options.citation
    });
  }

  return null;
}

function synchronizedGraph(html, route, hints) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const scripts = $("script[type='application/ld+json']");
  const parsedNodes = [];
  scripts.each((_, script) => {
    const raw = $(script).html().trim();
    if (!raw) return;
    parsedNodes.push(...graphNodes(JSON.parse(raw)));
  });

  const normalizedNodes = parsedNodes.map((node) => normalizeJsonLdValue(canonicalizeReferences(node, true)));
  const canonical = canonicalFromDocument($, route);
  const title = cleanText($("h1").first().text() || $("head > title").first().text());
  const description = cleanText($("meta[name='description']").attr("content") || firstNode(normalizedNodes, "WebPage")?.description || "");
  const pageKind = inferPageKind(route, hints, normalizedNodes);
  const dates = editorialDates(normalizedNodes, hints);
  const existingContent = pageKind === PAGE_KINDS.ARTICLE
    ? normalizedNodes.find((node) => hasType(node, "Article") || hasType(node, "BlogPosting") || hasType(node, "NewsArticle"))
    : firstContentNode(normalizedNodes);
  const factualProgram = programForRoute(route, PROGRAMS);

  const pageNode = webPageSchema({
    url: canonical,
    name: title,
    description,
    datePublished: dates.datePublished,
    dateModified: dates.dateModified,
    citation: hints?.citation
  });
  const content = contentEntity(pageKind, { canonical, name: title, description, dates, existing: existingContent, citation: hints?.citation });
  if (content && Array.isArray(hints?.citation) && hints.citation.length && !content.citation) content.citation = hints.citation;
  if (content) pageNode.mainEntity = { "@id": content["@id"] };
  if (factualProgram) {
    const programId = `${canonical}#funding-program`;
    pageNode.about = { "@id": programId };
    if (content) content.about = { "@id": programId };
  }

  const visibleFaq = visibleFaqItems($);
  const faq = visibleFaq.length >= 2
    ? faqPageSchema(visibleFaq.map((item) => [item.question, item.answer]), { minItems: 2 })
    : null;

  const nodes = [
    organizationSchema(),
    websiteSchema(),
    pageNode,
    breadcrumbSchema(breadcrumbItemsForPath(route, title)),
    content,
    factualProgram ? fundingProgramSchema(factualProgram) : null,
    faq
  ].filter(Boolean);

  return jsonLdGraph(normalizeJsonLdValue(nodes));
}

function replaceScripts(html, serialized) {
  let replaced = false;
  const output = html.replace(/<script\b[^>]*\btype=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/giu, (full) => {
    if (replaced) return "";
    replaced = true;
    const opening = full.match(/^<script\b[^>]*>/iu)?.[0] || '<script type="application/ld+json">';
    return `${opening}${serialized}</script>`;
  });
  return output.replace(/[ \t]+$/gmu, "");
}

function main() {
  const hints = loadPageHints(ROOT);
  const changed = [];
  const routes = [...new Set([
    ...sitemapRoutes(ROOT),
    ...PROGRAMS.filter((program) => program.publicationState === "public").map((program) => program.pageUrl)
  ])].sort((left, right) => left.localeCompare(right));
  for (const route of routes) {
    const primaryFile = fileForRoute(ROOT, route);
    if (!fs.existsSync(primaryFile)) throw new Error(`Lipsește fișierul pentru ruta indexabilă ${route}: ${primaryFile}`);
    const clean = route.replace(/^\//u, "");
    const files = [...new Set([
      primaryFile,
      route === "/" ? primaryFile : path.join(ROOT, `${clean}.html`),
      route === "/" ? primaryFile : path.join(ROOT, clean, "index.html")
    ])].filter((file) => fs.existsSync(file));
    for (const file of files) {
      const html = fs.readFileSync(file, "utf8");
      const $ = cheerio.load(html, { decodeEntities: false });
      if ($("body").attr("data-publication-state") === "pending_validation") continue;
      if (!$("script[type='application/ld+json']").length) {
        if (file === primaryFile) throw new Error(`Lipsește JSON-LD pe ruta indexabilă ${route}: ${path.relative(ROOT, file)}`);
        continue;
      }

      let serialized;
      try {
        serialized = synchronizedGraph(html, route, hints.get(route));
      } catch (error) {
        throw new Error(`${route}: ${error.message}`);
      }
      const next = replaceScripts(html, serialized);
      if (next === html) continue;
      changed.push(path.relative(ROOT, file).split(path.sep).join("/"));
      if (!CHECK_ONLY) fs.writeFileSync(file, next, "utf8");
    }
  }

  if (CHECK_ONLY && changed.length) {
    console.error(`JSON-LD nesincronizat în ${changed.length} fișiere:\n${changed.map((file) => `- ${file}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Sincronizate"} ${routes.length} pagini indexabile sau pagini publice de program; ${changed.length} ${CHECK_ONLY ? "neconforme" : "actualizate"}.`);
}

if (require.main === module) main();

module.exports = { synchronizedGraph };
