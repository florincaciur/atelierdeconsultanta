#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  BRAND_NAME,
  ORGANIZATION_ID,
  PAGE_KINDS,
  PROFESSIONAL_SERVICE_ID,
  WEBSITE_ID,
  articleSchema,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  faqPageSchema,
  fundingProgramSchema,
  jsonLdGraph,
  organizationSchema,
  pageKindForPath,
  professionalServiceSchema,
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
const PAGE_TYPES = new Set(["WebPage", "AboutPage", "ContactPage", "CollectionPage", "ProfilePage", "FAQPage"]);
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
  const configured = pageKindForPath(route, hints || {});
  if (configured !== PAGE_KINDS.WEB_PAGE) return configured;
  if (nodes.some((node) => hasType(node, "Article") || hasType(node, "BlogPosting") || hasType(node, "NewsArticle"))) return PAGE_KINDS.ARTICLE;
  return PAGE_KINDS.WEB_PAGE;
}

function editorialDates(nodes, hints) {
  const pageNode = nodes.find((node) => typesOf(node).some((type) => PAGE_TYPES.has(type) && type !== "FAQPage"));
  const contentNode = nodes.find((node) => ["Article", "BlogPosting", "NewsArticle", "Service", "WebApplication"].some((type) => hasType(node, type)))
    || firstContentNode(nodes);
  return {
    datePublished: hints?.publishedAt || contentNode?.datePublished || pageNode?.datePublished,
    dateModified: hints?.updatedAt || contentNode?.dateModified || pageNode?.dateModified
  };
}

function contentEntity(pageKind, options) {
  const { canonical, name, description, dates, existing } = options;
  if (pageKind === PAGE_KINDS.ARTICLE) {
    const schema = articleSchema({
      url: canonical,
      headline: existing?.headline || name,
      description,
      author: existing?.author,
      reviewer: existing?.reviewedBy,
      datePublished: dates.datePublished || dates.dateModified,
      dateModified: dates.dateModified || dates.datePublished
    });
    for (const key of ["about", "articleSection", "citation", "image", "keywords", "wordCount"]) {
      if (existing?.[key] !== undefined) schema[key] = existing[key];
    }
    return schema;
  }

  if (pageKind === PAGE_KINDS.SERVICE) {
    const schema = serviceSchema({
      url: canonical,
      name,
      description,
      serviceType: existing?.serviceType || existing?.category || "Consultanță pentru fonduri europene"
    });
    if (existing?.offers) schema.offers = existing.offers;
    return schema;
  }

  if (pageKind === PAGE_KINDS.WEB_APPLICATION) {
    return webApplicationSchema({
      url: canonical,
      name,
      description,
      applicationCategory: existing?.applicationCategory || "FinanceApplication"
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
    dateModified: dates.dateModified
  });
  const content = contentEntity(pageKind, { canonical, name: title, description, dates, existing: existingContent });
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

  const managed = (node) => {
    const types = typesOf(node);
    return isBrandedOrganization(node)
      || node["@id"] === WEBSITE_ID
      || node["@id"] === PROFESSIONAL_SERVICE_ID
      || /#funding-program$/.test(String(node["@id"] || ""))
      || types.includes("WebSite")
      || types.includes("ProfessionalService")
      || types.includes("LocalBusiness")
      || types.includes("BreadcrumbList")
      || types.includes("FAQPage")
      || types.some((type) => PAGE_TYPES.has(type))
      || types.some((type) => CONTENT_TYPES.has(type));
  };
  const preserved = normalizedNodes.filter((node) => !managed(node));
  const nodes = [
    organizationSchema(),
    websiteSchema(),
    route === "/" ? professionalServiceSchema() : null,
    pageNode,
    breadcrumbSchema(breadcrumbItemsForPath(route, title)),
    content,
    factualProgram ? fundingProgramSchema(factualProgram) : null,
    faq,
    ...preserved
  ].filter(Boolean);

  return jsonLdGraph(nodes);
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
  for (const route of sitemapRoutes(ROOT)) {
    const file = fileForRoute(ROOT, route);
    if (!fs.existsSync(file)) throw new Error(`Lipsește fișierul pentru ruta indexabilă ${route}: ${file}`);
    const html = fs.readFileSync(file, "utf8");
    const $ = cheerio.load(html, { decodeEntities: false });
    if (!$("script[type='application/ld+json']").length) throw new Error(`Lipsește JSON-LD pe ruta indexabilă ${route}`);

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

  if (CHECK_ONLY && changed.length) {
    console.error(`JSON-LD nesincronizat în ${changed.length} fișiere:\n${changed.map((file) => `- ${file}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${CHECK_ONLY ? "Verificate" : "Sincronizate"} ${sitemapRoutes(ROOT).length} pagini indexabile; ${changed.length} ${CHECK_ONLY ? "neconforme" : "actualizate"}.`);
}

if (require.main === module) main();

module.exports = { synchronizedGraph };
