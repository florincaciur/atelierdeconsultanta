"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { sitemapUrls: readSitemapUrls } = require("./sitemap-utils");

const SITE = "https://atelierdeconsultanta.ro";

// Keep source selection aligned with build-cloudflare-assets.js. These routes
// intentionally deploy the root HTML file when both legacy representations exist.
const CANONICAL_ROOT_HTML_ROUTES = new Set([
  "por-adr-nord-est",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "dr12-afir",
  "dr14-afir-ferme-mici",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "fondul-modernizare-energie-regenerabila-2026",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "start-up-nation-2026",
  "calculator-soc"
]);

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function comparableText(value) {
  return cleanText(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/gu, "")
    .replace(/[„”"'’.,:;!?()[\]{}]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .toLowerCase();
}

function typesOf(node) {
  if (!node || typeof node !== "object") return [];
  return Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]].filter(Boolean);
}

function hasType(node, type) {
  return typesOf(node).includes(type);
}

function graphNodes(data) {
  if (!data || typeof data !== "object") return [];
  if (Array.isArray(data)) return data.flatMap(graphNodes);
  if (Array.isArray(data["@graph"])) return data["@graph"].filter(Boolean);
  return [data];
}

function parseJsonLd($) {
  const blocks = [];
  $("script[type='application/ld+json']").each((index, element) => {
    const raw = $(element).html().trim();
    if (!raw) return;
    try {
      blocks.push({ index, raw, data: JSON.parse(raw), nodes: graphNodes(JSON.parse(raw)), error: "" });
    } catch (error) {
      blocks.push({ index, raw, data: null, nodes: [], error: error.message });
    }
  });
  return blocks;
}

function answerTextForContainer($, container, questionElement) {
  const direct = $(container).find("[itemprop='acceptedAnswer'] [itemprop='text'], .faq-a, .faq-answer").first();
  if (direct.length) return cleanText(direct.text());

  if ($(container).is("details")) {
    const clone = $(container).clone();
    clone.find("summary").first().remove();
    return cleanText(clone.text());
  }

  const answerBlocks = $(container).find("p, li").filter((_, element) => {
    return !$(element).is(questionElement) && !$(element).closest("h1,h2,h3,h4,h5,h6,summary").length;
  });
  return cleanText(answerBlocks.map((_, element) => $(element).text()).get().join(" "));
}

function isHiddenFromUsers($, element) {
  const lineage = $(element).parents().addBack();
  return lineage.toArray().some((node) => {
    const current = $(node);
    if (current.is("[hidden], [aria-hidden='true' i]")) return true;
    const style = current.attr("style") || "";
    return /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:;|$)/iu.test(style);
  });
}

function visibleFaqCandidates($) {
  const items = [];
  const containers = $(".faq-item, details:not([data-non-faq]), [itemprop='mainEntity'][itemtype*='Question']")
    .filter((_, container) => !$(container).closest("[data-long-form-toc], .editorial-governance").length);

  containers.each((_, container) => {
    if (isHiddenFromUsers($, container)) return;
    let questionElement = $(container)
      .children("[itemprop='name'], .faq-q, summary, h3, h4")
      .first();
    if (!questionElement.length && $(container).is("[itemprop='mainEntity'][itemtype*='Question']")) {
      questionElement = $(container).find("[itemprop='name'], .faq-q, summary, h3, h4").first();
    }
    const question = cleanText(questionElement.text());
    // A <details> element is not automatically a FAQ. Requiring an actual
    // question keeps source accordions and section wrappers out of FAQPage.
    if (!/[?？]$/u.test(question)) return;
    const answer = answerTextForContainer($, container, questionElement.get(0));
    if (!answer) return;
    items.push({ question, answer, element: container });
  });

  return items;
}

function visibleFaqItems($) {
  return visibleFaqCandidates($).map(({ question, answer }) => ({ question, answer }));
}

function sitemapRoutes(root) {
  return readSitemapUrls(root)
    .map((value) => new URL(value))
    .filter((url) => url.origin === SITE)
    .map((url) => url.pathname === "/" ? "/" : url.pathname.replace(/\/$/u, ""));
}

function fileForRoute(root, route) {
  if (route === "/") return path.join(root, "index.html");
  const relative = decodeURIComponent(route.replace(/^\//u, ""));
  const directoryIndex = path.join(root, relative, "index.html");
  const direct = path.join(root, `${relative}.html`);
  if (CANONICAL_ROOT_HTML_ROUTES.has(relative) && fs.existsSync(direct)) return direct;
  if (fs.existsSync(directoryIndex)) return directoryIndex;
  if (fs.existsSync(direct)) return direct;
  return directoryIndex;
}

function routeForFile(root, filePath) {
  const relative = path.relative(root, filePath).split(path.sep).join("/");
  if (relative === "index.html") return "/";
  if (relative.endsWith("/index.html")) return `/${relative.replace(/\/index\.html$/iu, "")}`;
  return `/${relative.replace(/\.html$/iu, "")}`;
}

function loadPageHints(root) {
  const hints = new Map();
  const editorialSource = JSON.parse(fs.readFileSync(path.join(root, "config", "editorial-pages.json"), "utf8"));
  const editorialBySlug = new Map((editorialSource.pages || []).map((page) => [page.slug, page]));
  const programs = JSON.parse(fs.readFileSync(path.join(root, "config", "seo-programs.json"), "utf8"));
  for (const page of programs.pages || []) {
    const route = `/${String(page.slug || "").replace(/^\//u, "")}`;
    const editorial = editorialBySlug.get(page.slug);
    hints.set(route, {
      type: page.type,
      schemaType: page.schemaType,
      updatedAt: page.updatedAt || editorial?.updatedAt || programs.updatedAt,
      publishedAt: page.publishedAt || editorial?.publishedAt || programs.updatedAt,
      lastReviewed: page.lastReviewed || page.lastVerifiedAt || editorial?.lastVerifiedAt || programs.lastReviewed
    });
  }

  const programmatic = JSON.parse(fs.readFileSync(path.join(root, "config", "seo-programmatic-pages.json"), "utf8"));
  for (const page of [...(programmatic.caenPages || []), ...(programmatic.regionalPages || [])]) {
    const slug = page.route || page.slug;
    if (!slug) continue;
    const route = `/${String(slug).replace(/^\//u, "")}`;
    hints.set(route, {
      type: page.type || "article",
      schemaType: page.schemaType || "Article",
      updatedAt: page.updatedAt || programmatic.updatedAt,
      publishedAt: page.publishedAt || programmatic.updatedAt,
      lastReviewed: page.lastReviewed || programmatic.lastReviewed
    });
  }

  // dateModified, sursa și atribuirea nu se deduc din build sau dintr-un
  // timestamp generic al colecției. Ele provin exclusiv din registrul de
  // guvernanță editorială, când înregistrarea este publicabilă.
  for (const [route, value] of hints) hints.set(route, { ...value, updatedAt: undefined });
  const governancePath = path.join(root, "config", "editorial-governance.json");
  if (fs.existsSync(governancePath)) {
    const governance = JSON.parse(fs.readFileSync(governancePath, "utf8"));
    for (const record of governance.records || []) {
      const route = record.route === "/" ? "/" : `/${String(record.route || "").replace(/^\/+|\/+$/gu, "")}`;
      const complete = record.governanceState === "public"
        && /^\d{4}-\d{2}-\d{2}$/u.test(String(record.lastMeaningfulUpdate || ""))
        && /^https:\/\//iu.test(String(record.officialSourceUrl || ""))
        && !String(record.sourceVersion || "").includes("DE_VALIDAT_UMAN");
      const current = hints.get(route) || {};
      hints.set(route, {
        ...current,
        updatedAt: complete ? record.lastMeaningfulUpdate : undefined,
        governance: complete ? record : undefined,
        citation: complete ? [{
          "@type": "CreativeWork",
          name: `${record.officialSourceName} — ${record.sourceVersion}`,
          url: record.officialSourceUrl
        }] : []
      });
    }
  }

  return hints;
}

module.exports = {
  SITE,
  cleanText,
  comparableText,
  fileForRoute,
  graphNodes,
  hasType,
  loadPageHints,
  parseJsonLd,
  routeForFile,
  sitemapRoutes,
  typesOf,
  visibleFaqCandidates,
  visibleFaqItems,
  isHiddenFromUsers
};
