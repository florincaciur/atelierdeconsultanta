#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  breadcrumbItemsForRoute,
  breadcrumbRouteEntries,
  knownRoutes,
  normalizeRoute
} = require("./breadcrumb-registry");
const { breadcrumbSchema, serializeJsonLd } = require("./schema-helpers");
const { fileForRoute, graphNodes, hasType, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK = process.argv.includes("--check");
const STYLE_LINK = '<link rel="stylesheet" href="/assets/breadcrumbs.css">';
const START = "<!-- BREADCRUMB_START -->";
const END = "<!-- BREADCRUMB_END -->";

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function renderBreadcrumb(route, currentName) {
  const entries = breadcrumbRouteEntries(route, currentName);
  if (!entries.length) return "";
  const items = entries.map((entry) => entry.current
    ? `      <li aria-current="page">${escapeHtml(entry.name)}</li>`
    : `      <li><a href="${escapeHtml(entry.route)}">${escapeHtml(entry.name)}</a></li>`);
  return [
    START,
    '  <nav class="breadcrumb" aria-label="Breadcrumb" data-breadcrumb>',
    "    <ol>",
    ...items,
    "    </ol>",
    "  </nav>",
    END
  ].join("\n");
}

function removeExistingVisibleBreadcrumb(html) {
  return html
    .replace(new RegExp(`${START}[\\s\\S]*?${END}`, "giu"), "")
    .replace(/\s*<nav\b[^>]*(?:data-breadcrumb|class=["'][^"']*\bbreadcrumb\b[^"']*["'])[^>]*>[\s\S]*?<\/nav>\s*/iu, "\n")
    .replace(/\s*<div\b[^>]*class=["'][^"']*\bbreadcrumb\b[^"']*["'][^>]*>[\s\S]*?<\/div>\s*/iu, "\n");
}

function insertVisibleBreadcrumb(html, markup) {
  if (!markup) return html;
  if (html.includes("<!-- GLOBAL_HEADER_END -->")) {
    return html.replace("<!-- GLOBAL_HEADER_END -->", `<!-- GLOBAL_HEADER_END -->\n${markup}`);
  }
  const hero = /<(?:header|section)\b[^>]*class=["'][^"']*\bhero\b[^"']*["'][^>]*>/iu;
  if (hero.test(html)) return html.replace(hero, `${markup}\n$&`);
  const main = /<main\b[^>]*>/iu;
  if (main.test(html)) return html.replace(main, `$&\n${markup}`);
  return html.replace(/<body\b[^>]*>/iu, `$&\n${markup}`);
}

function syncVisibleBreadcrumb(html, markup) {
  const managedPattern = new RegExp(`${START}[\\s\\S]*?${END}`, "giu");
  if (markup && managedPattern.test(html)) {
    return html.replace(new RegExp(`${START}[\\s\\S]*?${END}`, "giu"), markup);
  }
  return insertVisibleBreadcrumb(removeExistingVisibleBreadcrumb(html), markup);
}

function syncStylesheet(html, route) {
  const matches = html.match(/<link\b[^>]*href=["']\/assets\/breadcrumbs\.css["'][^>]*>/giu) || [];
  if (route !== "/" && matches.length === 1) return html;
  const withoutDuplicates = html.replace(/\s*<link\b[^>]*href=["']\/assets\/breadcrumbs\.css["'][^>]*>\s*/giu, "\n");
  if (route === "/") return withoutDuplicates;
  return withoutDuplicates.replace(/<\/head>/iu, `  ${STYLE_LINK}\n</head>`);
}

function replaceJsonLd(html, route, currentName, allowMissing = false) {
  const desired = breadcrumbSchema(breadcrumbItemsForRoute(route, currentName));
  let managed = false;
  let validBlockCount = 0;
  const output = html.replace(/(<script\b[^>]*type=["']application\/ld\+json["'][^>]*>)([\s\S]*?)(<\/script>)/giu, (block, open, raw, close) => {
    let data;
    try {
      data = JSON.parse(raw.trim());
    } catch {
      return block;
    }
    validBlockCount += 1;
    const filtered = graphNodes(data).filter((node) => !hasType(node, "BreadcrumbList"));
    if (!managed && desired) {
      const pageIndex = filtered.findIndex((node) => hasType(node, "WebPage"));
      filtered.splice(pageIndex >= 0 ? pageIndex + 1 : filtered.length, 0, desired);
    }
    managed = true;
    const synchronized = {
      "@context": data["@context"] || "https://schema.org",
      "@graph": filtered
    };
    return `${open}${serializeJsonLd(synchronized)}${close}`;
  });

  if (!validBlockCount) {
    if (allowMissing) return output;
    throw new Error(`${route}: lipsește un bloc JSON-LD valid`);
  }
  return output;
}

function pageTitle(html) {
  const $ = cheerio.load(html);
  return $("h1").first().text().replace(/\s+/gu, " ").trim();
}

function canonicalRoute(html) {
  const $ = cheerio.load(html);
  const canonical = $("link[rel='canonical']").first().attr("href");
  return canonical ? normalizeRoute(canonical) : null;
}

function synchronizedHtml(source, route) {
  const currentName = pageTitle(source);
  const document = cheerio.load(source);
  const pendingValidation = document("body").attr("data-publication-state") === "pending_validation";
  let output = syncVisibleBreadcrumb(source, renderBreadcrumb(route, currentName));
  output = syncStylesheet(output, route);
  output = replaceJsonLd(output, route, currentName, pendingValidation);
  return output;
}

function main() {
  const routes = [...new Set([...sitemapRoutes(ROOT), ...knownRoutes()])].sort();
  const changed = [];
  const skipped = [];

  for (const route of routes) {
    const file = fileForRoute(ROOT, route);
    if (!fs.existsSync(file)) {
      skipped.push(`${route}: fișier inexistent`);
      continue;
    }
    const source = fs.readFileSync(file, "utf8");
    const pageCanonical = canonicalRoute(source);
    if (pageCanonical !== route) {
      skipped.push(`${route}: canonical ${pageCanonical || "lipsește"}`);
      continue;
    }
    const output = synchronizedHtml(source, route);
    if (output === source) continue;
    changed.push(path.relative(ROOT, file).replace(/\\/gu, "/"));
    if (!CHECK) fs.writeFileSync(file, output, "utf8");
  }

  if (CHECK && changed.length) {
    console.error(`Breadcrumb sync FAIL: ${changed.length} pagini nesincronizate.`);
    console.error(changed.slice(0, 20).map((file) => `- ${file}`).join("\n"));
    process.exit(1);
  }
  console.log(`Breadcrumb sync ${CHECK ? "PASS" : "OK"}: ${routes.length - skipped.length} pagini verificate, ${changed.length} actualizate, ${skipped.length} rute nepublicate/absente.`);
}

if (require.main === module) main();

module.exports = {
  renderBreadcrumb,
  synchronizedHtml
};
