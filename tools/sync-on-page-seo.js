#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { SITE, cleanText, fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const DEFAULT_SHARE_IMAGE = `${SITE}/og-image.jpg`;

function escapeAttribute(value) {
  return String(value).replace(/&/gu, "&amp;").replace(/"/gu, "&quot;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

function metaIdentifier(tag) {
  const match = tag.match(/\b(?:name|property)\s*=\s*(["'])(.*?)\1/iu);
  return match ? match[2].toLowerCase() : "";
}

function setContent(tag, value) {
  if (/\bcontent\s*=\s*(["']).*?\1/iu.test(tag)) return tag.replace(/\bcontent\s*=\s*(["']).*?\1/iu, `content="${escapeAttribute(value)}"`);
  return tag.replace(/\s*\/?\s*>$/u, ` content="${escapeAttribute(value)}">`);
}

function syncMeta(head, identifier, attributeName, value) {
  let found = 0;
  let output = head.replace(/<meta\b[^>]*>/giu, (tag) => {
    if (metaIdentifier(tag) !== identifier.toLowerCase()) return tag;
    found += 1;
    return found === 1 ? setContent(tag, value) : "";
  });
  if (!found) output = output.replace(/\s*<\/head>/iu, `\n  <meta ${attributeName}="${identifier}" content="${escapeAttribute(value)}">\n</head>`);
  return output;
}

function firstMeta($, identifier) {
  const element = $("head meta").filter((_, node) => {
    const current = $(node);
    return String(current.attr("name") || current.attr("property") || "").toLowerCase() === identifier.toLowerCase();
  }).first();
  return cleanText(element.attr("content"));
}

function syncHeadingHierarchy(html) {
  return html.replace(
    /(<section\b[^>]*\bclass=["'][^"']*\bdesign-card-grid\b[^"']*["'][^>]*>)(\s*)(?=<article\b[^>]*\bclass=["'][^"']*\bdesign-card\b)/giu,
    "$1$2<h2 class=\"design-card-grid__title\">Repere pentru verificare</h2>$2"
  );
}

function syncHtml(html) {
  const headMatch = html.match(/<head\b[^>]*>[\s\S]*?<\/head>/iu);
  if (!headMatch) throw new Error("lipsește <head>");
  const originalHead = headMatch[0];
  const $ = cheerio.load(html, { decodeEntities: false });
  const title = cleanText($("head > title").first().text());
  const description = firstMeta($, "description");
  const canonical = cleanText($("head link[rel='canonical' i]").first().attr("href"));
  if (!title || !description || !canonical) throw new Error("title, meta description sau canonical lipsă");

  const h1 = cleanText($("h1").first().text());
  const shareAlt = `${h1 || title} — FABER`;
  const ogTitle = firstMeta($, "og:title") || title;
  const ogDescription = firstMeta($, "og:description") || description;
  const ogType = firstMeta($, "og:type") || ($("article").length ? "article" : "website");
  const ogImage = firstMeta($, "og:image") || DEFAULT_SHARE_IMAGE;
  const ogImageAlt = firstMeta($, "og:image:alt") || shareAlt;
  const hasTwitter = $("head meta").toArray().some((node) => /^twitter:/iu.test($(node).attr("name") || $(node).attr("property") || ""));

  let head = originalHead;
  for (const [field, value] of [["og:title", ogTitle], ["og:description", ogDescription], ["og:type", ogType],
    ["og:url", canonical], ["og:image", ogImage], ["og:image:alt", ogImageAlt]]) {
    head = syncMeta(head, field, "property", value);
  }
  if (hasTwitter) {
    for (const [field, value] of [
      ["twitter:card", firstMeta($, "twitter:card") || "summary_large_image"],
      ["twitter:title", firstMeta($, "twitter:title") || ogTitle],
      ["twitter:description", firstMeta($, "twitter:description") || ogDescription],
      ["twitter:image", firstMeta($, "twitter:image") || ogImage],
      ["twitter:image:alt", firstMeta($, "twitter:image:alt") || ogImageAlt]
    ]) head = syncMeta(head, field, "name", value);
  }
  return syncHeadingHierarchy(html.replace(originalHead, head));
}

function syncSite(root = ROOT, checkOnly = false) {
  const routes = sitemapRoutes(root);
  const changed = [];
  for (const route of routes) {
    const file = fileForRoute(root, route);
    const input = fs.readFileSync(file, "utf8");
    const output = syncHtml(input);
    if (input === output) continue;
    changed.push(path.relative(root, file).split(path.sep).join("/"));
    if (!checkOnly) fs.writeFileSync(file, output, "utf8");
  }
  return { routes: routes.length, changed };
}

function main() {
  const checkOnly = process.argv.includes("--check");
  const result = syncSite(ROOT, checkOnly);
  if (checkOnly && result.changed.length) {
    console.error(`Metadata on-page nesincronizată în ${result.changed.length} fișiere:\n${result.changed.map((file) => `- ${file}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${checkOnly ? "Verificate" : "Sincronizate"} ${result.routes} rute; ${result.changed.length} ${checkOnly ? "abateri" : "fișiere actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message || error); process.exitCode = 1; }
}
module.exports = { syncHeadingHierarchy, syncHtml, syncMeta, syncSite };
