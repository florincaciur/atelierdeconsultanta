#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const GLOBAL_HEADER_PATTERN = /<!-- GLOBAL_HEADER_START -->[\s\S]*?<!-- GLOBAL_HEADER_END -->/iu;
const GLOBAL_HEADER_PLACEHOLDER = "<!-- ACCESSIBILITY_GLOBAL_HEADER_PLACEHOLDER -->";

function moveMisplacedHeadElements($) {
  const misplaced = $("body > meta, body > title, body > base, body > link[rel='canonical'], body > link[rel='icon'], body > link[rel='preconnect'], body > link[rel='dns-prefetch'], body > link[rel='stylesheet']:not([href^='/assets/global-header.css']), body > script[type='application/ld+json']");
  if (!misplaced.length) return;
  $("head").append(misplaced);
}

function wrapEditorialContent($, route) {
  const bodyChildren = $("body").children();
  const first = bodyChildren.filter(".post-hero, .post-container, .article-hero, .article-layout").first();
  const last = bodyChildren.filter(".post-container, .article-layout, .vezi-si-section").last();
  if (!first.length || !last.length) {
    throw new Error(`${route}: lipsește un main și nu există un segment editorial sigur de încadrat.`);
  }

  const start = bodyChildren.index(first);
  const end = bodyChildren.index(last);
  if (start < 0 || end < start) throw new Error(`${route}: segment editorial invalid.`);
  bodyChildren.slice(start, end + 1).wrapAll('<main id="main-content" tabindex="-1"></main>');
}

function ensureMainAndSkipLink($, route) {
  let mains = $("main");
  if (!mains.length) {
    wrapEditorialContent($, route);
    mains = $("main");
  }
  if (mains.length !== 1) throw new Error(`${route}: sunt prezente ${mains.length} elemente main.`);

  const main = mains.first();
  $("#main-content").not(main).removeAttr("id");
  main.attr("id", "main-content").attr("tabindex", "-1");

  const skipLinks = $("a.skip-link");
  const skip = skipLinks.first();
  if (skip.length) {
    skip.attr("href", "#main-content").addClass("global-skip-link");
    skipLinks.slice(1).remove();
  } else {
    $("body").prepend('<a class="skip-link global-skip-link" href="#main-content">Sari la conținut</a>\n');
  }
}

function ensureResponsiveMetadataAndRegions($) {
  if (!$("meta[name='viewport']").length) {
    $("head").append('\n  <meta name="viewport" content="width=device-width, initial-scale=1.0">');
  }
  $(".calc-section").has("table").each((_, element) => {
    const region = $(element);
    const heading = region.find("h2[id], h3[id]").first();
    region.attr("role", "region").attr("tabindex", "0");
    if (heading.length) region.attr("aria-labelledby", heading.attr("id"));
    else if (!region.attr("aria-label")) region.attr("aria-label", "Tabel de calcul");
  });
}

function deduplicateIds($) {
  const seen = new Set();
  const suffixes = new Map();
  $("[id]").each((_, element) => {
    const node = $(element);
    const id = node.attr("id");
    if (!id || !seen.has(id)) {
      if (id) seen.add(id);
      return;
    }
    let suffix = suffixes.get(id) || 2;
    let candidate = `${id}-${suffix}`;
    while (seen.has(candidate)) candidate = `${id}-${++suffix}`;
    suffixes.set(id, suffix + 1);
    node.attr("id", candidate);
    seen.add(candidate);
  });
}

function synchronize(html, route) {
  const globalHeader = html.match(GLOBAL_HEADER_PATTERN)?.[0] || "";
  const source = globalHeader ? html.replace(GLOBAL_HEADER_PATTERN, GLOBAL_HEADER_PLACEHOLDER) : html;
  const $ = cheerio.load(source, { decodeEntities: false });
  if (!$('html[lang]').length) $("html").attr("lang", "ro");
  moveMisplacedHeadElements($);
  ensureMainAndSkipLink($, route);
  ensureResponsiveMetadataAndRegions($);
  deduplicateIds($);
  const output = $.html();
  return globalHeader ? output.replace(GLOBAL_HEADER_PLACEHOLDER, globalHeader) : output;
}

function main() {
  const routes = sitemapRoutes(ROOT);
  const changed = [];
  for (const route of routes) {
    const file = fileForRoute(ROOT, route);
    if (!fs.existsSync(file)) throw new Error(`${route}: fișierul canonic lipsește (${path.relative(ROOT, file)}).`);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, route);
    if (after === before) continue;
    changed.push(path.relative(ROOT, file));
    if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
  }
  if (CHECK_ONLY && changed.length) throw new Error(`Landmark-uri nesincronizate: ${changed.join(", ")}`);
  console.log(`Accesibilitate structurală: ${routes.length} rute verificate, ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { deduplicateIds, ensureMainAndSkipLink, ensureResponsiveMetadataAndRegions, moveMisplacedHeadElements, synchronize, wrapEditorialContent };
