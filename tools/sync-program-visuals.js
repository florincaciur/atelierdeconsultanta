#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute } = require("./structured-data-utils");
const { sitemapUrls } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const STYLE_HREF = "/assets/program-visuals.css?v=20260818-1";
const START = "PROGRAM_VISUAL_START";
const END = "PROGRAM_VISUAL_END";

function routes() {
  return sitemapUrls(ROOT, "sitemap-programs.xml")
    .map((value) => new URL(value).pathname.replace(/\/$/, "") || "/");
}

function filesForRoute(route) {
  if (route === "/") return [path.join(ROOT, "index.html")];
  const relative = decodeURIComponent(route.replace(/^\//u, ""));
  return [...new Set([
    fileForRoute(ROOT, route),
    path.join(ROOT, relative, "index.html"),
    path.join(ROOT, `${relative}.html`)
  ])].filter((file) => fs.existsSync(file));
}

function accessibleMainSvg($) {
  return $("main svg[role='img']").toArray().some((svg) => {
    const node = $(svg);
    const hidden = node.attr("aria-hidden") === "true" || node.parents("[aria-hidden='true']").length > 0;
    const named = Boolean(node.attr("aria-label") || node.attr("aria-labelledby") || node.find("title").text().trim());
    const described = Boolean(node.attr("aria-describedby") || node.find("desc").text().trim());
    return !hidden && named && described;
  });
}

function visual(route) {
  const id = `program-visual-${route.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "home"}`;
  return `<!-- ${START} -->
<figure class="program-visual" data-program-visual="decision-flow">
  <figcaption class="program-visual__copy"><strong>Traseul verificării proiectului</strong><span>Structură orientativă, aplicată documentelor programului</span></figcaption>
  <svg viewBox="0 0 920 190" role="img" aria-labelledby="${id}-title ${id}-desc">
    <title id="${id}-title">Eligibilitate, investiție, buget și depunere</title>
    <desc id="${id}-desc">Patru etape conectate arată ordinea recomandată pentru verificarea unui proiect de finanțare.</desc>
    <path class="program-visual__track" d="M95 88H825" fill="none" stroke="#8eb7a5" stroke-width="6" stroke-linecap="round"/>
    <g class="program-visual__marker" transform="translate(95 88)"><circle r="38" fill="#1f6d50"/><text y="5" text-anchor="middle" fill="#fff" font-size="16" font-weight="800">01</text></g>
    <g class="program-visual__marker" transform="translate(338 88)"><circle r="38" fill="#2c8060"/><text y="5" text-anchor="middle" fill="#fff" font-size="16" font-weight="800">02</text></g>
    <g class="program-visual__marker" transform="translate(581 88)"><circle r="38" fill="#3a9270"/><text y="5" text-anchor="middle" fill="#fff" font-size="16" font-weight="800">03</text></g>
    <g class="program-visual__marker" transform="translate(825 88)"><circle r="38" fill="#d69b2e"/><text y="5" text-anchor="middle" fill="#18322a" font-size="16" font-weight="800">04</text></g>
    <g fill="#18322a" font-size="15" font-weight="700" text-anchor="middle"><text x="95" y="154">Eligibilitate</text><text x="338" y="154">Investiție</text><text x="581" y="154">Buget</text><text x="825" y="154">Depunere</text></g>
  </svg>
</figure>
<!-- ${END} -->`;
}

function synchronize(html, route) {
  const startPattern = new RegExp(`\\s*<!--\\s*${START}\\s*-->[\\s\\S]*?<!--\\s*${END}\\s*-->\\s*`, "g");
  let current = html.replace(startPattern, "\n");
  if (!/<link\b[^>]*href=["']\/assets\/program-visuals\.css/iu.test(current)) {
    current = current.replace(/<\/head>/iu, `  <link rel="stylesheet" href="${STYLE_HREF}">\n</head>`);
  }
  const $ = cheerio.load(current, { decodeEntities: false });
  const needsGenericVisual = !accessibleMainSvg($);
  if (needsGenericVisual) {
    const mainOpen = /<main\b[^>]*>/iu.exec(current);
    if (!mainOpen) throw new Error(`${route}: lipsește elementul main`);
    const insertionIndex = mainOpen.index + mainOpen[0].length;
    // Insert immediately inside <main>. This keeps the generated figure
    // outside every independently regenerated section marker and preserves
    // the rest of the HTML byte-for-byte, including the global header.
    current = `${current.slice(0, insertionIndex)}\n${visual(route)}\n${current.slice(insertionIndex)}`;
  }
  return current;
}

function main() {
  const changed = [];
  for (const route of routes()) {
    const files = filesForRoute(route);
    if (!files.length) throw new Error(`${route}: fișierul canonic lipsește`);
    for (const file of files) {
      const before = fs.readFileSync(file, "utf8");
      const after = synchronize(before, route);
      if (after === before) continue;
      changed.push(path.relative(ROOT, file));
      if (!CHECK_ONLY) fs.writeFileSync(file, after, "utf8");
    }
  }
  if (CHECK_ONLY && changed.length) throw new Error(`Grafice de program nesincronizate: ${changed.join(", ")}`);
  console.log(`Grafice program: ${routes().length} rute verificate, ${changed.length} fișiere ${CHECK_ONLY ? "nesincronizate" : "actualizate"}.`);
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { accessibleMainSvg, filesForRoute, routes, synchronize, visual };
