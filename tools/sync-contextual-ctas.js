#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "contextual-ctas.json");
const START = "<!-- P1_15_CONTEXTUAL_CTA_START -->";
const END = "<!-- P1_15_CONTEXTUAL_CTA_END -->";
const CHECK = process.argv.includes("--check");
const GLOBAL_HEADER_PATTERN = /<!-- GLOBAL_HEADER_START -->[\s\S]*?<!-- GLOBAL_HEADER_END -->/iu;
const BREADCRUMB_PATTERN = /<!-- BREADCRUMB_START -->[\s\S]*?<!-- BREADCRUMB_END -->/iu;

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function contactHref(page) {
  const params = new URLSearchParams();
  if (page.programSlug) params.set("program_slug", page.programSlug);
  params.set("source_page", page.route);
  return `/contact#${params.toString()}`;
}

function tracking(cta, page, component) {
  cta
    .attr("data-analytics-event", "cta_click")
    .attr("data-analytics-component", component)
    .attr("data-analytics-cta-id", `${page.id}_contextual_primary`)
    .attr("data-analytics-target", "/contact")
    .attr("data-analytics-cta-view", "true")
    .attr("data-analytics-copy-variant", "p1_15");
  if (page.programSlug) cta.attr("data-analytics-program-slug", page.programSlug);
}

function setHeroCta($, page, config) {
  const hero = page.route === "/" ? $("#hero").first() : $("header.hero, .program-hero").first();
  if (!hero.length) throw new Error(`${page.route}: hero lipsă`);
  const actions = hero.find(".hero-ctas, .hero-actions").first();
  if (!actions.length) throw new Error(`${page.route}: acțiuni hero lipsă`);

  const primary = actions.find("a").first();
  if (!primary.length) throw new Error(`${page.route}: CTA principal lipsă`);
  primary.attr("href", contactHref(page)).attr("data-contextual-hero-cta", "").text(page.primary);
  tracking(primary, page, "contextual_hero");

  let secondary = actions.find("a").eq(1);
  if (!secondary.length) {
    secondary = $('<a class="btn btn-secondary"></a>');
    actions.append(secondary);
  }
  secondary
    .attr("href", config.secondary.href)
    .removeAttr("target rel")
    .attr("data-analytics-event", "cta_click")
    .attr("data-analytics-component", "contextual_secondary")
    .attr("data-analytics-cta-id", `${page.id}_prepare_secondary`)
    .attr("data-analytics-target", config.secondary.href)
    .attr("data-analytics-cta-view", "true")
    .attr("data-analytics-copy-variant", "p1_15")
    .text(config.secondary.label);

  hero.find(".contextual-cta__microcopy").remove();
  if (page.route === "/" && hero.find(".homepage-hero__microcopy").length) {
    hero.find(".homepage-hero__microcopy").text(page.microcopy);
  } else {
    actions.after(`<p class="contextual-cta__microcopy">${page.microcopy}</p>`);
  }
}

function syncProgramBodyCta($, page) {
  if (!page.programSlug) return;
  const links = $("a[href*='/contact']").filter((_, node) => !$(node).closest("#navbar, #mobileMenu, [data-sticky-cta], [data-program-contextual-links]").length);
  let primaryIndex = 0;
  links.each((_, node) => {
    const link = $(node);
    if (!/verific|încadr/iu.test(link.text())) return;
    primaryIndex += 1;
    link.attr("href", contactHref(page)).text(page.primary);
    tracking(link, page, "program_page");
    link.attr("data-analytics-cta-id", `${page.id}_contextual_primary_${primaryIndex}`);
  });
}

function calculatorBlock(page) {
  const href = contactHref(page);
  return `${START}<aside class="calculator-contextual-cta" aria-label="Continuă cu verificarea AFIR"><p>${page.microcopy}</p><a class="btn-primary" href="${href}" data-calculator-context-cta data-contextual-base-href="${href}" data-analytics-event="cta_click" data-analytics-component="calculator_result" data-analytics-cta-id="calculator_soc_contextual_primary" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15">${page.primary}</a></aside>${END}`;
}

function stickyBlock(page) {
  const href = contactHref(page);
  return `${START}
<aside data-sticky-cta aria-label="Verificarea proiectului" hidden>
  <p>${page.microcopy}</p>
  <a href="${href}" data-analytics-event="cta_click" data-analytics-component="mobile_sticky" data-analytics-cta-id="${page.id}_sticky_primary" data-analytics-target="/contact" data-analytics-cta-view="true" data-analytics-copy-variant="p1_15"${page.programSlug ? ` data-analytics-program-slug="${page.programSlug}"` : ""}>${page.primary}</a>
</aside>
${END}`;
}

function injectAssets(output, page) {
  const stylesheet = '<link rel="stylesheet" href="/assets/contextual-cta.css?v=20260722-1">';
  const script = '<script src="/assets/contextual-cta.js?v=20260722-1" defer></script>';
  const longFormStyle = /^[ \t]*<link\b[^>]*data-long-form-layout-style=["'][^"']+["'][^>]*>/imu;
  const headAssets = `  ${stylesheet}\n  ${script}`;
  output = longFormStyle.test(output)
    ? output.replace(longFormStyle, (match) => `${headAssets}\n  ${match.trimStart()}`)
    : output.replace("</head>", `${headAssets}\n</head>`);
  return output.replace("</body>", `${stickyBlock(page)}\n</body>`);
}

function synchronize(source, page, config) {
  let clean = source
    .replace(new RegExp(`${START}<aside class="calculator-contextual-cta"[\\s\\S]*?${END}\\s*`, "gu"), "")
    .replace(new RegExp(`${START}\\s*<aside data-sticky-cta[\\s\\S]*?${END}\\s*`, "gu"), "")
    .replace(/\s*<link\b[^>]*href=["']\/assets\/contextual-cta\.css[^>]*>\s*/giu, "\n")
    .replace(/\s*<script\b[^>]*src=["']\/assets\/contextual-cta\.js[^>]*><\/script>\s*/giu, "\n");
  if (page.route === "/") {
    return injectAssets(clean, page);
  }
  const globalHeader = clean.match(GLOBAL_HEADER_PATTERN)?.[0] || "";
  const breadcrumb = clean.match(BREADCRUMB_PATTERN)?.[0] || "";
  const $ = cheerio.load(clean, { decodeEntities: false });
  setHeroCta($, page, config);
  syncProgramBodyCta($, page);
  if (page.calculatorResult) {
    const result = $(".calc-result").first();
    if (!result.length) throw new Error(`${page.route}: rezultat calculator lipsă`);
    result.after(calculatorBlock(page));
  }
  let output = $.html();
  if (globalHeader) output = output.replace(GLOBAL_HEADER_PATTERN, globalHeader);
  if (breadcrumb) output = output.replace(BREADCRUMB_PATTERN, breadcrumb);
  return injectAssets(output, page);
}

function main() {
  const config = loadConfig();
  const changed = [];
  for (const page of config.pages) {
    const file = path.join(ROOT, page.file);
    const before = fs.readFileSync(file, "utf8");
    const after = synchronize(before, page, config);
    if (after !== before) {
      changed.push(page.file);
      if (!CHECK) fs.writeFileSync(file, after, "utf8");
    }
  }
  if (CHECK && changed.length) throw new Error(`CTA-uri contextuale nesincronizate: ${changed.join(", ")}`);
  console.log(`CTA-uri contextuale P1.15 sincronizate: ${config.pages.length} pagini${changed.length ? `, ${changed.length} actualizate` : ""}.`);
}

if (require.main === module) main();
module.exports = { contactHref, loadConfig, synchronize };
