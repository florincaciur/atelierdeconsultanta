#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadNextStepConfig, publicNextStepLinks } = require("../tools/contextual-next-steps");
const { isPublicProgram, loadProgramConfig, programForRoute } = require("../tools/program-factual-governance");
const { SITE, cleanText, fileForRoute, sitemapRoutes } = require("../tools/structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const BANNED_ANCHORS = new Set(["află mai multe", "click aici", "citește aici", "vezi pagina"]);

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

function oneSentence(value) {
  const text = cleanText(value);
  return text.endsWith(".") && (text.match(/[.!?](?=\s|$)/gu) || []).length === 1;
}

function validateInternalTarget(route, canonicalRoutes, redirects, errors, sourceRoute) {
  if (redirects.has(route)) errors.push(`${sourceRoute}: destinația ${route} este redirect`);
  if (!canonicalRoutes.has(route)) errors.push(`${sourceRoute}: destinația ${route} nu este în sitemap`);
  const file = fileForRoute(ROOT, route);
  if (!fs.existsSync(file)) {
    errors.push(`${sourceRoute}: destinația ${route} nu are fișier local`);
    return;
  }
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  if (/noindex/iu.test($("meta[name='robots']").attr("content") || "")) errors.push(`${sourceRoute}: destinația ${route} este noindex`);
  const canonical = $("link[rel='canonical']").attr("href");
  if (canonical !== `${SITE}${route === "/" ? "/" : route}`) errors.push(`${sourceRoute}: canonical diferit pentru ${route}: ${canonical || "lipsește"}`);
}

function main() {
  const config = loadNextStepConfig();
  const canonicalRoutes = new Set(sitemapRoutes(ROOT));
  const redirects = redirectSources();
  const errors = [];
  const anchorSources = new Map();
  const targetSources = new Map();
  const programs = loadProgramConfig().programs;
  const managedProgramRoutes = new Set(programs.map((program) => program.pageUrl));
  let verifiedPages = 0;

  for (const [slug, page] of Object.entries(config.pages)) {
    if (managedProgramRoutes.has(page.route)) continue;
    const sourceProgram = programForRoute(page.route, programs);
    if (sourceProgram && !isPublicProgram(sourceProgram)) continue;
    const expectedLinks = publicNextStepLinks(page, programs);
    const file = path.join(ROOT, page.file);
    const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
    const blocks = $("[data-contextual-next-step]");
      if (blocks.length !== 1) {
        errors.push(`${page.route}: trebuie exact un bloc contextual, găsite ${blocks.length}`);
      continue;
    }
    const block = blocks.first();
    const heading = cleanText(block.children("h2").first().text());
    if (heading !== page.title) errors.push(`${page.route}: titlul blocului trebuie să fie „${page.title}”`);
    const links = block.children("ul").children("li").children("a");
    if (links.length < 1 || links.length > 4) errors.push(`${page.route}: blocul are ${links.length} linkuri; sunt permise 1–4`);
    if (links.length !== expectedLinks.length) errors.push(`${page.route}: HTML/config public diferit (${links.length}/${expectedLinks.length})`);
    const seenTargets = new Set();

    expectedLinks.forEach((expected, index) => {
      const link = links.eq(index);
      const href = link.attr("href") || "";
      const anchor = cleanText(link.find(".see-also-card-title").text());
      const explanation = cleanText(link.find(".see-also-card-text").text());
      if (href !== expected.href) errors.push(`${page.route}: destinație diferită la poziția ${index + 1}: ${href}`);
      if (anchor !== expected.anchor) errors.push(`${page.route}: ancoră diferită pentru ${expected.href}`);
      if (explanation !== expected.explanation) errors.push(`${page.route}: explicație diferită pentru ${expected.href}`);
      if (!oneSentence(explanation)) errors.push(`${page.route}: explicația pentru ${expected.href} nu este o singură propoziție`);
      if (BANNED_ANCHORS.has(anchor.toLowerCase())) errors.push(`${page.route}: ancoră generică interzisă „${anchor}”`);
      if (seenTargets.has(href)) errors.push(`${page.route}: destinație duplicată ${href}`);
      seenTargets.add(href);
      if (href === page.route) errors.push(`${page.route}: blocul trimite către aceeași pagină`);
      if (/\.html(?:$|[?#])/iu.test(href)) errors.push(`${page.route}: link legacy .html ${href}`);
      const conversion = /^\/contact(?:[?#]|$)/u.test(href) || link.attr("data-link-relation") === "conversion";
      if (link.attr("data-link-type") !== (conversion ? "conversion" : "contextual")) errors.push(`${page.route}: tip semantic invalid pentru ${href}`);
      if (conversion) {
        if (link.attr("data-analytics-event") !== "cta_click") errors.push(`${page.route}: CTA fără eveniment cta_click pentru ${href}`);
        if (link.attr("data-analytics-target") !== "/contact") errors.push(`${page.route}: target analytics diferit pentru ${href}`);
      } else if (link.attr("data-analytics-event")) {
        errors.push(`${page.route}: link editorial instrumentat nepermis pentru ${href}`);
      }

      const url = new URL(href, SITE);
      if (url.origin === SITE) {
        const targetRoute = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/u, "");
        validateInternalTarget(targetRoute, canonicalRoutes, redirects, errors, page.route);
        if (!targetSources.has(targetRoute)) targetSources.set(targetRoute, new Set());
        targetSources.get(targetRoute).add(page.route);
      }
      else if (url.protocol !== "https:" || link.attr("target") !== "_blank" || !/noopener/u.test(link.attr("rel") || "")) errors.push(`${page.route}: sursă externă nesecurizată ${href}`);

      const normalizedAnchor = anchor.toLocaleLowerCase("ro-RO");
      if (!anchorSources.has(normalizedAnchor)) anchorSources.set(normalizedAnchor, new Set());
      anchorSources.get(normalizedAnchor).add(page.route);
    });
    verifiedPages += 1;
    console.log(`${page.route}: ${links.length} legături contextuale conforme`);
  }

  for (const [anchor, sources] of anchorSources) {
    if (sources.size > 4) errors.push(`ancora contextuală „${anchor}” este repetată pe ${sources.size} pagini`);
  }

  const projectDesignSources = targetSources.get("/proiectare-fonduri-europene") || new Set();

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`Trasee contextuale valide pentru ${verifiedPages} pagini non-program; doar CTA-urile sunt instrumentate, cu zero redirecturi și zero destinații moarte.`);
}

main();
