#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { ASSET_VERSION, loadConfig, renderHeader } = require("../tools/generate-global-header");
const { END, ROOT, START, findPublicHtmlFiles, partialSource } = require("../tools/sync-global-header");

const SITE = "https://atelierdeconsultanta.ro";

function normalize(value) {
  return String(value).replace(/^\uFEFF/u, "").replace(/\r\n/gu, "\n").trim();
}

function markedBlock(html) {
  const start = html.indexOf(START);
  const end = html.indexOf(END);
  return start >= 0 && end > start ? html.slice(start, end + END.length) : "";
}

function htmlFileForRoute(href) {
  const pathname = new URL(href, SITE).pathname.replace(/^\/+|\/+$/gu, "");
  if (!pathname) return "index.html";
  const index = path.join(ROOT, pathname, "index.html");
  return fs.existsSync(index) ? index : path.join(ROOT, `${pathname}.html`);
}

function validateCanonicalRoute(errors, href) {
  const parsed = new URL(href, SITE);
  if (parsed.origin !== SITE || parsed.search) return errors.push(`destinație necanonică: ${href}`);
  const file = htmlFileForRoute(href);
  if (!fs.existsSync(file)) return errors.push(`destinația nu are sursă HTML: ${href}`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"));
  const canonical = $('link[rel="canonical"]').first().attr("href");
  if (canonical !== `${SITE}${parsed.pathname}`) errors.push(`canonical incorect pentru ${href}: ${canonical || "LIPSĂ"}`);
  if (parsed.hash && $(`[id="${parsed.hash.slice(1)}"]`).length !== 1) errors.push(`ancoră lipsă pentru ${href}`);
}

function main() {
  const config = loadConfig();
  const partial = partialSource();
  const expected = renderHeader(config);
  const $ = cheerio.load(partial, { decodeEntities: false }, false);
  const errors = [];

  if (normalize(partial) !== normalize(expected)) errors.push("partialul diferă de configurația generată");
  if ($("#navbar [data-nav-disclosure]").length !== 3) errors.push("desktopul trebuie să aibă trei grupuri disclosure principale");
  if ($("#mobileMenu [data-mobile-disclosure]").length !== 3) errors.push("mobilul trebuie să aibă trei grupuri disclosure principale");
  if ($("#navbar .nav-primary-link").map((_, el) => $(el).text().trim()).get().join("|") !== "Calculator SO|Contact") errors.push("Calculator SO și Contact trebuie să fie destinații directe");
  if ($("#navbar .nav-cta").text().trim() !== config.cta.label) errors.push("CTA-ul desktop nu corespunde configurației");
  if ($("#mobileMenu .mobile-cta").text().trim() !== config.cta.label) errors.push("CTA-ul mobil nu corespunde configurației");
  if (/\b(?:Instrumente|Ghiduri|Cuprins)\b/u.test($("#navbar, #mobileMenu").text())) errors.push("o etichetă eliminată a rămas în navigarea principală");
  if ($("#dropdownPanel [data-program-id]").length !== config.programMenu.featuredProgramSlugs.length) errors.push("meniul Programe nu conține măsurile aprobate");
  if ($('[href="/por-adr-nord-est"]').length) errors.push("meniul publică ruta regională consolidată");
  if ($('[href="/investitii-modernizarea-microintreprinderilor-apel-2"]').length < 2) errors.push("pagina regională de conversie lipsește din meniuri");
  if ($(`[href="/assets/global-header.css?v=${ASSET_VERSION}"]`).length !== 1) errors.push("versiunea CSS a headerului este incorectă");
  if ($(`[src="/assets/global-header.js?v=${ASSET_VERSION}"]`).length !== 1) errors.push("versiunea JS a headerului este incorectă");

  const hrefs = [...new Set($("#navbar a[href], #mobileMenu a[href]").map((_, element) => $(element).attr("href")).get())]
    .filter((href) => href.startsWith("/"));
  hrefs.forEach((href) => validateCanonicalRoute(errors, href));

  const files = findPublicHtmlFiles();
  for (const relative of files) {
    const html = fs.readFileSync(path.join(ROOT, ...relative.split("/")), "utf8");
    if (normalize(markedBlock(html)) !== normalize(partial)) errors.push(`${relative}: header nesincronizat`);
  }

  if (errors.length) {
    console.error(`Global header verification FAILED (${errors.length}):`);
    errors.forEach((error) => console.error(` - ${error}`));
    process.exitCode = 1;
    return;
  }
  console.log(`PASS: 5 destinații principale, măsuri verificate și header identic în ${files.length} pagini HTML publice.`);
}

main();
