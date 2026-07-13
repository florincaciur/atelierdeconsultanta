#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { chromium } = require("playwright");
const {
  END,
  ROOT,
  START,
  findPublicHtmlFiles,
  partialSource
} = require("../tools/sync-global-header");

function count(text, token) {
  return text.split(token).length - 1;
}

function normalize(text) {
  return text.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").trim();
}

function extractMarkedBlock(html) {
  const start = html.indexOf(START);
  const end = html.indexOf(END);
  if (start === -1 || end === -1 || end < start) return null;
  return html.slice(start, end + END.length);
}

function hrefs($, selector) {
  return $(selector).map((_, element) => $(element).attr("href") || "").get();
}

function equalSequence(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function routeExists(href) {
  const route = href.slice(1);
  return fs.existsSync(path.join(ROOT, route, "index.html")) || fs.existsSync(path.join(ROOT, `${route}.html`));
}

function canonicalMegaMenuErrors(megaLinks) {
  const errors = [];
  const seen = new Set();
  for (const href of megaLinks) {
    if (!/^\/[a-z0-9-]+(?:\/[a-z0-9-]+)*$/.test(href)) errors.push(`URL necanonic în mega-menu: ${href}`);
    if (/\.html|\/index\.html|[?#]|\/$/.test(href)) errors.push(`Alias sau sufix necanonic în mega-menu: ${href}`);
    if (seen.has(href)) errors.push(`URL duplicat în mega-menu: ${href}`);
    seen.add(href);
    if (!routeExists(href)) errors.push(`Ruta mega-menu nu are sursă HTML: ${href}`);
  }
  return errors;
}

function verifyStructure($, partialLinks, partialMobileLinks, partialMegaLinks) {
  const errors = [];
  if ($("#navbar").length !== 1) errors.push(`număr invalid de navbare globale: ${$("#navbar").length}`);
  if ($("nav.navbar").length !== 0) errors.push(`navbar legacy rămas: ${$("nav.navbar").length}`);
  if ($("#mobileMenu").length !== 1) errors.push(`număr invalid de meniuri mobile: ${$("#mobileMenu").length}`);
  if ($("#hamburgerBtn").length !== 1) errors.push(`buton hamburger lipsă sau duplicat: ${$("#hamburgerBtn").length}`);
  if ($("#dropdownPanel").length !== 1 || $("#dropdownBtn").length !== 1) errors.push("mega-menu lipsă sau duplicat");
  if ($("#dropdownPanel .dropdown-item").length !== partialMegaLinks.length) errors.push("mega-menu incomplet");
  if ($("#mobileMenu .mobile-links").length !== 1) errors.push("meniul mobil lipsește");
  if ($('script[src="/assets/global-header.js?v=20260713-2"]').length !== 1) errors.push("comportamentul static versionat al headerului lipsește sau este duplicat");
  if ($('link[rel="stylesheet"][href="/assets/global-header.css?v=20260713-2"]').length !== 1) errors.push("stilurile versionate ale headerului lipsesc sau sunt duplicate");
  if ($("#eligibility-whatsapp-dialog").length !== 1) errors.push("dialogul WhatsApp lipsește sau este duplicat");
  if ($("#navbar [data-whatsapp-dialog-open], #mobileMenu [data-whatsapp-dialog-open]").length !== 2) errors.push("CTA-urile desktop/mobil pentru dialog lipsesc");
  const whatsappLinks = hrefs($, "#eligibility-whatsapp-dialog .eligibility-whatsapp-options a");
  if (!equalSequence(whatsappLinks, ["https://wa.me/40769828338", "https://wa.me/40753326229"])) errors.push("numerele WhatsApp diferă de configurația cerută");
  if ($('a.nav-cta[href="/verificare-eligibilitate-fonduri-europene"], a.mobile-cta[href="/verificare-eligibilitate-fonduri-europene"]').length) errors.push("CTA-ul global trimite încă spre pagina dedicată");

  const pageLinks = hrefs($, "#navbar a");
  const pageMobileLinks = hrefs($, "#mobileMenu a");
  const pageMegaLinks = hrefs($, "#dropdownPanel a.dropdown-item");
  if (!equalSequence(pageLinks, partialLinks)) errors.push("linkurile desktop diferă de partial");
  if (!equalSequence(pageMobileLinks, partialMobileLinks)) errors.push("linkurile mobile diferă de partial");
  if (!equalSequence(pageMegaLinks, partialMegaLinks)) errors.push("linkurile mega-menu diferă de partial");
  return errors;
}

async function verifyBehavior(partial, stylesheet, behavior) {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const executablePartial = partial
      .replace('<link rel="stylesheet" href="/assets/global-header.css?v=20260713-2">', `<style>${stylesheet}</style>`)
      .replace('<script src="/assets/global-header.js?v=20260713-2"></script>', `<script>${behavior}</script>`);
    await page.setContent(`<!doctype html><html><body>${executablePartial}<main><a id="homepage-eligibility-cta" href="#eligibility-whatsapp-dialog" data-whatsapp-dialog-open>Solicită verificare eligibilitate</a></main></body></html>`, { waitUntil: "domcontentloaded" });

    await page.click("#dropdownBtn");
    if (await page.getAttribute("#dropdownBtn", "aria-expanded") !== "true") throw new Error("mega-menu nu se deschide la click");
    if (await page.$eval("#dropdownPanel", (element) => element.hidden)) throw new Error("mega-menu rămâne hidden după click");

    await page.click("#dropdownBtn");
    await page.focus("#dropdownBtn");
    await page.keyboard.press("ArrowDown");
    await page.waitForFunction(() => document.activeElement === document.querySelector("#dropdownPanel .dropdown-item:first-of-type"));
    if (!(await page.$eval("#dropdownPanel .dropdown-item:first-of-type", (element) => element === document.activeElement))) {
      throw new Error("ArrowDown nu mută focusul pe primul element din mega-menu");
    }
    await page.keyboard.press("End");
    if (!(await page.$eval("#dropdownPanel .dropdown-item:last-of-type", (element) => element === document.activeElement))) {
      throw new Error("End nu mută focusul pe ultimul element din mega-menu");
    }
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowUp");
    if (!(await page.$eval("#dropdownPanel .dropdown-item:last-of-type", (element) => element === document.activeElement))) {
      throw new Error("Home/ArrowUp nu păstrează navigarea circulară");
    }
    await page.keyboard.press("Escape");
    if (!(await page.$eval("#dropdownBtn", (element) => element === document.activeElement))) throw new Error("Escape nu restaurează focusul pe butonul Programe");
    if (!(await page.$eval("#dropdownPanel", (element) => element.hidden))) throw new Error("Escape nu închide mega-menu-ul");

    await page.click("#navbar [data-whatsapp-dialog-open]");
    if (await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden)) throw new Error("CTA-ul desktop nu deschide dialogul WhatsApp");
    if (!(await page.$eval("[data-whatsapp-dialog-close]", (element) => element === document.activeElement))) throw new Error("dialogul nu mută focusul pe butonul de închidere");
    const whatsappHrefs = await page.$$eval("#eligibility-whatsapp-dialog .eligibility-whatsapp-options a", (links) => links.map((link) => link.href));
    if (!equalSequence(whatsappHrefs, ["https://wa.me/40769828338", "https://wa.me/40753326229"])) throw new Error("dialogul nu conține cele două numere WhatsApp");
    await page.keyboard.press("Escape");
    if (!(await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden))) throw new Error("Escape nu închide dialogul WhatsApp");
    if (!(await page.$eval("#navbar [data-whatsapp-dialog-open]", (element) => element === document.activeElement))) throw new Error("dialogul nu restaurează focusul pe CTA");

    await page.click("#homepage-eligibility-cta");
    if (await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden)) throw new Error("CTA-ul homepage încărcat după script nu deschide dialogul WhatsApp");
    await page.click("[data-whatsapp-dialog-close]");
    if (!(await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden))) throw new Error("dialogul homepage nu se închide");

    await page.setViewportSize({ width: 375, height: 800 });
    await page.click("#hamburgerBtn");
    if (!(await page.$eval("#mobileMenu", (element) => element.classList.contains("open")))) throw new Error("hamburgerul nu deschide meniul mobil");
    if (await page.getAttribute("#hamburgerBtn", "aria-expanded") !== "true") throw new Error("hamburgerul nu actualizează aria-expanded");
    await page.click("#mobileMenu [data-whatsapp-dialog-open]");
    if (await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden)) throw new Error("CTA-ul mobil nu deschide dialogul WhatsApp");
    if (await page.$eval("#mobileMenu", (element) => element.classList.contains("open"))) throw new Error("CTA-ul mobil nu închide meniul înainte de dialog");
    await page.click("[data-whatsapp-dialog-close]");
    if (!(await page.$eval("#eligibility-whatsapp-dialog", (element) => element.hidden))) throw new Error("butonul de închidere nu închide dialogul WhatsApp");
  } finally {
    await browser.close();
  }
}

async function main() {
  const partial = partialSource();
  const $partial = cheerio.load(partial, { decodeEntities: false });
  const partialLinks = hrefs($partial, "#navbar a");
  const partialMobileLinks = hrefs($partial, "#mobileMenu a");
  const partialMegaLinks = hrefs($partial, "#dropdownPanel a.dropdown-item");
  const errors = [...canonicalMegaMenuErrors(partialMegaLinks)];

  const stylesheet = fs.readFileSync(path.join(ROOT, "assets", "global-header.css"), "utf8");
  const behavior = fs.readFileSync(path.join(ROOT, "assets", "global-header.js"), "utf8");
  for (const required of ["ArrowDown", "ArrowUp", "Home", "End", "Escape", "focusout", "aria-expanded", "closeMobileMenu", "eligibility-whatsapp-dialog"]) {
    if (!behavior.includes(required)) errors.push(`comportament obligatoriu absent din partial: ${required}`);
  }

  const files = findPublicHtmlFiles();
  for (const relativePath of files) {
    const filePath = path.join(ROOT, ...relativePath.split("/"));
    const html = fs.readFileSync(filePath, "utf8");
    const fileErrors = [];
    if (count(html, START) !== 1 || count(html, END) !== 1) fileErrors.push("delimitatori lipsă sau duplicați");
    const block = extractMarkedBlock(html);
    if (!block || normalize(block) !== normalize(partial)) fileErrors.push("blocul global diferă de partial");
    const $ = cheerio.load(html, { decodeEntities: false });
    fileErrors.push(...verifyStructure($, partialLinks, partialMobileLinks, partialMegaLinks));
    for (const error of fileErrors) errors.push(`${relativePath}: ${error}`);
  }

  const generators = [
    "tools/generate-program-pages.js",
    "tools/generate-programmatic-seo.js",
    "tools/generate-project-design-pages.js",
    "tools/generate-seo-hubs.js",
    "tools/generate-seo-blog-article.js"
  ];
  for (const generator of generators) {
    const source = fs.readFileSync(path.join(ROOT, ...generator.split("/")), "utf8");
    if (!source.includes("GLOBAL_HEADER") || !source.includes("partials\", \"global-header.html")) {
      errors.push(`${generator}: generatorul nu consumă partialul global`);
    }
  }

  if (errors.length) {
    console.error(`Global header verification FAILED (${errors.length}):`);
    for (const error of errors) console.error(` - ${error}`);
    process.exitCode = 1;
    return;
  }

  await verifyBehavior(partial, stylesheet, behavior);

  const indexFiles = files.filter((file) => path.posix.basename(file) === "index.html").length;
  console.log(`Global header verification PASS: ${files.length} pagini HTML publice, ${indexFiles} index.html, ${partialMegaLinks.length} linkuri canonice în mega-menu; interacțiuni desktop/mobile validate în Chromium.`);
}

main().catch((error) => {
  console.error(`Global header verification FAILED: ${error.message}`);
  process.exitCode = 1;
});
