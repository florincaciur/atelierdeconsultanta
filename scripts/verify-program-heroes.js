#!/usr/bin/env node
"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const cheerio = require("cheerio");
const { chromium } = require("playwright");
const { sourcesForKeys } = require("../tools/official-sources");
const {
  PRIORITY_ROUTES,
  PROGRAM_ROUTES,
  PRO_INFRA_REFERENCE,
  bannerForRoute,
  createBannerIndex,
  familyForRoute,
  iconClass,
  loadBanners,
  normalizeCtaLink
} = require("../tools/sync-program-heroes");

const ROOT = path.resolve(__dirname, "..");
const failures = [];

function fail(route, message) {
  failures.push(`${route}: ${message}`);
}

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function count(haystack, needle) {
  return haystack.split(needle).length - 1;
}

function heroText(element) {
  const clone = element.clone();
  clone.find("br").replaceWith(" ");
  return normalizeText(clone.text());
}

function verifyNormalizer() {
  const cases = new Map([
    ["https://atelierdeconsultanta.ro/dr12-afir.html?utm_source=test#top", "/dr12-afir"],
    ["https://www.atelierdeconsultanta.ro/dr14/index.html/", "/dr14"],
    ["por-adr-nord-est/", "/por-adr-nord-est"],
    ["/pro-infra.html", "/pro-infra"]
  ]);
  for (const [input, expected] of cases) {
    const actual = normalizeCtaLink(input);
    if (actual !== expected) fail("normalizeCtaLink", `${input} -> ${actual}; expected ${expected}`);
  }
}

function verifyMegaMenuCoverage() {
  const header = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8");
  const $ = cheerio.load(header, { decodeEntities: false }, false);
  const hrefs = $("#dropdownPanel a.dropdown-item").map((_, element) => $(element).attr("href")).get();
  const expected = new Set(PROGRAM_ROUTES);
  const actual = new Set(hrefs.map(normalizeCtaLink));
  for (const href of hrefs) {
    if (href !== normalizeCtaLink(href)) fail("mega-menu", `noncanonical program URL: ${href}`);
  }
  for (const route of expected) {
    if (!actual.has(route)) fail("mega-menu", `${route} is configured but absent from the program mega-menu`);
  }
  for (const route of actual) {
    if (!expected.has(route)) fail("mega-menu", `${route} has no synchronized program hero mapping`);
  }
}

function verifyStaticPage(route, bannerIndex) {
  const filePath = path.join(ROOT, route.slice(1), "index.html");
  if (!fs.existsSync(filePath)) return fail(route, "index.html is missing");
  const html = fs.readFileSync(filePath, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const banner = bannerForRoute(route, bannerIndex);
  if (!banner) return fail(route, "no matching banners.json entry");
  const hero = $("header.program-hero");

  if (count(html, "<!-- PROGRAM_HERO_START -->") !== 1 || count(html, "<!-- PROGRAM_HERO_END -->") !== 1) {
    fail(route, "program hero delimiters must occur exactly once");
  }
  if (hero.length !== 1 || $("header.hero").length !== 1) fail(route, `expected one program hero, found ${hero.length}`);
  if ($('link[href="/assets/program-heroes.css"]').length !== 1) fail(route, "program hero stylesheet is missing or duplicated");
  if ($("h1").length !== 1) fail(route, `expected exactly one H1, found ${$("h1").length}`);
  if ($(".hero-summary, .hero-summary__item").length) fail(route, "compact BENEFICIAR/STATUS/DOCUMENTE/RISC cards still exist");
  if (!hero.length) return;

  const expectedFamily = familyForRoute(route);
  const expectedImage = String(banner.image || "");
  if (hero.attr("data-banner-id") !== banner.id) fail(route, "data-banner-id differs from banners.json");
  if (hero.attr("data-banner-image") !== expectedImage) fail(route, "data-banner-image differs from banners.json");
  if (hero.attr("data-program-route") !== route) fail(route, "data-program-route is not canonical");
  if (hero.attr("data-program-family") !== expectedFamily) fail(route, "chromatic family is incorrect");
  if (!String(hero.attr("style") || "").includes(`url('${expectedImage}')`)) fail(route, "static hero image differs from banners.json");

  const actualIcon = normalizeText(hero.find(".hero-icon i").attr("class"));
  const expectedIcon = iconClass(route === "/pro-infra" ? PRO_INFRA_REFERENCE.icon : banner.icon);
  if (actualIcon !== expectedIcon) fail(route, `icon differs: ${actualIcon} != ${expectedIcon}`);

  const expectedTitle = route === "/pro-infra"
    ? PRO_INFRA_REFERENCE.title
    : ((banner.pageTitles && banner.pageTitles[route]) || banner.pageTitle || banner.title);
  const expectedDescription = route === "/pro-infra"
    ? PRO_INFRA_REFERENCE.description
    : ((banner.pageDescriptions && banner.pageDescriptions[route]) || banner.description || banner.subtitle);
  if (heroText(hero.find("h1").first()) !== normalizeText(expectedTitle)) fail(route, "H1 does not reuse the banner title");
  if (normalizeText(hero.find("p").first().text()) !== normalizeText(expectedDescription)) fail(route, "description does not reuse banners.json");

  const actions = hero.find(".hero-actions").first();
  const links = actions.find("a");
  if (links.length < 2) fail(route, "eligibility or official-guide CTA is missing");
  if (normalizeCtaLink(links.eq(0).attr("href")) !== "/verificare-eligibilitate-fonduri-europene") {
    fail(route, "first CTA is not the eligibility check");
  }
  const officialGuideKey = (banner.officialGuideKeys && banner.officialGuideKeys[route]) || banner.officialGuideKey;
  const officialSource = sourcesForKeys([officialGuideKey])[0];
  if (!officialSource || links.eq(1).attr("href") !== officialSource.url) fail(route, "official-guide CTA does not target the banner's official source");
  if (!/ghid|surs|program|apel/i.test(normalizeText(links.eq(1).text()))) fail(route, "second CTA is not labelled as an official guide/source");

  if (route === "/pro-infra") {
    if (normalizeText(hero.find(".design-badge").text()) !== PRO_INFRA_REFERENCE.tag) fail(route, "reference badge changed");
    if (links.eq(0).attr("href") !== PRO_INFRA_REFERENCE.primaryHref || normalizeText(links.eq(0).text()) !== PRO_INFRA_REFERENCE.primaryText) {
      fail(route, "reference eligibility CTA changed");
    }
    if (links.eq(1).attr("href") !== PRO_INFRA_REFERENCE.guideHref || normalizeText(links.eq(1).text()) !== PRO_INFRA_REFERENCE.guideText) {
      fail(route, "reference official-guide CTA changed");
    }
  }
}

function verifyGenerator(routes) {
  const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
  const { pageHtml } = require("../tools/generate-program-pages");
  const configured = new Map((config.pages || []).map((page) => [`/${page.slug}`, page]));
  for (const route of routes) {
    const page = configured.get(route);
    if (!page) continue;
    const generated = pageHtml(page, config);
    const $ = cheerio.load(generated, { decodeEntities: false });
    if ($("header.program-hero").length !== 1) fail(route, "generator does not emit the synchronized static hero");
    if ($(".hero-summary, .hero-summary__item").length) fail(route, "generator would recreate the compact summary cards");
    if ($('link[href="/assets/program-heroes.css"]').length !== 1) fail(route, "generator omits the program hero stylesheet");
  }
}

function contentType(filePath) {
  return ({
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
    ".woff2": "font/woff2"
  })[path.extname(filePath).toLowerCase()] || "application/octet-stream";
}

function startServer() {
  return new Promise((resolve) => {
    const server = http.createServer((request, response) => {
      let pathname;
      try {
        pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
      } catch {
        response.statusCode = 400;
        return response.end("bad request");
      }
      if (pathname.endsWith("/")) pathname += "index.html";
      const filePath = path.resolve(ROOT, pathname.replace(/^\/+/, ""));
      if (!filePath.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        response.statusCode = 404;
        return response.end("not found");
      }
      response.setHeader("Content-Type", contentType(filePath));
      fs.createReadStream(filePath).pipe(response);
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

async function verifyResponsivePages(routes, bannerIndex) {
  const server = await startServer();
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const browser = await chromium.launch({ headless: true });
  try {
    for (const route of routes) {
      const banner = bannerForRoute(route, bannerIndex);
      for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
        const page = await browser.newPage({ viewport });
        try {
          await page.goto(`${baseUrl}${route}/`, { waitUntil: "domcontentloaded" });
          await page.locator("header.program-hero").waitFor({ state: "visible" });
          const result = await page.evaluate(({ expectedImage, mobile }) => {
            const root = document.documentElement;
            const hero = document.querySelector("header.program-hero");
            const h1 = hero.querySelector("h1");
            const actions = hero.querySelector(".hero-actions");
            const heroRect = hero.getBoundingClientRect();
            const h1Rect = h1.getBoundingClientRect();
            const actionsRect = actions.getBoundingClientRect();
            const style = getComputedStyle(hero);
            return {
              viewportWidth: root.clientWidth,
              scrollWidth: root.scrollWidth,
              heroLeft: heroRect.left,
              heroRight: heroRect.right,
              heroWidth: heroRect.width,
              h1Width: h1Rect.width,
              actionsWidth: actionsRect.width,
              overflow: style.overflow,
              display: style.display,
              minHeight: style.minHeight,
              backgroundImage: style.backgroundImage,
              expectedImage,
              mobile
            };
          }, { expectedImage: banner.image, mobile: viewport.width <= 760 });

          if (result.scrollWidth > result.viewportWidth + 1) fail(route, `horizontal overflow at ${viewport.width}px: ${result.scrollWidth}px`);
          if (result.heroLeft < -1 || result.heroRight > result.viewportWidth + 1) fail(route, `hero exceeds viewport at ${viewport.width}px`);
          if (result.h1Width > result.viewportWidth || result.actionsWidth > result.viewportWidth) fail(route, `hero content exceeds viewport at ${viewport.width}px`);
          if (result.overflow !== "hidden" || result.display !== "grid") fail(route, `responsive hero primitives changed at ${viewport.width}px`);
          if (!result.backgroundImage.includes(path.basename(result.expectedImage))) fail(route, `rendered background omits banner image at ${viewport.width}px`);
          if (!result.mobile && result.minHeight !== "390px") fail(route, "desktop hero minimum height differs from PRO INFRA model");
          if (result.mobile && result.minHeight !== "0px") fail(route, "mobile hero does not release its fixed minimum height");
        } finally {
          await page.close();
        }
      }
    }

    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    try {
      await page.goto(`${baseUrl}/pro-infra/`, { waitUntil: "domcontentloaded" });
      const signature = await page.locator("header.program-hero").evaluate((hero) => {
        const heroRect = hero.getBoundingClientRect();
        const iconRect = hero.querySelector(".hero-icon").getBoundingClientRect();
        const h1 = hero.querySelector("h1");
        const h1Rect = h1.getBoundingClientRect();
        const actionsRect = hero.querySelector(".hero-actions").getBoundingClientRect();
        const style = getComputedStyle(hero);
        const h1Style = getComputedStyle(h1);
        const iconStyle = getComputedStyle(hero.querySelector(".hero-icon"));
        return {
          backgroundImage: style.backgroundImage,
          padding: style.padding,
          textAlign: style.textAlign,
          h1MaxWidth: h1Style.maxWidth,
          iconWidth: iconStyle.width,
          iconHeight: iconStyle.height,
          iconTop: iconRect.top - heroRect.top,
          h1Top: h1Rect.top - heroRect.top,
          actionsTop: actionsRect.top - heroRect.top,
          actionsWidth: actionsRect.width
        };
      });
      const approximate = (actual, expected) => Math.abs(actual - expected) <= 1;
      if (!signature.backgroundImage.includes("rgba(34, 58, 72, 0.9)") || !signature.backgroundImage.includes("hero-solar.webp")) fail("/pro-infra", "reference gradient or banner changed visually");
      if (signature.padding !== "70px 24px 58px" || signature.textAlign !== "center" || signature.h1MaxWidth !== "900px") fail("/pro-infra", "reference hero layout styles changed");
      if (signature.iconWidth !== "62px" || signature.iconHeight !== "62px") fail("/pro-infra", "reference icon geometry changed");
      if (!approximate(signature.iconTop, 70) || !approximate(signature.h1Top, 192.1875) || !approximate(signature.actionsTop, 486.90625) || !approximate(signature.actionsWidth, 421.3125)) {
        fail("/pro-infra", `reference geometry changed: ${JSON.stringify(signature)}`);
      }
    } finally {
      await page.close();
    }
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function main() {
  verifyNormalizer();
  verifyMegaMenuCoverage();
  const routes = process.argv.includes("--priority") ? [...PRIORITY_ROUTES] : [...PROGRAM_ROUTES];
  const bannerIndex = createBannerIndex(loadBanners());
  for (const route of routes) verifyStaticPage(route, bannerIndex);
  verifyGenerator(routes);
  await verifyResponsivePages(routes, bannerIndex);

  if (failures.length) {
    console.error(`Program hero verification failed (${failures.length}):`);
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log(`Program hero verification passed for ${routes.length} pages at desktop and mobile widths.`);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
