#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const DIST_ROOT = path.join(ROOT, "dist");
const SITE = "https://atelierdeconsultanta.ro";
const LIVE = process.argv.includes("--live");
const DIST = process.argv.includes("--dist");
assert(!(LIVE && DIST), "--live and --dist are mutually exclusive");
const { carouselPrograms, catalogPrograms, cofinancingSummaryText, grantSummaryText, isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { fileForRoute } = require("../tools/structured-data-utils");
const seo = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
const familyConfig = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8"));
const legalIdentity = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "legal-identity.json"), "utf8"));
const { programs } = loadProgramConfig();

const programPages = programs.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
const programRoutes = new Set(programPages.map((program) => program.pageUrl));
const programByRoute = new Map(programPages.map((program) => [program.pageUrl, program]));
const familyRoutes = new Set(familyConfig.hubs.map((hub) => hub.route));
const services = seo.pages
  .filter((page) => page.type === "service" && !page.redirectTo)
  .map((page) => `/${page.slug}`);
const fixedRoutes = [
  "/",
  ...familyRoutes,
  ...services,
  "/calculator-soc",
  "/contact",
  "/despre-faber",
  "/gdpr",
  "/politica-de-confidentialitate",
  "/termeni-si-conditii"
];
const routes = [...new Set([...fixedRoutes, ...programRoutes])];
const catalog = catalogPrograms(programs);
const carousel = carouselPrograms(programs);
const programRouteList = [...programRoutes];

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function comparable(value) {
  return cleanText(value).normalize("NFC");
}

function questionKey(value) {
  return cleanText(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/gu, "")
    .replace(/[^a-z0-9]+/giu, " ")
    .trim()
    .toLowerCase();
}

function normalizedHref(value, base = SITE) {
  if (!value) return "";
  try {
    const url = new URL(value, base);
    if (url.origin === SITE || url.origin.startsWith("http://127.0.0.1:")) {
      return `${url.pathname === "/" ? "/" : url.pathname.replace(/\/$/u, "")}${url.search}${url.hash}`;
    }
    return url.href;
  } catch {
    return String(value);
  }
}

function sortedUnique(values) {
  return [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right, "ro"));
}

function faqSchemaQuestionsFromCheerio($) {
  const questions = [];
  $("script[type='application/ld+json']").each((_, element) => {
    try {
      const data = JSON.parse($(element).html().trim());
      const visit = (node) => {
        if (!node || typeof node !== "object") return;
        if (Array.isArray(node)) return node.forEach(visit);
        const types = Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]];
        if (types.includes("FAQPage")) {
          for (const item of node.mainEntity || []) questions.push(cleanText(item?.name));
        }
        for (const value of Object.values(node)) visit(value);
      };
      visit(data);
    } catch {
      // Invalid JSON-LD is covered by the existing structured-data gate.
    }
  });
  return sortedUnique(questions);
}

function cheerioSnapshot(html, base) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const bodyClone = $("body").clone();
  bodyClone.find("script,style,template,noscript").remove();
  const bodyText = comparable(bodyClone.text());
  const answerSelectors = [
    "[data-aeo-direct-answer]",
    ".aeo-direct-answer",
    ".direct-answer",
    ".answer-first",
    ".core-lead__copy p",
    "header.hero > p",
    ".hero-content > p",
    ".hero > p",
    "main p"
  ];
  let answer = "";
  for (const selector of answerSelectors) {
    answer = cleanText($(selector).first().text());
    if (answer) break;
  }
  const officialSelector = [
    "main a[data-aeo-official-source]",
    "main a[data-analytics-event='source_document_click']",
    "main .program-family-card__source[href]",
    "main .program-factual-status a[href]"
  ].join(",");
  const faqSelector = [
    "main details:not([data-non-faq]) > summary",
    "main .faq-item h2",
    "main .faq-item h3",
    "main .faq-item h4",
    "main [itemprop='mainEntity'] [itemprop='name']"
  ].join(",");
  const programLinks = $("main a[href]").map((_, element) => normalizedHref($(element).attr("href"), base)).get()
    .filter((href) => programRoutes.has(href));
  const statuses = $("main [data-program-id][data-program-status], body[data-program-id][data-program-status]").map((_, element) => ({
    id: $(element).attr("data-program-id") || "",
    status: $(element).attr("data-program-status") || "",
    label: $(element).attr("data-status-label") || ""
  })).get();
  return {
    title: cleanText($("title").first().text()),
    h1Count: $("h1").length,
    h1: cleanText($("h1").first().text()),
    answer,
    bodyText,
    breadcrumbs: $("nav.breadcrumb[aria-label='Breadcrumb'] li").map((_, element) => ({
      text: cleanText($(element).text()),
      href: normalizedHref($(element).find("a[href]").attr("href"), base)
    })).get(),
    faqQuestions: sortedUnique($(faqSelector).map((_, element) => cleanText($(element).text())).get().filter((question) => !/^Vezi încă \d+ carduri$/iu.test(question))),
    faqSchemaQuestions: faqSchemaQuestionsFromCheerio($),
    officialLinks: sortedUnique($(officialSelector).map((_, element) => normalizedHref($(element).attr("href"), base)).get()),
    programLinks: sortedUnique(programLinks),
    statuses: statuses.filter((item, index) => statuses.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(item)) === index),
    carousel: $("[data-priority-slide]").map((_, element) => ({
      id: $(element).attr("data-program-id") || "",
      status: $(element).attr("data-program-status") || "",
      title: cleanText($(element).find("h3").first().text()),
      href: normalizedHref($(element).find(".priority-program-link[href]").attr("href"), base)
    })).get()
  };
}

async function browserSnapshot(page, url) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
  assert(response, `${url}: browser navigation did not return a response`);
  assert.equal(response.status(), 200, `${url}: browser status must be 200`);
  await page.waitForTimeout(75);
  return page.evaluate(({ canonicalSite, knownProgramRoutes }) => {
    const clean = (value) => String(value || "").replace(/\s+/gu, " ").trim();
    const normalizeHref = (value) => {
      if (!value) return "";
      try {
        const urlValue = new URL(value, location.href);
        if (urlValue.origin === canonicalSite || urlValue.hostname === "127.0.0.1") {
          return `${urlValue.pathname === "/" ? "/" : urlValue.pathname.replace(/\/$/u, "")}${urlValue.search}${urlValue.hash}`;
        }
        return urlValue.href;
      } catch {
        return String(value);
      }
    };
    const unique = (values) => [...new Set(values.filter(Boolean))].sort((left, right) => left.localeCompare(right, "ro"));
    const bodyClone = document.body.cloneNode(true);
    bodyClone.querySelectorAll("script,style,template,noscript").forEach((element) => element.remove());
    const answerSelectors = [
      "[data-aeo-direct-answer]",
      ".aeo-direct-answer",
      ".direct-answer",
      ".answer-first",
      ".core-lead__copy p",
      "header.hero > p",
      ".hero-content > p",
      ".hero > p",
      "main p"
    ];
    let answer = "";
    for (const selector of answerSelectors) {
      answer = clean(document.querySelector(selector)?.textContent);
      if (answer) break;
    }
    const faqSchemaQuestions = [];
    for (const element of document.querySelectorAll("script[type='application/ld+json']")) {
      try {
        const visit = (node) => {
          if (!node || typeof node !== "object") return;
          if (Array.isArray(node)) return node.forEach(visit);
          const types = Array.isArray(node["@type"]) ? node["@type"] : [node["@type"]];
          if (types.includes("FAQPage")) {
            for (const item of node.mainEntity || []) faqSchemaQuestions.push(clean(item?.name));
          }
          for (const value of Object.values(node)) visit(value);
        };
        visit(JSON.parse(element.textContent));
      } catch {
        // Invalid JSON-LD is covered by the existing structured-data gate.
      }
    }
    const all = (selector) => [...document.querySelectorAll(selector)];
    const statusItems = all("main [data-program-id][data-program-status], body[data-program-id][data-program-status]").map((element) => ({
      id: element.getAttribute("data-program-id") || "",
      status: element.getAttribute("data-program-status") || "",
      label: element.getAttribute("data-status-label") || ""
    }));
    return {
      title: clean(document.title),
      h1Count: all("h1").length,
      h1: clean(document.querySelector("h1")?.textContent),
      answer,
      bodyText: clean(bodyClone.textContent).normalize("NFC"),
      breadcrumbs: all("nav.breadcrumb[aria-label='Breadcrumb'] li").map((element) => ({
        text: clean(element.textContent),
        href: normalizeHref(element.querySelector("a[href]")?.getAttribute("href"))
      })),
      faqQuestions: unique(all("main details:not([data-non-faq]) > summary, main .faq-item h2, main .faq-item h3, main .faq-item h4, main [itemprop='mainEntity'] [itemprop='name']").map((element) => clean(element.textContent)).filter((question) => !/^Vezi încă \d+ carduri$/iu.test(question))),
      faqSchemaQuestions: unique(faqSchemaQuestions),
      officialLinks: unique(all("main a[data-aeo-official-source], main a[data-analytics-event='source_document_click'], main .program-family-card__source[href], main .program-factual-status a[href]").map((element) => normalizeHref(element.getAttribute("href")))),
      programLinks: unique(all("main a[href]").map((element) => normalizeHref(element.getAttribute("href"))).filter((href) => knownProgramRoutes.includes(href))),
      statuses: statusItems.filter((item, index) => statusItems.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(item)) === index),
      carousel: all("[data-priority-slide]").map((element) => ({
        id: element.getAttribute("data-program-id") || "",
        status: element.getAttribute("data-program-status") || "",
        title: clean(element.querySelector("h3")?.textContent),
        href: normalizeHref(element.querySelector(".priority-program-link[href]")?.getAttribute("href"))
      }))
    };
  }, { canonicalSite: SITE, knownProgramRoutes: programRouteList });
}

function contentType(file) {
  const extension = path.extname(file).toLowerCase();
  return ({
    ".css": "text/css; charset=utf-8",
    ".gif": "image/gif",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".xml": "application/xml; charset=utf-8"
  })[extension] || "application/octet-stream";
}

function localFile(pathname) {
  const decoded = decodeURIComponent(pathname);
  if (DIST) {
    const relative = decoded.replace(/^\//u, "");
    const candidates = routes.includes(decoded)
      ? decoded === "/"
        ? [path.join(DIST_ROOT, "index.html")]
        : [path.join(DIST_ROOT, `${relative}.html`), path.join(DIST_ROOT, relative, "index.html")]
      : [path.resolve(DIST_ROOT, `.${decoded}`)];
    return candidates.find((candidate) => (
      candidate !== DIST_ROOT
      && candidate.startsWith(`${DIST_ROOT}${path.sep}`)
      && fs.existsSync(candidate)
      && fs.statSync(candidate).isFile()
    )) || null;
  }
  if (routes.includes(decoded)) return fileForRoute(ROOT, decoded);
  const resolved = path.resolve(ROOT, `.${decoded}`);
  if (resolved !== ROOT && !resolved.startsWith(`${ROOT}${path.sep}`)) return null;
  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) return resolved;
  if (!path.extname(decoded)) {
    const canonical = fileForRoute(ROOT, decoded);
    if (fs.existsSync(canonical)) return canonical;
  }
  return null;
}

async function startServer() {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    if (url.pathname.startsWith("/api/")) {
      response.writeHead(204, { "Cache-Control": "no-store" });
      response.end();
      return;
    }
    const file = localFile(url.pathname);
    if (!file) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": contentType(file) });
    fs.createReadStream(file).pipe(response);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address === "object", "local prerender server did not expose an address");
  return { server, base: `http://127.0.0.1:${address.port}` };
}

function assertCriticalContent(route, snapshot) {
  assert.equal(snapshot.h1Count, 1, `${route}: exactly one H1 must exist in fetched HTML`);
  assert(snapshot.h1.length >= 3, `${route}: H1 is empty`);
  assert(snapshot.title.length >= 10, `${route}: document title is empty`);
  assert(snapshot.answer.length >= 20, `${route}: answer-first summary is missing from normal HTML`);
  if (route !== "/") {
    assert(snapshot.breadcrumbs.length >= 2, `${route}: visible breadcrumb is missing from normal HTML`);
    assert.equal(snapshot.breadcrumbs[0].href, "/", `${route}: breadcrumb must start at homepage`);
  }
  const visibleQuestionKeys = new Set(snapshot.faqQuestions.map(questionKey));
  for (const question of snapshot.faqSchemaQuestions) {
    assert(visibleQuestionKeys.has(questionKey(question)), `${route}: FAQ schema question is not visible in normal HTML: ${question}`);
  }

  const program = programByRoute.get(route);
  if (program) {
    assert(snapshot.bodyText.includes(comparable(program.shortName)) || snapshot.bodyText.includes(comparable(program.name)), `${route}: program title is missing`);
    assert(snapshot.bodyText.includes(comparable(program.statusLabel)), `${route}: program status label is missing`);
    assert(snapshot.statuses.some((item) => item.id === program.id && item.status === program.status), `${route}: program status record is missing`);
    assert(snapshot.officialLinks.includes(program.sourceUrl), `${route}: official source link is missing`);
    for (const value of [grantSummaryText(program), cofinancingSummaryText(program)].filter(Boolean)) {
      assert(snapshot.bodyText.includes(comparable(value)), `${route}: registry key value is missing from normal HTML: ${value}`);
    }
  }

  if (familyRoutes.has(route)) {
    const expected = catalog.filter((programItem) => programItem.discovery.parentHub === route);
    for (const programItem of expected) {
      assert(snapshot.programLinks.includes(programItem.pageUrl), `${route}: family program link missing for ${programItem.id}`);
      assert(snapshot.officialLinks.includes(programItem.sourceUrl), `${route}: family official source missing for ${programItem.id}`);
    }
  }

  if (route === "/") {
    assert.deepEqual(snapshot.carousel.map((item) => item.id), carousel.map((programItem) => programItem.id), "homepage: every carousel program must be discoverable without interaction");
    assert.deepEqual(snapshot.carousel.map((item) => item.href), carousel.map((programItem) => programItem.pageUrl), "homepage: carousel canonical links differ from registry");
  }

  if (route === "/calculator-soc") {
    assert(snapshot.officialLinks.length >= 1, `${route}: official methodology/source link is missing`);
  }

  if (["/contact", "/despre-faber", "/politica-de-confidentialitate", "/termeni-si-conditii"].includes(route)) {
    const legalName = comparable(legalIdentity.fields.legalName.approvedValue);
    const taxIdentifier = comparable(legalIdentity.fields.taxIdentifier.approvedValue);
    assert(snapshot.bodyText.includes(legalName), `${route}: approved legal name is missing`);
    assert(snapshot.bodyText.includes(taxIdentifier), `${route}: approved tax identifier is missing`);
  }
}

function assertNoCrawlerSpecificRendering() {
  const files = [path.join(ROOT, "cloudflare", "domain-seo-redirects.mjs")];
  const stack = [path.join(ROOT, "assets")];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(target);
      else if (entry.isFile() && entry.name.endsWith(".js")) files.push(target);
    }
  }
  const forbidden = /navigator\.userAgent|user-agent|cf\.client\.bot|googlebot|bingbot|isbot/iu;
  for (const file of files) {
    assert.doesNotMatch(fs.readFileSync(file, "utf8"), forbidden, `${path.relative(ROOT, file)}: crawler-specific rendering is forbidden`);
  }
  for (const route of routes) {
    const html = fs.readFileSync(fileForRoute(ROOT, route), "utf8");
    const $ = cheerio.load(html);
    assert.doesNotMatch($("script:not([src])").text(), forbidden, `${route}: inline crawler-specific rendering is forbidden`);
  }
}

assert.equal(programPages.length, 24, "program-page scope changed; review the prerender contract explicitly");
assert.equal(familyRoutes.size, 5, "family-page scope changed; review the prerender contract explicitly");
assert.equal(services.length, 7, "service-page scope changed; review the prerender contract explicitly");
assert.equal(routes.length, 42, "critical prerender route scope changed; review the contract explicitly");
for (const route of routes) assert(fs.existsSync(fileForRoute(ROOT, route)), `${route}: canonical source HTML is missing`);
assertNoCrawlerSpecificRendering();

let local;
let browser;
try {
  local = LIVE ? null : await startServer();
  const base = LIVE ? SITE : local.base;
  browser = await chromium.launch({ headless: true });
  const jsOffContext = await browser.newContext({ javaScriptEnabled: false });
  const jsOnContext = await browser.newContext({ javaScriptEnabled: true });
  for (const context of [jsOffContext, jsOnContext]) {
    await context.route("**/*", (route) => {
      const requestUrl = new URL(route.request().url());
      if (requestUrl.origin === base || (LIVE && requestUrl.origin === SITE)) return route.continue();
      return route.abort();
    });
  }
  const jsOffPage = await jsOffContext.newPage();
  const jsOnPage = await jsOnContext.newPage();

  for (const route of routes) {
    const url = `${base}${route}`;
    const rawResponse = await fetch(url, { headers: { "User-Agent": "FABER-Prerender-Contract/1.0" } });
    assert.equal(rawResponse.status, 200, `${route}: fetched HTML status must be 200`);
    assert.match(rawResponse.headers.get("content-type") || "", /text\/html/iu, `${route}: fetched response must be HTML`);
    const raw = cheerioSnapshot(await rawResponse.text(), base);
    assertCriticalContent(route, raw);
    const jsOff = await browserSnapshot(jsOffPage, url);
    const jsOn = await browserSnapshot(jsOnPage, url);
    const criticalKeys = ["title", "h1Count", "h1", "answer", "breadcrumbs", "faqQuestions", "faqSchemaQuestions", "officialLinks", "programLinks", "statuses", "carousel"];
    for (const key of criticalKeys) {
      assert.deepEqual(jsOff[key], raw[key], `${route}: ${key} differs between fetched HTML and DOM without JavaScript`);
      assert.deepEqual(jsOn[key], raw[key], `${route}: ${key} differs after JavaScript hydration`);
    }
  }

  await jsOffContext.close();
  await jsOnContext.close();
  const mode = LIVE ? "live" : DIST ? "dist" : "local";
  console.log(`Prerender critical-content contract PASS (${mode}): ${routes.length} routes, fetched HTML = JS-off DOM = hydrated critical DOM; ${carousel.length} carousel programs discoverable without interaction.`);
} finally {
  if (browser) await browser.close();
  if (local) await new Promise((resolve) => local.server.close(resolve));
}
