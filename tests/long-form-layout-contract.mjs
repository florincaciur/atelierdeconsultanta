import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { CONFIG, countWords, removeInjected } = require("../tools/sync-long-form-layout");
const inventory = JSON.parse(fs.readFileSync(path.join(ROOT, CONFIG.inventoryPath), "utf8"));
const report = JSON.parse(fs.readFileSync(path.join(ROOT, CONFIG.reportPath), "utf8"));
const css = fs.readFileSync(path.join(ROOT, "assets", "long-form-layout.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "assets", "long-form-layout.js"), "utf8");
const homepage = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");

const normalizeRoute = (value) => {
  const route = String(value || "/").replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/)[0] || "/";
  return route === "/" ? route : route.replace(/\/$/, "");
};

const candidates = inventory.rows.filter((row) => CONFIG.forcedRoutes.includes(normalizeRoute(row.route)) || CONFIG.includedTypes.includes(row.type));
const expected = candidates.filter((row) => {
  const html = removeInjected(fs.readFileSync(path.join(ROOT, row.sourceFile), "utf8"));
  return CONFIG.forcedRoutes.includes(normalizeRoute(row.route)) || countWords(html, normalizeRoute(row.route)) > CONFIG.wordThreshold;
});

assert.equal(report.pageCount, expected.length, "raportul trebuie să includă toate paginile care depășesc pragul");
assert.equal(report.pages.length, expected.length);
assert(report.pages.some((page) => page.route === CONFIG.pilotRoute), "pagina pilot lipsește din raport");

for (const page of report.pages) {
  const html = fs.readFileSync(path.join(ROOT, page.sourceFile), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const root = page.variant === "home" ? $("main").first() : ($("main").first().length ? $("main").first() : $(".post-container").first());

  assert.equal($("body[data-long-form-page='true']").length, 1, `${page.route}: lipsește metadata layout`);
  assert.equal($("body").attr("data-long-form-type"), page.type, `${page.route}: tip greșit`);
  assert.equal(root.attr("data-long-form-layout"), page.variant, `${page.route}: variantă greșită`);
  assert.equal(root.attr("data-long-form-content"), "true", `${page.route}: containerul editorial nu este marcat`);
  const toc = $("[data-long-form-toc]");
  const tocExcluded = CONFIG.tocExcludedRoutes.includes(page.route);
  assert.equal(toc.length, page.route === "/" || tocExcluded ? 0 : 1, `${page.route}: număr incorect de cuprinsuri`);
  assert.equal($(".article-toc").length, 0, `${page.route}: cuprinsul vechi duplicat trebuie eliminat`);
  assert.equal($("link[data-long-form-layout-style='p1_09']").length, 1, `${page.route}: CSS duplicat/lipsă`);
  assert.equal($("script[data-long-form-layout-script='p1_09']").length, 1, `${page.route}: JS duplicat/lipsă`);
  if (page.route !== "/" && !tocExcluded) {
    assert.equal($("[data-long-form-toc] summary").text().trim(), "Cuprins", `${page.route}: disclosure fără etichetă`);
    assert.equal($("[data-long-form-toc] details[open]").length, 0, `${page.route}: cuprinsul trebuie să pornească închis ca dropdown`);
    assert.equal(toc.find("nav").attr("aria-label"), "Cuprinsul paginii");

    const links = toc.find("[data-long-form-toc-link]");
    assert.equal(links.length, page.tocItemCount, `${page.route}: numărul de ancore diferă de raport`);
    assert(links.length >= 3, `${page.route}: cuprins prea scurt`);
    assert.equal(links.first().attr("aria-current"), "location", `${page.route}: prima secțiune nu are stare inițială`);
    links.each((_, link) => {
    const href = $(link).attr("href");
      assert(href?.startsWith("#"), `${page.route}: linkul de cuprins nu este ancoră`);
    const selector = `#${new URL(href, "https://atelierdeconsultanta.ro/").hash.slice(1)}`;
    assert.equal($(selector).length, 1, `${page.route}: ținta ${href} lipsește sau este duplicată`);
    });
  }

  const ids = $("[id]").map((_, node) => $(node).attr("id")).get();
  assert.equal(new Set(ids).size, ids.length, `${page.route}: ID-uri duplicate`);
  const scopedTables = root.find("table");
  scopedTables.each((_, table) => {
    const region = $(table).closest(".long-form-table-region");
    assert.equal(region.length, 1, `${page.route}: tabel fără wrapper responsive`);
    assert.equal(region.attr("role"), "region");
    assert.equal(region.attr("tabindex"), "0");
    assert(region.attr("aria-label"), `${page.route}: regiune de tabel fără nume`);
  });

  assert.equal(countWords(removeInjected(html), page.route), page.wordCount, `${page.route}: conținutul editorial a fost redus`);

  root.find(".long-form-secondary-detail").each((_, detail) => {
    assert.equal($(detail).prop("tagName"), "DETAILS", `${page.route}: detaliul secundar trebuie să fie nativ`);
    assert($(detail).children("summary").text().trim(), `${page.route}: FAQ fără summary`);
    assert($(detail).find(".long-form-secondary-detail__body").text().trim(), `${page.route}: conținutul FAQ nu trebuie eliminat`);
  });

  if (page.decisionActionAdded) {
    const action = $(".long-form-decision-action");
    assert.equal(action.length, 1, `${page.route}: lipsește acțiunea după rezumat`);
    const link = action.find("a");
    assert.equal(link.text().trim(), "Verifică proiectul");
    assert.equal(link.attr("data-analytics-event"), "cta_click");
    assert.equal(link.attr("data-analytics-component"), "long_form_decision");
    assert(link.attr("data-analytics-program-slug"));
    const actionIndex = html.indexOf("<!-- P1_09_DECISION_ACTION_START -->");
    const summaryEnd = [html.indexOf("<!-- ANSWER_READINESS_END -->"), html.indexOf("<!-- PROGRAM_FACTUAL_STATUS_END -->")]
      .filter((index) => index >= 0 && index < actionIndex)
      .sort((left, right) => right - left)[0];
    assert(Number.isInteger(summaryEnd), `${page.route}: CTA-ul trebuie să urmeze rezumatului`);
  }
}

const excluded = candidates.filter((row) => !expected.some((page) => page.sourceFile === row.sourceFile));
for (const row of excluded) {
  const html = fs.readFileSync(path.join(ROOT, row.sourceFile), "utf8");
  assert(!html.includes("data-long-form-page"), `${row.route}: pagina sub prag nu trebuie instrumentată`);
}

assert(css.includes("max-inline-size: 68ch"), "lipsește limita editorială de 68ch");
assert(css.includes("position: sticky") && css.includes("scroll-margin-top"), "lipsește comportamentul sticky/offset pentru ancore");
assert(css.includes("overflow-x: auto") && css.includes("min-height: 44px"), "lipsesc tabelele responsive sau targetul mobil");
assert(css.includes("@media (max-width: 63.99rem)"), "lipsește disclosure/reflow mobil");
assert(css.includes(".long-form-secondary-detail") && css.includes("font-size: clamp(1.55rem"), "lipsește compactarea detaliilor secundare");
assert(js.includes("IntersectionObserver") && js.includes('aria-current", "location"'), "starea secțiunii nu este actualizată");
assert(js.includes('matchMedia("(max-width: 63.99rem)")') && js.includes('removeAttribute("open")'), "fallback-ul mobil trebuie să păstreze disclosure-ul compact");
assert(js.includes('event.key !== "Enter"') && js.includes('event.key !== " "') && js.includes("disclosure.open = !disclosure.open"), "disclosure-ul trebuie activabil cu Enter și Spațiu");
assert(!/link\.addEventListener\("click"[\s\S]{0,220}preventDefault/.test(js), "ancorele native nu trebuie interceptate");
assert(homepage.includes("target.scrollIntoView") && homepage.includes("window.history.pushState"), "homepage-ul trebuie să păstreze ancora stabilă și scroll-margin-ul nativ");
assert((homepage.match(/<!-- HOMEPAGE_DECISION_HERO_END -->/g) || []).length === 1, "markerul de închidere al hero-ului trebuie să existe o singură dată");
assert.equal((homepage.match(/<!-- P1_09_LONG_FORM_TOC_START -->/g) || []).length, 0, "homepage-ul nu trebuie să păstreze un cuprins separat după hero");
assert(!homepage.includes("data-homepage-navbar-toc"), "cuprinsul homepage-ului nu trebuie să reapară în navbar");

console.log(`Long-form layout contract PASS: ${report.pageCount} pagini, ${report.pages.reduce((sum, page) => sum + page.tocItemCount, 0)} ancore și conținut păstrat integral.`);
