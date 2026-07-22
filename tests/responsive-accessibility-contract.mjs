import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const require = createRequire(import.meta.url);
const { findPublicHtmlFiles } = require("../tools/sync-global-header.js");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "responsive-accessibility.json"), "utf8"));
const globalCss = fs.readFileSync(path.join(ROOT, "assets", "global-header.css"), "utf8");
const designCss = fs.readFileSync(path.join(ROOT, "assets", "design-system.css"), "utf8");
const hubCss = fs.readFileSync(path.join(ROOT, "assets", "program-family-hubs.css"), "utf8");
const headerJs = fs.readFileSync(path.join(ROOT, "assets", "global-header.js"), "utf8");
const headerPartial = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8");
const calculator = fs.readFileSync(path.join(ROOT, "calculator-soc.html"), "utf8");

assert.equal(config.standard, "WCAG 2.2 AA");
assert.deepEqual(config.viewports.map(({ width }) => width), [320, 360, 390, 768, 1024, 1366]);
assert(config.viewports.some(({ orientation }) => orientation === "portrait"));
assert(config.viewports.some(({ orientation }) => orientation === "landscape"));
assert.equal(config.textResizePercent, 200);
assert.equal(config.minimumTargetCssPx, 24);
assert.equal(config.preferredMobileTargetCssPx, 44);
assert.equal(config.manualScreenReader.publicationState, "DE_VALIDAT_UMAN");

for (const route of config.routes) {
  const html = fs.readFileSync(path.join(ROOT, route.file), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });

  assert.match($("html").attr("lang") || "", /^ro(?:-|$)/iu, `${route.label}: lipsește lang=ro`);
  assert.equal($("main").length, 1, `${route.label}: trebuie să existe un singur main`);
  assert.equal($("main#main-content[tabindex='-1']").length, 1, `${route.label}: ținta skip-link lipsește`);
  assert.equal($("h1").length, 1, `${route.label}: trebuie să existe un singur H1`);
  assert.equal($("meta[name='description']").length, 1, `${route.label}: meta description lipsă/duplicat`);
  assert.equal($("link[rel='canonical']").length, 1, `${route.label}: canonical lipsă/duplicat`);
  assert.equal($("a.skip-link[href='#main-content']").length, 1, `${route.label}: skip link lipsă/duplicat`);

  const ids = new Map();
  $("[id]").each((_, element) => {
    const id = $(element).attr("id");
    ids.set(id, (ids.get(id) || 0) + 1);
  });
  assert.deepEqual([...ids].filter(([, count]) => count > 1), [], `${route.label}: ID-uri duplicate`);

  let previousLevel = 0;
  $("main h1, main h2, main h3, main h4, main h5, main h6").each((_, heading) => {
    const level = Number(heading.tagName.slice(1));
    if (previousLevel) assert(level <= previousLevel + 1, `${route.label}: salt de heading H${previousLevel} → H${level}`);
    previousLevel = level;
  });

  $("main table").each((_, table) => {
    const node = $(table);
    assert(
      node.find("caption").length || node.attr("aria-label") || node.attr("aria-labelledby"),
      `${route.label}: tabel fără caption/nume accesibil`
    );
  });

  $("main img").each((_, image) => {
    assert.notEqual($(image).attr("alt"), undefined, `${route.label}: imagine fără atribut alt`);
  });
  $("button").each((_, button) => {
    assert($(button).attr("aria-label") || $(button).text().trim(), `${route.label}: buton fără nume accesibil`);
  });
  $("main input:not([type='hidden']):not([name='website']), main select, main textarea").each((_, control) => {
    const node = $(control);
    const id = node.attr("id");
    assert(node.attr("aria-label") || (id && $(`label[for='${id}']`).length === 1), `${route.label}: control fără label (${id || control.tagName})`);
  });
  $("a[href]").each((_, link) => {
    const node = $(link);
    assert(node.attr("aria-label") || node.text().trim() || node.find("img[alt]").attr("alt"), `${route.label}: link fără nume accesibil`);
  });

  $("script[type='application/ld+json']").each((_, script) => {
    assert.doesNotThrow(() => JSON.parse($(script).text()), `${route.label}: JSON-LD invalid`);
  });
}

let publicDocumentsWithMain = 0;
for (const relativePath of findPublicHtmlFiles()) {
  const $ = cheerio.load(fs.readFileSync(path.join(ROOT, relativePath), "utf8"), { decodeEntities: false });
  if (!$("main").length) continue;
  publicDocumentsWithMain += 1;
  assert.equal($("main#main-content[tabindex='-1']").length, 1, `${relativePath}: țintă skip-link globală invalidă`);
  assert.equal($("a.skip-link[href='#main-content']").length, 1, `${relativePath}: skip-link global lipsă/duplicat`);
}

assert.match(globalCss, /\.global-skip-link/u, "stilul skip-link global lipsește");
assert.match(globalCss, /main#main-content:focus/u, "focusul țintei skip-link lipsește");
assert.match(globalCss, /min-height:\s*44px/u, "headerul global nu garantează ținte mobile de 44 px");
assert.match(globalCss, /prefers-reduced-motion:\s*reduce/u, "headerul nu respectă reduced motion");
assert.match(designCss, /:where\(#footer, footer, \.footer\)[^{]*\{\s*color:\s*#fff/u, "contrastul headingurilor din footer nu este protejat");
assert.match(designCss, /\.stars\s*\{\s*color:\s*var\(--ds-color-accent\)/u, "contrastul etichetelor din hero nu este protejat");
assert.match(designCss, /\.sr-only\s*\{/u, "clasa pentru labeluri vizual ascunse lipsește");
assert.match(hubCss, /\.program-family-how__cta h3\s*\{\s*color:\s*#fff/u, "contrastul CTA din hub nu este protejat");

assert.match(headerJs, /Escape/u, "meniul global nu tratează Escape");
assert.match(headerJs, /aria-expanded/u, "meniul global nu sincronizează aria-expanded");
assert.match(headerJs, /focus\(\)/u, "meniul global nu restaurează/gestionează focusul");
assert.match(headerJs, /target\.focus\(\{ preventScroll: true \}\)/u, "skip-link-ul nu mută focusul pe conținut");
assert.match(headerJs, /event\.key === "Tab"/u, "dialogul WhatsApp nu captează ciclic Tab");
assert.match(headerJs, /eligibilityDialogTrigger\.focus\(\)/u, "dialogul WhatsApp nu restaurează focusul");
{
  const $ = cheerio.load(headerPartial, { decodeEntities: false }, false);
  assert.equal($("#eligibility-whatsapp-dialog[role='dialog'][aria-modal='true'][aria-labelledby][hidden]").length, 1, "semantica dialogului WhatsApp este incompletă");
  assert.equal($("#eligibility-whatsapp-dialog [data-whatsapp-dialog-close]").length, 1, "dialogul WhatsApp nu are control de închidere");
}

assert.doesNotMatch(calculator, /class="topbar"/u, "calculatorul păstrează navigația legacy duplicată");
assert.match(calculator, /--orange:#b84716/u, "calculatorul nu folosește accentul cu contrast AA");
assert.match(calculator, /\.calc-wrapper\{[^}]*max-width:100%;min-width:0/u, "calculatorul nu este limitat la viewport");
assert.match(calculator, /\.calc-section\{[^}]*overflow-x:auto/u, "tabelele calculatorului nu au overflow local controlat");
{
  const $ = cheerio.load(calculator, { decodeEntities: false });
  const calculatorTables = $("#calculator table");
  assert.equal(calculatorTables.length, 4, "calculatorul trebuie să păstreze cele patru familii interactive");
  calculatorTables.each((_, table) => {
    assert.equal($(table).find("caption.sr-only").length, 1, "fiecare tabel interactiv trebuie denumit");
    assert($(table).attr("aria-labelledby"), "fiecare tabel interactiv trebuie asociat titlului său");
  });
  assert.equal($("#calculator .calc-result[role='status'][aria-live='polite']").length, 1, "rezultatul calculatorului nu este anunțat");
}
for (const label of ["Categorie pentru", "Coeficient SOC oficial pentru", "Cantitate în", "Șterge rândul din"]) {
  assert(calculator.includes(label), `calculator: lipsește eticheta dinamică „${label}”`);
}

console.log(`Responsive/accessibility contract PASS (${config.routes.length} rute × ${config.viewports.length} viewporturi declarate; ${publicDocumentsWithMain} pagini publice cu skip-link valid).`);
