import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function pageFile(route) {
  const slug = route.replace(/^\//u, "");
  const directoryFile = path.join(ROOT, slug, "index.html");
  if (fs.existsSync(directoryFile)) return directoryFile;
  const legacyFile = path.join(ROOT, `${slug}.html`);
  if (fs.existsSync(legacyFile)) return legacyFile;
  throw new Error(`Lipsește pagina ${route}`);
}

function loadPage(route) {
  return cheerio.load(fs.readFileSync(pageFile(route), "utf8"), { decodeEntities: false });
}

function clean(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function meta($, selector, attribute = "content") {
  return clean($(selector).first().attr(attribute));
}

function assertShareMetadata(route, $) {
  const required = [
    "meta[property='og:title']",
    "meta[property='og:description']",
    "meta[property='og:image']",
    "meta[property='og:image:alt']",
    "meta[name='twitter:title']",
    "meta[name='twitter:description']",
    "meta[name='twitter:image']",
    "meta[name='twitter:image:alt']",
  ];
  for (const selector of required) assert.equal($(selector).length, 1, `${route}: lipsește ${selector}`);
}

function assertUniqueH2(route, $) {
  const headings = $("h2").map((_, node) => clean($(node).text()).toLocaleLowerCase("ro-RO")).get();
  const duplicates = [...new Set(headings.filter((heading, index) => headings.indexOf(heading) !== index))];
  assert.deepEqual(duplicates, [], `${route}: H2 duplicate: ${duplicates.join(", ")}`);
}

for (const route of ["/gal-afir", "/femeia-antreprenor-2026", "/calculator-soc", "/dr12-afir", "/dr14", "/investitii-modernizarea-microintreprinderilor-apel-2"]) {
  const $ = loadPage(route);
  const title = clean($("head > title").first().text());
  const description = meta($, "meta[name='description']");
  assert.ok(title.length > 20 && title.length <= 65, `${route}: title neoptimizat (${title.length})`);
  assert.ok(description.length >= 70 && description.length <= 160, `${route}: descriere neoptimizată (${description.length})`);
  assert.equal($("h1").length, 1, `${route}: trebuie un singur H1`);
  assert.ok($("a[href^='https://']").length > 0, `${route}: lipsește o sursă externă verificabilă`);
  assertShareMetadata(route, $);
}

{
  const route = "/gal-afir";
  const $ = loadPage(route);
  assert.match(clean($("head > title").first().text()), /GAL AFIR 2026/iu);
  assert.match(clean($("h1").text()), /GAL AFIR \/ DR-36/iu);
  assert.equal($("a[href^='https://gal.afir.ro']").length > 0, true, `${route}: lipsește platforma oficială AFIR GAL`);
  assert.equal($("h2").filter((_, node) => /exemplu numeric de cofinanțare/iu.test(clean($(node).text()))).length, 0, `${route}: exemplul generic de cofinanțare nu este permis`);
  assertUniqueH2(route, $);
}

{
  const route = "/femeia-antreprenor-2026";
  const $ = loadPage(route);
  const text = clean($("main").text());
  assert.match(clean($("head > title").first().text()), /Femeia Antreprenor 2026/iu);
  assert.match(clean($("h1").text()), /Femeia Antreprenor 2026/iu);
  assert.match(text, /nu (?:există|are încă) o procedură/iu, `${route}: trebuie delimitată ediția 2026 neconfirmată`);
  assert.equal($("h2").filter((_, node) => /exemplu numeric de cofinanțare/iu.test(clean($(node).text()))).length, 0, `${route}: exemplul generic de cofinanțare nu este permis`);
}

{
  const route = "/calculator-soc";
  const $ = loadPage(route);
  const jsonLd = $("script[type='application/ld+json']").map((_, node) => $(node).text()).get().join("\n");
  assert.match(clean($("h1").text()), /Calculator SO(?:\/SOC)? .*AFIR/iu);
  assert.match(jsonLd, /WebApplication/u, `${route}: lipsește schema WebApplication`);
  assert.ok($("[data-aeo-direct-answer]").length >= 2, `${route}: sunt necesare răspunsuri directe reutilizabile`);
}

console.log("AI citation readiness contract: PASS");
