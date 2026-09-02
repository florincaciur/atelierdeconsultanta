import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { hasOfficialSource, homepageHeroPrograms, isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { latestVerifiedProgram } = require("../tools/sync-homepage-hero");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "homepage-hero.css"), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });
const { programs } = loadProgramConfig();
const latest = latestVerifiedProgram(programs);
const homepagePrograms = homepageHeroPrograms(programs);

assert(latest && isPublicProgram(latest) && hasOfficialSource(latest), "programul recent trebuie să fie public și verificat oficial");
assert.equal($("#hero.homepage-decision-hero").length, 1, "trebuie să existe exact un hero decizional");
assert.equal($("#homepage-hero-title").text().trim(), "Consultanță și proiectare pentru proiecte cu fonduri europene", "H1 diferit de copy-ul restaurat");
assert.match($("#hero .hero-subtitle").text().trim(), /^FABER – Atelier de Consultanță sprijină/u, "identitatea și rolul FABER lipsesc din hero");
assert.equal($("#hero .homepage-hero__microcopy").length, 0, "microcopy-ul redundant trebuie eliminat");

const primary = $("#hero .hero-ctas a").eq(0);
const secondary = $("#hero .hero-ctas a").eq(1);
assert.equal($("#hero .hero-ctas a").length, 2, "hero-ul trebuie să aibă exact două CTA-uri");
assert.equal(primary.text().trim(), "Începe verificarea proiectului");
assert.equal(primary.attr("href"), "/contact#source_page=%2F");
assert.equal(secondary.text().trim(), "Vezi ce date pregătești");
assert.equal(secondary.attr("href"), "/verificare-eligibilitate-fonduri-europene");
for (const [name, cta] of [["principal", primary], ["secundar", secondary]]) {
  assert.equal(cta.attr("data-analytics-event"), "cta_click", `CTA ${name}: lipsește cta_click`);
  assert.equal(cta.attr("data-analytics-cta-view"), "true", `CTA ${name}: lipsește cta_view`);
  assert.equal(cta.attr("data-analytics-copy-variant"), "p1_15", `CTA ${name}: variantă copy greșită`);
}

assert.equal($("#hero .hero-flow-svg, #hero .im-sculpture, #hero .im-program-drawer").length, 0, "roadmap-ul și sculptura din hero au fost înlocuite la cererea beneficiarului");
assert.deepEqual($("#hero [data-program-scene]").map((_, node) => $(node).attr("data-program-scene")).get(), homepagePrograms.map(program => program.id), "fiecare măsură trebuie să aibă o ilustrație proprie în ordinea registrului");
assert.equal($("#hero [data-hero-programs]").length, 1, "tabelul cu măsuri trebuie să fie unic și vizibil în hero");
assert.equal($("#hero [data-hero-program-item]").length, homepagePrograms.length, "meniul interactiv trebuie să corespundă selecției din registrul unic");
assert.equal($("#hero [data-hero-program-item][href='/dr14']").length, 1, "DR 14 trebuie publicat în meniul hero");
assert.equal($("#hero [data-program-scene='dr14-afir'] .pv-tractor").length, 1, "Scena DR 14 din homepage trebuie să includă tractorul animat");
assert.equal($("#hero [data-program-scene='dr14-afir'] .pv-field-bed").length, 1, "Scena DR 14 din homepage trebuie să includă un câmp");
assert.equal($("#hero [data-hero-program-item][href='/dr18']").length, 1, "DR 18 trebuie publicat în meniul hero");
assert.equal($("#hero [data-hero-program-item][href='/e-drive']").length, 1, "e-DRIVE trebuie publicat în meniul hero");
assert.equal($("#hero [data-hero-programs]").parents("details").length, 0, "tabelul nu trebuie ascuns într-un acordeon");
assert.equal($("#hero [data-hero-program-item][href='/por-adr-nord-est']").length, 0, "ruta regională duplicată nu trebuie publicată în hero");
assert.equal($("#hero [data-hero-program-item][href='/investitii-modernizarea-microintreprinderilor-apel-2']").length, 1, "pagina de conversie regională trebuie publicată în hero");
const latestNode = $("#hero [data-homepage-hero-latest-program]");
assert.equal(latestNode.attr("data-program-id"), latest.id, "programul recent nu corespunde registrului");
assert.equal(latestNode.attr("data-program-status"), latest.status, "statusul programului recent diferă");
assert.equal(latestNode.attr("data-verified-at"), latest.verifiedAt, "data programului recent diferă");
assert.equal(latestNode.attr("data-source-url"), latest.sourceUrl, "sursa programului recent diferă");
assert.equal(latestNode.attr("data-public-program-count"), String(programs.filter(isPublicProgram).length), "indicatorul registrului nu este calculat din sursa unică");
assert.equal($("#homepage-hero-critical-css").length, 1, "stilurile critice ale hero-ului trebuie incluse inline");
assert.equal($("link[href*='homepage-hero.css']").length, 0, "hero-ul nu trebuie să adauge o cerere CSS care blochează LCP");
assert.equal($("script[data-homepage-hero-script]").length, 1, "runtime-ul accesibil al meniului de măsuri lipsește");

assert.match(css, /font-size:\s*clamp\(3\.25rem,\s*4vw,\s*3\.5rem\)/, "lipsește intervalul desktop 52–56 px");
assert.match(css, /font-size:\s*clamp\(2\.25rem,\s*9\.5vw,\s*2\.625rem\)/, "lipsește intervalul mobil 36–42 px");
assert.match(css, /max-width:\s*64ch/, "textul nu este limitat la 60–68 caractere");
assert.match(css, /prefers-reduced-motion:\s*reduce/, "lipsește prefers-reduced-motion");

console.log(`Homepage hero contract PASS: tabel cu ${homepagePrograms.length} scene, 2 CTA-uri contextuale și registru ${latest.slug} (${latest.verifiedAt}).`);
