import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { carouselPrograms, loadProgramConfig } = require("../tools/program-factual-governance");
const { fileForRoute } = require("../tools/structured-data-utils");
const { assetDigest, verifyHomepageContent } = require("../tools/homepage-release-contract");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-decision-flow.json"), "utf8"));
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });
const mainText = $("main").text().replace(/\s+/gu, " ").trim();
const heroText = $("#hero").text().replace(/\s+/gu, " ").trim();

assert.equal($("main h1").length, 1, "homepage-ul trebuie să păstreze un singur H1");
assert.equal($("main h1").text().trim(), "Consultanță și proiectare pentru proiecte cu fonduri europene");
assert.match(heroText, /FABER – Atelier de Consultanță sprijină firme, fermieri, start-up-uri, IMM-uri și instituții publice/u, "hero-ul nu răspunde cine este FABER și pentru cine lucrează");
assert.match(heroText, /Consultanța clarifică eligibilitatea, programul, cererea și documentele; proiectarea corelează soluția tehnică, bugetul și anexele/u, "diferența dintre consultanță și proiectare nu este explicită");
assert.match(heroText, /sursele oficiale înainte de dosar/u, "metoda de verificare nu este vizibilă de la început");
assert.match(heroText, /pregătirea și implementarea, fără promisiunea aprobării finanțării/u, "traseul și limita serviciului nu sunt explicite");
assert.match($("#homepage-method").text(), /Verificăm în sursa oficială scopul și statutul programului/u);
assert.equal($("#homepage-explorer-title").text().trim(), "Alege informația de care ai nevoie");
assert.equal($("#homepage-contact-title").text().trim(), "Spune-ne solicitantul, localitatea și investiția");
assert.equal(config.reviewedAt, "2026-08-31", "revizia copy-ului homepage trebuie datată");
assert.equal($("#hero.im-hero").attr("data-homepage-revision"), "immersive-20260901-5", "build-ul trebuie să păstreze designul imersiv construit azi");
assert.equal($("#hero .im-lead").length, 1, "introducerea imersivă trebuie să rămână compactă");
assert.equal($("#hero .im-about .im-detail-copy").length, 1, "explicația completă rămâne în HTML și poate fi extinsă");
assert.match($("#hero .im-lead").text(), /Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar\./u);
assert.equal($("[data-program-scene]").length, 10);
assert.equal($(".im-method-sculpture .im-slab").length, 5);
assert.equal($("#homepage-contact #contact-triage-form").length, 1);
assert.equal($("#homepage-contact .im-contact-disclosure").attr("open"), undefined, "formularul trebuie să fie restrâns implicit pentru a păstra al cincilea cadru compact");

const requiredLinks = [
  "/verificare-eligibilitate-fonduri-europene",
  "/consultanta-fonduri-europene",
  "/proiectare-fonduri-europene",
  "/management-proiecte-fonduri-europene",
  "/calculator-soc",
  "/despre-faber",
  "/metodologie-verificare-eligibilitate",
  "/surse-oficiale-fonduri-europene",
  "/contact#source_page=%2F"
];
for (const href of requiredLinks) {
  assert.equal($("main a").filter((_, link) => $(link).attr("href") === href).length > 0, true, `lipsește traseul homepage ${href}`);
  const route = href.split("#")[0];
  assert.equal(fs.existsSync(fileForRoute(ROOT, route)), true, `ruta locală nu există pentru ${href}`);
}

assert.equal($(".homepage-service-grid .homepage-card").length, 4, "lista serviciilor trebuie păstrată");
assert.equal($(".homepage-tool-grid .homepage-card").length, 3, "lista instrumentelor trebuie păstrată");
assert.equal($(".homepage-proof-grid .homepage-card a").length, 3, "despre, sursele și metodologia trebuie să fie accesibile direct");
assert.doesNotMatch(mainText, /\b(?:lider(?:ul)?|numărul\s*1|cei\s+mai\s+buni|rată\s+de\s+succes|sume\s+atrase|garantăm\s+(?:aprobarea|finanțarea)|finanțare\s+garantată)\b/iu, "homepage-ul conține o afirmație internă sau neverificabilă");

const expectedPrograms = carouselPrograms(loadProgramConfig().programs);
const slides = $("[data-priority-slide]");
assert.equal(slides.length, expectedPrograms.length, "caruselul nu mai corespunde registrului unic");
slides.each((index, slide) => {
  const program = expectedPrograms[index];
  assert.equal($(slide).attr("data-program-id"), program.id);
  assert.equal($(slide).attr("data-program-status"), program.status);
  assert.equal($(slide).attr("data-verified-at"), program.verifiedAt);
  assert.equal($(slide).attr("data-source-url"), program.sourceUrl);
  assert.equal($(slide).find(".priority-program-link").attr("href"), program.pageUrl);
});

assert.equal($("head > title").text().trim(), "Consultanță și proiectare fonduri europene | FABER");
assert.equal($("meta[name='description']").attr("content"), "FABER oferă consultanță și proiectare pentru proiecte cu fonduri europene: eligibilitate, cereri de finanțare, documentații tehnice și implementare.");
assert.equal($("meta[name='keywords']").attr("content"), "fonduri europene, consultanță fonduri europene, PNRR, POR, AFIR, finanțare nerambursabilă, proiecte europene, fonduri nerambursabile România, consultanță finanțare, absorbție fonduri europene");
assert.equal($("link[rel='canonical']").attr("href"), "https://atelierdeconsultanta.ro/");
assert.equal($("meta[name='robots']").attr("content"), "index, follow");
assert.equal($("meta[property='og:title']").attr("content"), "Consultanță și proiectare pentru proiecte | FABER");
assert.equal($("meta[property='og:url']").attr("content"), "https://atelierdeconsultanta.ro/");
assert.equal($("script[type='application/ld+json']").length > 0, true, "lipsește JSON-LD");
$("script[type='application/ld+json']").each((_, script) => assert.doesNotThrow(() => JSON.parse($(script).text()), "JSON-LD invalid"));

assert.equal(verifyHomepageContent(html, html).revision, "immersive-20260901-5");
assert.equal(verifyHomepageContent(html, html).assets.length, 9);
assert.throws(() => verifyHomepageContent(html.replace("immersive-20260901-5\"", "old\""), html));
assert.throws(() => verifyHomepageContent(html.replace("Alege informația de care ai nevoie", "Ce oferă FABER și cum verifică informația"), html));
assert.throws(() => verifyHomepageContent(html.replace("data-homepage-method-indicator", "data-old-indicator"), html));
assert.throws(() => verifyHomepageContent(html.replace("homepage-decision-flow.js?v=20260901-5", "homepage-decision-flow.js?v=20260901-1"), html));
assert.throws(() => verifyHomepageContent(html.replace("data-program-scene=", "data-old-scene="), html));
assert.throws(() => verifyHomepageContent(html.replace("data-immersive-style", "data-old-style"), html));
assert.throws(() => verifyHomepageContent(html.replace('id="contact-triage-form"', 'id="old-form"'), html));
assert.throws(() => verifyHomepageContent(html.replace(".hero-subtitle__positioning {", ".old-hero-positioning {"), html));
assert.equal(assetDigest("a\r\nb"), assetDigest("a\nb"), "hash-ul trebuie să fie portabil între Windows și Cloudflare");

console.log(`Homepage clarity PASS: identitate, 5 publicuri, 4 servicii, 3 instrumente, metodologie, ${slides.length} programe și contact.`);
