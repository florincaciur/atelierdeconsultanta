import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const cheerio = require("cheerio");
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "editorial-clusters.json"), "utf8"));
const pages = config.clusters.flatMap((cluster) => cluster.routes.map((page) => ({ ...page, clusterId: cluster.id })));
const sitemapXml = fs.readdirSync(ROOT)
  .filter((file) => /^sitemap.*\.xml$/u.test(file))
  .map((file) => fs.readFileSync(path.join(ROOT, file), "utf8"))
  .join("\n");

const routes = new Set();
const intents = new Set();
const topicOwners = new Map();

for (const page of pages) {
  assert.ok(!routes.has(page.route), `${page.route}: ruta trebuie să fie unică`);
  routes.add(page.route);
  assert.ok(!intents.has(page.intentId), `${page.route}: intenția trebuie să fie unică`);
  intents.add(page.intentId);
  for (const topic of page.ownedTopics || []) {
    assert.ok(!topicOwners.has(topic), `${page.route}: tema ${topic} este deținută și de ${topicOwners.get(topic)}`);
    topicOwners.set(topic, page.route);
  }
}

const expectedRoles = new Map([
  ["/fonduri-europene", "hub"],
  ["/fonduri-nerambursabile", "guide"],
  ["/digitalizare-imm", "canonical_program_hub"],
  ["/granturi-digitalizare-imm", "redirect_candidate"],
  ["/cheltuieli-eligibile-digitalizare-imm", "guide"],
  ["/eligibilitate-fonduri-europene", "guide"],
  ["/verificare-eligibilitate-fonduri-europene", "service"]
]);

for (const [route, role] of expectedRoles) {
  assert.equal(pages.find((page) => page.route === route)?.role, role, `${route}: rol editorial greșit`);
}

for (const page of pages.filter((entry) => entry.render)) {
  const html = fs.readFileSync(path.join(ROOT, page.file), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const canonical = `https://atelierdeconsultanta.ro${page.route}`;
  assert.equal($("title").first().text().trim(), page.title, `${page.route}: title nesincronizat`);
  assert.equal($("meta[name='description']").first().attr("content"), page.description, `${page.route}: meta nesincronizat`);
  assert.equal($("meta[property='og:title']").first().attr("content"), page.ogTitle || page.title, `${page.route}: og:title nesincronizat`);
  assert.equal($("meta[property='og:description']").first().attr("content"), page.ogDescription || page.description, `${page.route}: og:description nesincronizat`);
  if (page.ogTitle) assert.equal($("meta[name='twitter:title']").first().attr("content"), page.ogTitle, `${page.route}: twitter:title nesincronizat`);
  if (page.ogDescription) assert.equal($("meta[name='twitter:description']").first().attr("content"), page.ogDescription, `${page.route}: twitter:description nesincronizat`);
  assert.equal($("link[rel='canonical']").first().attr("href"), canonical, `${page.route}: canonical greșit`);
  assert.ok(!/noindex/i.test($("meta[name='robots']").first().attr("content") || ""), `${page.route}: pagina publică este noindex`);
  assert.equal($("h1").length, 1, `${page.route}: trebuie să existe un singur H1`);
  assert.equal($("h1").first().text().trim(), page.h1, `${page.route}: H1 nesincronizat`);
  assert.equal($("[data-direct-answer]").first().text().trim(), page.directAnswer, `${page.route}: răspuns direct nesincronizat`);
  assert.equal($("article .editorial-cluster__cta").length, 1, `${page.route}: trebuie să existe un singur CTA comercial`);
  assert.equal($("article .editorial-cluster__source-note").length, 1, `${page.route}: trebuie să existe o singură notă despre surse`);
  assert.equal($("article .core-card, article .design-card, article .mini-card").length, 0, `${page.route}: au rămas carduri generice`);
  assert.equal($("body").attr("data-primary-intent"), page.intentId, `${page.route}: intenția nu este expusă pentru QA`);
  assert.match(sitemapXml, new RegExp(`<loc>https://atelierdeconsultanta\\.ro${page.route}</loc>`, "u"), `${page.route}: lipsește din sitemap`);

  const jsonLdNodes = $("script[type='application/ld+json']").toArray().flatMap((element) => {
    const parsed = JSON.parse($(element).html());
    return Array.isArray(parsed["@graph"]) ? parsed["@graph"] : [parsed];
  });
  assert.ok(jsonLdNodes.length > 0, `${page.route}: JSON-LD lipsește`);
  assert.ok(
    jsonLdNodes.some((node) => node.url === canonical || node["@id"] === canonical || String(node["@id"] || "").startsWith(`${canonical}#`)),
    `${page.route}: JSON-LD nu indică URL-ul canonic`
  );
  assert.ok(!jsonLdNodes.some((node) => node["@type"] === "FAQPage"), `${page.route}: FAQPage nu trebuie păstrat fără FAQ vizibil`);
}

const readArticle = (route) => {
  const page = pages.find((entry) => entry.route === route);
  const html = fs.readFileSync(path.join(ROOT, page.file), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  return $("article").first().text().replace(/\s+/gu, " ").trim();
};

const fundsHub = readArticle("/fonduri-europene");
const grantGuide = readArticle("/fonduri-nerambursabile");
assert.match(fundsHub, /Alege familia de programe/u, "Hubul Fonduri trebuie să organizeze familiile");
assert.doesNotMatch(fundsHub, /Cash-flow-ul arată când trebuie să existe banii/u, "Hubul nu trebuie să dubleze ghidul financiar");
assert.match(grantGuide, /Grantul nu este același lucru cu bugetul proiectului/u, "Ghidul financiar trebuie să explice grantul");
assert.match(grantGuide, /Avans \/ prefinanțare/u, "Ghidul financiar trebuie să explice prefinanțarea");

const eligibilityGuide = readArticle("/eligibilitate-fonduri-europene");
const eligibilityService = readArticle("/verificare-eligibilitate-fonduri-europene");
assert.match(eligibilityGuide, /Checklist de autoevaluare/u, "Ghidul trebuie să conțină checklistul");
assert.doesNotMatch(eligibilityGuide, /Ce conține livrabilul/u, "Ghidul nu trebuie să dubleze livrabilul serviciului");
assert.match(eligibilityService, /Ce conține livrabilul/u, "Serviciul trebuie să descrie livrabilul");
assert.match(eligibilityService, /Cum se desfășoară verificarea/u, "Serviciul trebuie să descrie procesul");

const digitalMain = pages.find((page) => page.route === "/digitalizare-imm");
const digitalDuplicate = pages.find((page) => page.route === "/granturi-digitalizare-imm");
const digitalMainHtml = fs.readFileSync(path.join(ROOT, digitalMain.file), "utf8");
const digitalMainDocument = cheerio.load(digitalMainHtml, { decodeEntities: false });
assert.doesNotMatch(digitalMainDocument("meta[name='robots']").first().attr("content") || "", /noindex/i, "/digitalizare-imm: pagina aprobată trebuie să fie indexabilă");
assert.equal(digitalMain.publicationState, "public", "/digitalizare-imm: aprobarea factuală trebuie reflectată în cluster");
assert.equal(digitalMain.render, false, "/digitalizare-imm: pagina rămâne randată din registrul programelor, nu din copy-ul clusterului");
assert.match(sitemapXml, /<loc>https:\/\/atelierdeconsultanta\.ro\/digitalizare-imm<\/loc>/u, "/digitalizare-imm: pagina aprobată trebuie să intre în sitemap");

const digitalDuplicateHtml = fs.readFileSync(path.join(ROOT, digitalDuplicate.file), "utf8");
const digitalDuplicateDocument = cheerio.load(digitalDuplicateHtml, { decodeEntities: false });
assert.match(digitalDuplicateDocument("meta[name='robots']").first().attr("content") || "", /noindex/i, "/granturi-digitalizare-imm: poarta factuală trebuie păstrată");
assert.equal(digitalDuplicate.render, false, "/granturi-digitalizare-imm: copy-ul nu trebuie publicat înaintea deciziei de consolidare");
assert.doesNotMatch(sitemapXml, /<loc>https:\/\/atelierdeconsultanta\.ro\/granturi-digitalizare-imm<\/loc>/u, "/granturi-digitalizare-imm: pagina pending nu trebuie să intre în sitemap");

for (const redirect of config.redirects) {
  assert.equal(redirect.status, "APROBARE_UMANĂ_NECESARĂ", `${redirect.source}: redirect neaprobat`);
}

const redirectsFile = fs.existsSync(path.join(ROOT, "_redirects")) ? fs.readFileSync(path.join(ROOT, "_redirects"), "utf8") : "";
assert.doesNotMatch(
  redirectsFile,
  /^\/granturi-digitalizare-imm\s+\/digitalizare-imm\s+30[18]\b/mu,
  "Redirectul Digitalizare nu trebuie implementat înainte de aprobare"
);

console.log(`PASS editorial-cluster-intents: ${pages.length} URL-uri au roluri și intenții distincte; redirecturile neaprobate nu sunt active.`);
