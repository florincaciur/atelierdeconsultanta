import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { carouselPrograms, isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { fileForRoute } = require("../tools/structured-data-utils");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-programs.json"), "utf8"));
const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "homepage-program-explorer.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "assets", "homepage-program-explorer.js"), "utf8");
const { programs } = loadProgramConfig();
const $ = cheerio.load(html, { decodeEntities: false });
const expectedPrograms = programs.filter((program) => isPublicProgram(program) && program.discovery?.listed !== false && !program.discovery?.redirectTarget);
const expectedCarousel = carouselPrograms(programs);
const programsById = new Map(programs.map((program) => [program.id, program]));
const bannerProgramIds = banners.map((banner) => banner.programId);
const bannerIds = banners.map((banner) => banner.id);
const bannerLinks = banners.map((banner) => banner.ctaLink);

assert.equal($("[data-priority-carousel]").length, 1, "trebuie să existe un singur carusel de programe");
const slides = $("[data-priority-slide]");
const renderedIds = slides.map((_, slide) => $(slide).attr("data-program-id")).get();
const renderedBannerIds = slides.map((_, slide) => $(slide).attr("data-banner-id")).get();
const renderedLinks = slides.map((_, slide) => $(slide).find(".priority-program-link").attr("href")).get();
assert.equal(slides.length, expectedCarousel.length, "count(rendered banners) trebuie să fie egal cu count(presentation.carousel=true)");
assert.equal(new Set(renderedIds).size, renderedIds.length, "ID-urile programelor din bannere trebuie să fie unice");
assert.equal(new Set(renderedBannerIds).size, renderedBannerIds.length, "ID-urile bannerelor randate trebuie să fie unice");
assert.equal(new Set(renderedLinks).size, renderedLinks.length, "linkurile canonice ale bannerelor trebuie să fie unice");
assert.deepEqual(renderedIds, expectedCarousel.map((program) => program.id), "ordinea trebuie să provină din registrul unic");
assert.deepEqual(new Set(expectedCarousel.map((program) => program.id)), new Set(expectedPrograms.map((program) => program.id)), "flagurile caruselului trebuie să acopere toate programele publice și listate");
assert.equal(banners.length, expectedCarousel.length, "banners.json trebuie să fie 1:1 cu programele banner-enabled");
assert.equal(new Set(bannerIds).size, bannerIds.length, "banners.json nu poate conține ID-uri duplicate");
assert.equal(new Set(bannerProgramIds).size, bannerProgramIds.length, "banners.json nu poate conține programe duplicate");
assert.equal(new Set(bannerLinks).size, bannerLinks.length, "banners.json nu poate conține canonical links duplicate");
assert.deepEqual(new Set(bannerProgramIds), new Set(expectedCarousel.map((program) => program.id)), "banners.json nu poate avea orfani sau programe enabled fără banner");
assert.equal(config.carousel.autoRotate, false, "auto-rotirea trebuie dezactivată editorial");
assert(!/setInterval|autoPlay|autoplay/i.test(js), "JS-ul nu trebuie să implementeze auto-rotire");
assert.equal($("[data-priority-previous]").attr("aria-label"), "Programul anterior");
assert.equal($("[data-priority-next]").attr("aria-label"), "Programul următor");
assert.equal($("[data-priority-counter]").attr("aria-live"), "polite");
assert.equal($("[data-priority-counter]").text().trim(), `1 din ${slides.length}`);
assert.equal($(".priority-program-all[href='/fonduri-europene']").length, 1, "lipsește linkul Vezi toate programele");

slides.each((index, slide) => {
  const element = $(slide);
  const program = programsById.get(element.attr("data-program-id"));
  assert(program && isPublicProgram(program), `${element.attr("data-program-id")}: program nepublicabil în carusel`);
  assert.equal(element.attr("data-banner-id"), program.id);
  assert.equal(element.attr("data-program-status"), program.status);
  assert.equal(element.attr("data-status-label"), program.statusLabel);
  assert.equal(element.attr("data-verified-at"), program.verifiedAt);
  assert.equal(element.attr("data-source-url"), program.sourceUrl);
  assert.equal(element.find(".priority-program-link").text().trim(), "Vezi condițiile");
  assert.equal(element.find("h3").text().trim(), program.shortName);
  assert.equal(element.find("p").first().text().trim(), program.cardSummary);
  assert.equal(element.find(".priority-program-link").attr("href"), program.pageUrl);
  assert.equal(element.find(".priority-program-link").attr("data-analytics-event"), "program_card_click");
  assert(fs.existsSync(fileForRoute(ROOT, program.pageUrl)), `${program.id}: ruta canonical din banner trebuie să existe`);
  if (index === 0) {
    assert.equal(element.attr("aria-hidden"), "false");
    assert.equal(element.is("[inert]"), false);
  } else {
    assert.equal(element.attr("aria-hidden"), "true");
    assert.equal(element.is("[inert]"), true);
    assert.equal(element.find("a").attr("tabindex"), "-1");
  }
});

for (const banner of banners) {
  const program = programsById.get(banner.programId);
  assert(program && expectedCarousel.some((entry) => entry.id === banner.programId), `${banner.id}: banner orphan`);
  assert.equal(banner.title, program.name, `${banner.id}: denumire diferită de registry`);
  assert.equal(banner.description, program.metaDescription, `${banner.id}: descriere diferită de registry`);
  assert.equal(banner.programStatus, program.status, `${banner.id}: status diferit de registry`);
  assert.equal(banner.statusLabel, program.statusLabel, `${banner.id}: status label diferit de registry`);
  assert.equal(banner.verifiedAt, program.verifiedAt, `${banner.id}: verifiedAt diferit de registry`);
  assert.equal(banner.ctaLink, program.pageUrl, `${banner.id}: canonical diferit de registry`);
  assert.equal(banner.image, program.presentation.image, `${banner.id}: imagine diferită de registry`);
  assert.equal(banner.order, program.presentation.carouselOrder, `${banner.id}: ordine diferită de registry`);
}

assert.equal($("[data-program-directory], [data-program-directory-card]").length, 0, "gridul complet trebuie mutat pe huburi, nu păstrat pe homepage");
const hubLinks = $(".homepage-program-hubs a");
assert.equal(hubLinks.length, 0, "descrierea redundantă de familie trebuie eliminată");
assert.equal($(".homepage-program-hubs").length, 0);
assert(!$("main").text().includes("Explorează după familie"));

assert.equal($("#carousel-section, #finantare, #financing-grid, #program-carousel-track").length, 0, "componentele repetitive vechi trebuie eliminate");
assert(!html.includes("programCarouselState") && !html.includes("loadProgramCarousel"), "runtime-ul caruselului vechi trebuie eliminat");
assert.equal($('link[data-homepage-program-explorer-style="p1_08"]').length, 1);
assert.equal($('script[data-homepage-program-explorer-script="p1_08"]').length, 1);
assert(js.includes('"carousel_interaction"') && js.includes('"program_card_click"') === false, "carousel_interaction trebuie emis din JS, iar clickurile cardurilor rămân declarative");
assert(js.includes("ArrowLeft") && js.includes("ArrowRight") && js.includes("pointerdown") && js.includes("pointerup"), "lipsesc controalele tastatură/touch");
assert(js.includes('toggleAttribute("inert"'), "slide-urile ascunse trebuie scoase din focus");
assert(js.includes("slides.length > 24") && !js.includes("slides.length > 6"), "runtime-ul trebuie să accepte catalogul complet de programe");
assert(css.includes("min-height: 44px") && css.includes("touch-action: pan-y"), "targeturile mobile și gesturile touch trebuie definite");
assert(css.includes("@media (max-width: 42rem)"), "lipsește reflow-ul mobil");
assert(css.includes("prefers-reduced-motion: reduce"), "lipsește respectarea preferinței reduced-motion");

console.log(`Homepage program explorer contract PASS: ${slides.length} priorități, un carusel și zero descrieri redundante.`);
