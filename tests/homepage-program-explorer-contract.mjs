import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-programs.json"), "utf8"));
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "homepage-program-explorer.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "assets", "homepage-program-explorer.js"), "utf8");
const { programs } = loadProgramConfig();
const $ = cheerio.load(html, { decodeEntities: false });

assert.equal($("[data-priority-carousel]").length, 1, "trebuie să existe un singur carusel de programe");
const slides = $("[data-priority-slide]");
assert(slides.length > 0 && slides.length <= 6, "caruselul trebuie să aibă maximum șase slide-uri");
assert.deepEqual(slides.map((_, slide) => $(slide).attr("data-program-id")).get(), config.featuredProgramSlugs, "ordinea trebuie să urmeze selecția editorială");
assert.equal(config.carousel.autoRotate, false, "auto-rotirea trebuie dezactivată editorial");
assert(!/setInterval|autoPlay|autoplay/i.test(js), "JS-ul nu trebuie să implementeze auto-rotire");
assert.equal($("[data-priority-previous]").attr("aria-label"), "Programul anterior");
assert.equal($("[data-priority-next]").attr("aria-label"), "Programul următor");
assert.equal($("[data-priority-counter]").attr("aria-live"), "polite");
assert.equal($("[data-priority-counter]").text().trim(), `1 din ${slides.length}`);
assert.equal($(".priority-program-all[href='/fonduri-europene']").length, 1, "lipsește linkul Vezi toate programele");

slides.each((index, slide) => {
  const element = $(slide);
  const program = programs.find((entry) => entry.slug === element.attr("data-program-id"));
  assert(program && isPublicProgram(program), `${element.attr("data-program-id")}: program nepublicabil în carusel`);
  assert.equal(element.attr("data-program-status"), program.status);
  assert.equal(element.attr("data-status-label"), program.statusLabel);
  assert.equal(element.attr("data-verified-at"), program.verifiedAt);
  assert.equal(element.attr("data-source-url"), program.sourceUrl);
  assert.equal(element.find(".priority-program-link").text().trim(), "Vezi condițiile");
  assert.equal(element.find(".priority-program-link").attr("data-analytics-event"), "program_card_click");
  if (index === 0) {
    assert.equal(element.attr("aria-hidden"), "false");
    assert.equal(element.is("[inert]"), false);
  } else {
    assert.equal(element.attr("aria-hidden"), "true");
    assert.equal(element.is("[inert]"), true);
    assert.equal(element.find("a").attr("tabindex"), "-1");
  }
});

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
assert(css.includes("min-height: 44px") && css.includes("touch-action: pan-y"), "targeturile mobile și gesturile touch trebuie definite");
assert(css.includes("@media (max-width: 42rem)"), "lipsește reflow-ul mobil");

console.log(`Homepage program explorer contract PASS: ${slides.length} priorități, un carusel și zero descrieri redundante.`);
