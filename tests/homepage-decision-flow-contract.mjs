import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const require = createRequire(import.meta.url);
const { carouselPrograms, loadProgramConfig } = require("../tools/program-factual-governance");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-decision-flow.json"), "utf8"));
const homepagePrograms = carouselPrograms(loadProgramConfig().programs);
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "homepage-decision-flow.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "assets", "homepage-decision-flow.js"), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });

assert.equal((html.match(/<!-- P1_21_HOMEPAGE_FLOW_START -->/g) || []).length, 1);
assert.equal((html.match(/<!-- P1_21_HOMEPAGE_FLOW_END -->/g) || []).length, 1);
assert.equal($("main h1").length, 1, "homepage-ul trebuie să aibă un singur H1");
assert.deepEqual($("main > section").map((_, node) => $(node).attr("id")).get(), [
  "hero", "homepage-method", "priority-programs", "homepage-explorer", "homepage-contact"
]);
assert.equal($("main form").length, 0, "homepage-ul nu trebuie să păstreze formulare concurente");
assert.equal($("main [data-priority-carousel]").length, 1, "trebuie păstrat un singur carusel principal");
assert.equal($("main [data-card-carousel], main [data-program-directory]").length, 0, "componentele repetitive trebuie eliminate");
assert.equal($("[data-homepage-method-frame]").length, 5);
assert.equal($("[data-homepage-explorer-frame]").length, 4);
assert.equal($("div[data-priority-slide][role='group']").length, homepagePrograms.length, "toate slide-urile caruselului trebuie să folosească un element compatibil cu rolul group");
assert.equal($("div[data-homepage-method-frame][role='tabpanel']").length, 5, "panourile metodei trebuie să folosească un element compatibil cu rolul tabpanel");
assert.equal($("div[data-homepage-explorer-frame][role='tabpanel']").length, 4, "panourile explorerului trebuie să folosească un element compatibil cu rolul tabpanel");
assert.equal($("article[role='tabpanel']").length, 0, "rolul tabpanel nu este permis pe elementul article");
assert.equal($("article[role='group']").length, 0, "rolul group nu este permis pe elementul article");
assert.equal($(".homepage-service-grid .homepage-card").length, 4);
assert.equal($(".homepage-tool-grid .homepage-card").length, 3);
assert.equal($(".homepage-proof-grid .homepage-card").length, 3);
assert.equal($("#homepage-analysis .homepage-flow-action").length, 1);
assert.equal($(".homepage-program-hubs").length, 0);
assert(!$("main").text().includes("Explorează după familie"));
assert($("main a").length < config.baseline.desktop.mainLinks, "numărul de linkuri trebuie redus față de baseline");
assert.equal($("#homepage-contact .homepage-flow-action").attr("href"), config.contact.primaryHref);
assert.equal($("#homepage-contact .homepage-flow-action").attr("data-analytics-event"), "cta_click");
assert.equal($("#homepage-contact .homepage-flow-action").attr("data-analytics-cta-view"), "true");
assert.equal($("#homepage-contact a[href^='tel:']").length, 2);
assert.equal($("#homepage-contact a[href^='mailto:']").length, 1);
assert.equal($("main > aside.long-form-toc").length, 0, "cuprinsul nu trebuie să rămână o secțiune separată în main");
assert.equal($("[data-homepage-navbar-toc]").length, 0, "cuprinsul a fost eliminat din navigare");
assert.equal($("link[data-homepage-decision-flow-style='p1_22']").length, 1);
assert.equal($("script[data-homepage-decision-flow-script='p1_22']").length, 1);
assert(!/newsletterForm|id="contactForm"|id="blog"|id="testimoniale"/.test($("main").html()), "au rămas trasee vechi în main");
assert(!/handleNewsletterSubmit|moveCardCarousel|fetch\('\/blog\.json'\)|modalOverlay|homepage-faq-toggle/.test(html), "runtime-ul componentelor eliminate trebuie șters, nu doar ascuns");
assert(css.includes("min-height: 44px") && css.includes(":focus-visible"), "lipsesc targeturile/focusul accesibil");
assert(css.includes("@media (max-width: 30rem)") && css.includes("prefers-reduced-motion"), "lipsesc reflow-ul/reduced motion");
assert(js.includes("pointerdown") && js.includes("pointerup") && js.includes("ArrowRight"));
assert(js.includes('toggleAttribute("inert"'));

console.log(`Homepage decision flow PASS: ${$("main a").length} linkuri, zero formulare, un carusel, cinci secțiuni.`);
