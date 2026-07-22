import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "homepage-decision-flow.json"), "utf8"));
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "assets", "homepage-decision-flow.css"), "utf8");
const $ = cheerio.load(html, { decodeEntities: false });

assert.equal((html.match(/<!-- P1_21_HOMEPAGE_FLOW_START -->/g) || []).length, 1);
assert.equal((html.match(/<!-- P1_21_HOMEPAGE_FLOW_END -->/g) || []).length, 1);
assert.equal($("main h1").length, 1, "homepage-ul trebuie să aibă un singur H1");
assert.deepEqual($("main > section").map((_, node) => $(node).attr("id")).get(), [
  "hero", "homepage-method", "priority-programs", "homepage-services", "homepage-tools", "homepage-proof", "homepage-analysis", "homepage-contact"
]);
assert.equal($("main form").length, 0, "homepage-ul nu trebuie să păstreze formulare concurente");
assert.equal($("main [data-priority-carousel]").length, 1, "trebuie păstrat un singur carusel principal");
assert.equal($("main [data-card-carousel], main [data-program-directory]").length, 0, "componentele repetitive trebuie eliminate");
assert.equal($(".homepage-method-step").length, 5);
assert.equal($(".homepage-service-grid .homepage-card").length, 4);
assert.equal($(".homepage-tool-grid .homepage-card").length, 3);
assert.equal($(".homepage-proof-card").length, 3);
assert.equal($("#homepage-analysis .homepage-analysis-card").length, 1);
assert.equal($(".homepage-program-hubs a").length, 5);
assert($("main a").length <= 35, `prea multe linkuri în main: ${$("main a").length}`);
assert($("main a").length < config.baseline.desktop.mainLinks, "numărul de linkuri trebuie redus față de baseline");
assert.equal($("#homepage-contact .homepage-flow-action").attr("href"), config.contact.primaryHref);
assert.equal($("#homepage-contact .homepage-flow-action").attr("data-analytics-event"), "cta_click");
assert.equal($("#homepage-contact .homepage-flow-action").attr("data-analytics-cta-view"), "true");
assert.equal($("#homepage-contact a[href^='tel:']").length, 2);
assert.equal($("#homepage-contact a[href^='mailto:']").length, 1);
assert.equal($("main > aside.long-form-toc").length, 0, "cuprinsul nu trebuie să rămână o secțiune separată în main");
assert.equal($("#navbar [data-homepage-navbar-toc]").length, 1, "cuprinsul trebuie integrat în navbar");
assert.equal($("#navbar [data-homepage-navbar-toc]").attr("hidden"), "hidden", "cuprinsul navbar pornește ascuns până la inițializarea homepage-ului");
assert.equal($("link[data-homepage-decision-flow-style='p1_21']").length, 1);
assert(!/newsletterForm|id="contactForm"|id="blog"|id="testimoniale"/.test($("main").html()), "au rămas trasee vechi în main");
assert(!/handleNewsletterSubmit|moveCardCarousel|fetch\('\/blog\.json'\)|modalOverlay|homepage-faq-toggle/.test(html), "runtime-ul componentelor eliminate trebuie șters, nu doar ascuns");
assert(css.includes("min-height: 44px") && css.includes(":focus-visible"), "lipsesc targeturile/focusul accesibil");
assert(css.includes("@media (max-width: 30rem)") && css.includes("prefers-reduced-motion"), "lipsesc reflow-ul/reduced motion");

console.log(`Homepage decision flow PASS: ${$("main a").length} linkuri, zero formulare, un carusel, opt secțiuni.`);
