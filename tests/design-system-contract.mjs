import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { audit } = require("../tools/audit-design-system");
const { TARGETS } = require("../tools/sync-design-system-pilot");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "design-system.json"), "utf8"));
const css = fs.readFileSync(path.join(ROOT, "assets", "design-system.css"), "utf8");

assert.equal(config.typography.bodyPx, 17, "body trebuie să fie 17 px în pilot");
assert(config.typography.lineHeight >= 1.55 && config.typography.lineHeight <= 1.7, "line-height trebuie să fie 1.55–1.7");
assert.equal(config.typography.measure, "68ch");
assert.equal(config.targets.minimumPx, 24);
assert.equal(config.targets.mobilePreferredPx, 44);
assert.deepEqual(Object.keys(config.statusSymbols).sort(), [
  "apel_deschis",
  "apel_inchis",
  "arhivat",
  "calendar_estimativ",
  "consultare_publica",
  "ghid_aprobat_nedeschis"
].sort());

for (const relativePath of TARGETS) {
  const html = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  assert.equal($("body").attr("data-design-system"), "p1_07", `${relativePath}: scope lipsă`);
  assert.equal($('link[data-design-system-stylesheet="p1_07"]').length, 1, `${relativePath}: stylesheet lipsă sau duplicat`);
}

assert(css.includes('body[data-design-system="p1_07"]'), "CSS-ul trebuie limitat la pilot");
assert(css.includes("prefers-reduced-motion: reduce"), "lipsește reduced motion");
assert(css.includes(":focus-visible"), "lipsește focus-visible");
assert(css.includes("aria-invalid"), "lipsește starea error");
assert(css.includes("aria-busy"), "lipsește starea loading");
assert(css.includes("aria-disabled"), "lipsește starea disabled");
assert(css.includes("[data-sticky-cta]"), "lipsește contractul sticky CTA");
for (const symbol of ["●", "◐", "○"]) assert(css.includes(symbol), `lipsește simbolul de status ${symbol}`);

const report = audit();
assert.equal(report.result, "PASS", report.failures.join("; "));
assert(report.contrast.every((item) => item.pass), "toate perechile trebuie să treacă pragul WCAG");
console.log(`Design system contract PASS (${TARGETS.length} fișiere pilot, ${report.contrast.length} contraste).`);
