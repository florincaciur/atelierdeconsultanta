import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { fileForRoute } = require("../tools/structured-data-utils");
const { CSS_HREF, JS_SRC, routes } = require("../tools/sync-site-immersive");
const { routes: programRoutes } = require("../tools/sync-program-visuals");
const programSet = new Set(programRoutes());

const css = fs.readFileSync(path.join(ROOT, "assets", "site-immersive.css"), "utf8");
const js = fs.readFileSync(path.join(ROOT, "assets", "site-immersive.js"), "utf8");
assert.match(css, /prefers-reduced-motion:\s*reduce/u, "Mișcarea redusă trebuie respectată");
assert.match(css, /\.site-immersive-progress/u, "Indicatorul de parcurs trebuie stilizat");
assert.doesNotMatch(js, /preventDefault\s*\(/u, "Stratul vizual nu poate intercepta navigarea sau scroll-ul nativ");
assert.doesNotMatch(js, /\.innerHTML\s*=/u, "Stratul vizual nu poate înlocui conținutul indexabil");

for (const route of routes()) {
  const file = fileForRoute(ROOT, route);
  assert(fs.existsSync(file), `${route}: fișier canonic absent`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("body[data-site-immersive='faber-20260901']").length, 1, `${route}: marcaj vizual absent`);
  assert.equal($(`link[href='${CSS_HREF}']`).length, 1, `${route}: stylesheet vizual absent sau duplicat`);
  assert.equal($(`script[src='${JS_SRC}']`).length, 1, `${route}: script vizual absent sau duplicat`);
  assert.equal($("link[rel='canonical']").length, 1, `${route}: canonical invalid`);
  assert.equal($("main").length, 1, `${route}: trebuie să existe exact un main`);
  if (programSet.has(route)) {
    const visual = $("main [data-program-visual='immersive-verification']");
    assert.equal(visual.length, 1, `${route}: bannerul imersiv de program lipsește sau este duplicat`);
    assert.equal(visual.find("[data-program-step]").length, 4, `${route}: traseul interactiv trebuie să aibă patru repere`);
    const source = visual.find(".program-visual__footer a[href^='https://']");
    assert.equal(source.length, 1, `${route}: sursa oficială lipsește din banner`);
  }
}

console.log(`Contract vizual site: ${routes().length} rute canonice și ${programSet.size} bannere de program conforme.`);
