import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const { fileForRoute } = require("../tools/structured-data-utils");
const { routes } = require("../tools/sync-program-visuals");
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(?:[A-Za-z]:)/, (value) => value.slice(1))), "..");

const css = fs.readFileSync(path.join(ROOT, "assets", "program-visuals.css"), "utf8");
assert.match(css, /prefers-reduced-motion:\s*reduce/, "Stilul graficelor trebuie să respecte reducerea mișcării");
assert.match(css, /body\[data-program-id\][\s\S]*max-width:\s*100%/, "Paginile de program trebuie să limiteze graficele și conținutul la lățimea disponibilă");
assert.match(css, /program-visual__svg--mobile/, "Graficul comun trebuie să aibă o compoziție mobilă distinctă și lizibilă");

for (const route of routes()) {
  const file = fileForRoute(ROOT, route);
  assert(fs.existsSync(file), `${route}: fișier canonic absent`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("main").length, 1, `${route}: trebuie să existe exact un main`);
  assert($("link[href^='/assets/program-visuals.css']").length, `${route}: lipsește stylesheet-ul comun pentru grafice`);
  const banner = $("[data-program-visual='immersive-verification']");
  assert.equal(banner.length, 1, `${route}: trebuie să existe un singur banner imersiv`);
  assert.equal($("figure.program-visual").length, 0, `${route}: bannerul vizual separat nu trebuie recreat`);
  assert.equal(banner.find(".hero-icon,.post-icon").length, 0, `${route}: pictograma veche nu trebuie să dubleze animația`);
  const visuals = banner.find("svg[role='img']").toArray().filter((svg) => {
    const node = $(svg);
    return node.attr("aria-hidden") !== "true" && !node.parents("[aria-hidden='true']").length && Boolean(node.attr("aria-label") || node.attr("aria-labelledby") || node.find("title").text().trim()) && Boolean(node.attr("aria-describedby") || node.find("desc").text().trim());
  });
  assert(visuals.length, `${route}: lipsește un SVG informativ, numit și descris accesibil`);
  banner.find("svg").each((_, svg) => {
    const node = $(svg);
    const viewBox = (node.attr("viewBox") || node.attr("viewbox") || "").trim().split(/\s+/u).map(Number);
    assert.equal(viewBox.length, 4, `${route}: fiecare SVG trebuie să aibă viewBox complet`);
    assert(viewBox.every(Number.isFinite) && viewBox[2] > 0 && viewBox[3] > 0, `${route}: viewBox SVG trebuie să aibă dimensiuni finite și pozitive`);
    assert.notEqual(node.attr("preserveAspectRatio"), "none", `${route}: raportul SVG nu poate fi deformat`);
    if (node.attr("aria-hidden") !== "true") {
      assert(node.attr("aria-label") || node.attr("aria-labelledby") || node.find("title").text().trim(), `${route}: SVG informativ fără nume accesibil`);
    }
  });
  banner.each((_, element) => {
    const fluidSvg = $(element).find("svg").toArray().some((svg) => Boolean($(svg).attr("viewBox") || $(svg).attr("viewbox")));
    assert(fluidSvg, `${route}: graficul generic trebuie să fie fluid prin viewBox`);
    assert.equal($(element).find(".program-visual__svg--desktop").length, 1, `${route}: lipsește compoziția SVG desktop`);
    assert.equal($(element).find(".program-visual__svg--mobile").length, 1, `${route}: lipsește compoziția SVG mobilă`);
  });
}

console.log(`Contract grafice program: ${routes().length} rute conforme.`);
