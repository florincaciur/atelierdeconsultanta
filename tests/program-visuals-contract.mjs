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

for (const route of routes()) {
  const file = fileForRoute(ROOT, route);
  assert(fs.existsSync(file), `${route}: fișier canonic absent`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("main").length, 1, `${route}: trebuie să existe exact un main`);
  assert($("link[href^='/assets/program-visuals.css']").length, `${route}: lipsește stylesheet-ul comun pentru grafice`);
  const visuals = $("main svg[role='img']").toArray().filter((svg) => {
    const node = $(svg);
    return node.attr("aria-hidden") !== "true" && !node.parents("[aria-hidden='true']").length && Boolean(node.attr("aria-label") || node.attr("aria-labelledby") || node.find("title").text().trim()) && Boolean(node.attr("aria-describedby") || node.find("desc").text().trim());
  });
  assert(visuals.length, `${route}: lipsește un SVG informativ, numit și descris accesibil`);
  $(".program-visual").each((_, element) => {
    const fluidSvg = $(element).find("svg").toArray().some((svg) => Boolean($(svg).attr("viewBox") || $(svg).attr("viewbox")));
    assert(fluidSvg, `${route}: graficul generic trebuie să fie fluid prin viewBox`);
  });
}

console.log(`Contract grafice program: ${routes().length} rute conforme.`);
