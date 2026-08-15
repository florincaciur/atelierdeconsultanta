import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as cheerio from "cheerio";

const ROOT = path.resolve(import.meta.dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "priority-conversion-pages.json"), "utf8"));

for (const page of config.pages) {
  const html = fs.readFileSync(path.join(ROOT, page.file), "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const block = $(`[data-priority-conversion='${page.id}']`);
  assert.equal(block.length, 1, `${page.route}: trebuie să existe un singur bloc de conversie`);
  assert.equal(block.find("ol > li").length, 3, `${page.route}: trierea trebuie explicată în trei pași`);
  assert.equal(block.find("h2").length, 1, `${page.route}: blocul are nevoie de titlu semantic`);
  const primary = block.find("a[href^='/contact#']").first();
  assert(primary.length, `${page.route}: lipsește CTA-ul către formular`);
  assert(primary.attr("href").includes(`program_slug=${page.programSlug}`));
  assert.equal(primary.attr("data-analytics-program-slug"), page.programSlug);
  assert.match(block.text(), /nu (?:garantează|garantăm)|nu poate fi garantată/iu);
  assert.equal($("link[href^='/assets/priority-program-conversion.css']").length, 1);
  assert.equal($("h1").length, 1, `${page.route}: inserarea nu poate duplica H1`);
  assert($("svg").length >= 2, `${page.route}: animațiile și ilustrațiile SVG trebuie păstrate`);
}

console.log("PASS: cele trei pagini prioritare au trasee de conversie atribuite, măsurabile și conforme.");
