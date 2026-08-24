#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const program = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs.find((item) => item.pageUrl === "/dr14");
const pagePath = path.join(ROOT, "dr14", "index.html");
const cssPath = path.join(ROOT, "assets", "dr14-final.css");
const jsPath = path.join(ROOT, "assets", "dr14-final.js");
const html = fs.readFileSync(pagePath, "utf8");
const css = fs.readFileSync(cssPath, "utf8");
const js = fs.readFileSync(jsPath, "utf8");
const $ = cheerio.load(html, { decodeEntities: false });

assert.equal($("head > title").first().text().trim(), "DR 14 AFIR 2026: depuneri 1 sept.–31 oct., 50.000 € | FABER");
assert.match($("meta[name='description']").attr("content") || "", /depuneri 1 septembrie–31 octombrie 2026/);
assert.equal($("link[rel='canonical']").attr("href"), "https://atelierdeconsultanta.ro/dr14");
assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /noindex/i);
assert.match($("h1").first().text(), /DR 14 AFIR 2026/);

const dr14MainText = $("main").text().replace(/\s+/g, " ");
assert.doesNotMatch(dr14MainText, /ghid(?:ul)? consultativ/i, "Conținutul DR 14 nu trebuie să descrie ghidul drept consultativ");
assert.match(dr14MainText, /ghid(?:ul|ului)? oficial final/i);
assert.match(dr14MainText, /50\.000 EUR/);
assert.match(dr14MainText, /85%/);
assert.match(dr14MainText, /4\.000–11\.999 SO/);
assert.match(dr14MainText, /80 de puncte/);
assert.match(dr14MainText, /40 de puncte/);

const calendar = $("[data-program-calendar='official']").text().replace(/\s+/g, " ").trim();
assert.match(calendar, /Depuneri: 1 septembrie–31 octombrie 2026/);
assert.match(calendar, /Calendar oficial AFIR/i);

assert.equal($("body").attr("data-program-status"), "ghid_aprobat_nedeschis");
assert.equal($("body").attr("data-verified-at"), program.verifiedAt);
assert.equal($("[data-dr14-tab]").length, 4);
assert.equal($("[data-score-component]").length, 4);
assert.equal($("[data-dr14-total]").length, 1);
assert.equal($("[data-dossier-check]").length, 12);
assert.equal($(".dr14-faq details").length, 10);
assert.equal($("script[src^='/assets/dr14-final.js']").length, 1);
assert.equal($("link[href^='/assets/dr14-final.css']").length, 1);
assert.match(html, /https:\/\/www\.afir\.ro\/domenii-de-interventie\/detalii-si-anexe-dr-14\//);
assert.match(html, /https:\/\/www\.afir\.ro\/instrumente\/sesiuni\/sesiuni-primire-proiecte\//);
assert.match(dr14MainText, /108 mil\. EUR/);
assert.match(dr14MainText, /1 septembrie 2026, ora 09:00/);

const schemas = $("script[type='application/ld+json']").toArray().map((node) => JSON.parse($(node).text()));
assert(schemas.length > 0, "Pagina trebuie să publice JSON-LD");
const schemaText = JSON.stringify(schemas);
assert.match(schemaText, /FAQPage/);
assert.match(schemaText, /FinancialIncentive/);
assert.doesNotMatch(schemaText, /VARIANTA CONSULTATIV/i);
assert.match(schemaText, /Anunțul A1\.2\/01\/2026 pentru sesiunea DR 14/);
assert.match(schemaText, /"validFrom":"2026-09-01"/);
assert.match(schemaText, /"validThrough":"2026-10-31"/);

assert.match(css, /@keyframes dr14-drive/);
assert.match(css, /prefers-reduced-motion/);
assert.match(js, /data-dr14-calculator/);
assert.match(js, /data-score-component/);
assert.match(js, /data-dossier-check/);

console.log("PASS: pagina DR 14 folosește ghidul final și păstrează contractele SEO, AEO, interactivitate și accesibilitate.");
