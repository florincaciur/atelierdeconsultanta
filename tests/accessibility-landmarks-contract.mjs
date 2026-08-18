import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const { fileForRoute, sitemapRoutes } = require("../tools/structured-data-utils");
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(?:[A-Za-z]:)/, (value) => value.slice(1))), "..");
const routes = sitemapRoutes(ROOT);

for (const route of routes) {
  const file = fileForRoute(ROOT, route);
  assert(fs.existsSync(file), `${route}: fișier canonic absent`);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  assert.equal($("main").length, 1, `${route}: trebuie să existe exact un main`);
  assert.equal($("main#main-content").length, 1, `${route}: main trebuie să fie ținta main-content`);
  assert.equal($("a.skip-link[href='#main-content']").length, 1, `${route}: trebuie să existe exact o legătură skip validă`);
  assert.equal($("h1").length, 1, `${route}: trebuie să existe exact un h1`);
  assert.equal($("meta[name='viewport']").length, 1, `${route}: trebuie să existe viewport responsive`);
  assert.equal($("link[rel='stylesheet'][href^='/assets/global-header.css']").length, 1, `${route}: stylesheet-ul headerului global trebuie inclus o singură dată`);
  const ids = $("[id]").map((_, element) => $(element).attr("id")).get();
  assert.equal(new Set(ids).size, ids.length, `${route}: există ID-uri duplicate`);
  assert.equal($("body > meta[http-equiv='Content-Security-Policy' i]").length, 0, `${route}: politica CSP nu poate fi în body`);
  $(".calc-section").has("table").each((_, element) => {
    assert.equal($(element).attr("role"), "region", `${route}: tabelul de calcul trebuie încadrat într-o regiune`);
    assert.equal($(element).attr("tabindex"), "0", `${route}: regiunea tabelului trebuie să poată primi focus`);
  });
}

console.log(`Contract landmark-uri accesibile: ${routes.length} rute conforme.`);
