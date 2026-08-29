import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const root = path.resolve(import.meta.dirname, "..");
const { findPublicHtmlFiles } = require("../tools/sync-global-header");
const { canonicalUrl, isCanonicalIndexable } = require("../tools/sync-preferred-source");

const eligible = findPublicHtmlFiles().filter((relativePath) => {
  const html = fs.readFileSync(path.join(root, ...relativePath.split("/")), "utf8");
  return isCanonicalIndexable(relativePath, html);
});

const canonicalRoutes = new Set();
for (const relativePath of eligible) {
  const html = fs.readFileSync(path.join(root, ...relativePath.split("/")), "utf8");
  canonicalRoutes.add(new URL(canonicalUrl(html)).pathname.replace(/\/$/, "") || "/");
  assert.equal((html.match(/<!-- PREFERRED_SOURCE_START -->/g) || []).length, 1, `${relativePath}: bloc Preferred Sources lipsă/duplicat`);
  assert.equal((html.match(/<!-- PREFERRED_SOURCE_HEAD_START -->/g) || []).length, 1, `${relativePath}: asset-urile head lipsesc/sunt duplicate`);
  assert.equal((html.match(/google-add-preferred-source-btn/g) || []).length, 1, `${relativePath}: control Google lipsă/duplicat`);
  assert.equal((html.match(/news\.google\.com\/swg\/js\/v1\/publisher\.js/g) || []).length, 1, `${relativePath}: script oficial Google lipsă/duplicat`);
  assert.equal((html.match(/\/assets\/preferred-source\.js/g) || []).length, 1, `${relativePath}: script local lipsă/duplicat`);
  assert.match(html, /https:\/\/www\.google\.com\/preferences\/source\?q=atelierdeconsultanta\.ro/, `${relativePath}: deeplink fallback lipsă`);
}
assert.equal(canonicalRoutes.size, 104, "Preferred Sources trebuie publicat pe exact cele 104 rute canonice indexabile");

const css = fs.readFileSync(path.join(root, "assets", "preferred-source.css"), "utf8");
assert.match(css, /color:\s*#0b2442/i, "Componenta trebuie să declare explicit contrastul textului");
assert.match(css, /@media \(max-width:\s*760px\)/, "Componenta trebuie să aibă layout mobil");
assert.match(css, /:focus-visible/, "Fallback-ul trebuie să aibă focus vizibil");

console.log(`PASS: Preferred Sources — ${canonicalRoutes.size} rute canonice (${eligible.length} fișiere), fallback, contrast și responsive.`);
