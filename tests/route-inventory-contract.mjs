import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { buildInventory, checkReportCoverage, validateInventory } = require("../tools/generate-route-inventory.js");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPORT = path.join(ROOT, "docs", "faber-remediation", "ROUTE_INVENTORY.md");
const inventory = buildInventory();

assert.equal(validateInventory(inventory).length, 0, validateInventory(inventory).join("\n"));
assert.equal(inventory.routes.length, 105, "Inventarul public aprobat trebuie revizuit explicit când se schimbă de la 105.");
assert.deepEqual(inventory.routesWithoutSitemap.map((route) => route.route), ["/gdpr"], "Pagina GDPR publică/indexabilă trebuie păstrată vizibilă ca excludere de sitemap aprobată.");
assert.equal(new Set(inventory.routes.map((route) => route.route)).size, inventory.routes.length, "Rutele canonical trebuie să fie unice.");
assert.equal(new Set(inventory.routes.map((route) => route.canonicalUrl)).size, inventory.routes.length, "Canonicalele publicate trebuie să fie unice.");
assert.equal(inventory.seo.programs.length, 25, "Baseline-ul registry are 25 de entități de program.");
assert.equal(inventory.banners.filter((banner) => banner.active !== false).length, 23, "Baseline-ul homepage are 23 bannere active.");
assert.ok(inventory.canonicalDuplicates.length > 0, "Aliasurile fizice canonical trebuie detectate și documentate.");
assert.deepEqual(inventory.publicFragments.map((item) => item.route).sort(), [
  "/google8bbb9999c523a3bd",
  "/partials/global-header",
  "/templates/dr14-final-content",
  "/templates/dr18-final-content",
]);
assert.ok(fs.existsSync(REPORT), "ROUTE_INVENTORY.md trebuie generat și versionat.");
assert.deepEqual(checkReportCoverage(inventory), [], "Raportul versionat trebuie să acopere toate rutele și redirecturile descoperite.");

console.log(`Route inventory contract PASS (${inventory.routes.length} canonical routes; ${inventory.canonicalDuplicates.length} physical duplicate groups; ${inventory.exactRedirects.length} exact redirects).`);
