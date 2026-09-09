#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { NETWORK_CATEGORIES, auditLinkIntegrity } = require("../tools/check-links");

const audit = await auditLinkIntegrity({ network: false });
const { inventory, siteAudit, graphAudit } = audit;

assert.equal(audit.errors.length, 0, audit.errors.join("\n"));
assert.equal(siteAudit.issues.length, 0, "există linkuri interne, redirecturi sau fragmente invalide");
assert.equal(graphAudit.errors.length, 0, graphAudit.errors.join("\n"));
assert.equal(graphAudit.summary.zeroIncoming, 0, "există pagini canonice orfane");
assert.equal(graphAudit.summary.legacyLinks, 0, "există linkuri către URL-uri legacy");
assert.equal(graphAudit.summary.brokenOrRedirectedLinks, 0, "există muchii interne rupte sau redirectate");
assert.ok(inventory.records.size >= 70, "inventarul extern pare incomplet");
assert.ok(inventory.special.mailto.size >= 2, "lipsesc adresele mailto publice");
assert.ok(inventory.special.tel.size >= 2, "lipsesc numerele tel publice");
assert.equal(inventory.special.whatsapp.size, 2, "canalele WhatsApp publice s-au schimbat fără actualizarea contractului");
assert.ok(inventory.localDocuments.length >= 4, "documentele locale nu sunt inventariate complet");

for (const surface of ["router", "homepage", "navigation", "footer", "registry", "program", "family", "guide", "breadcrumbs", "schema", "legal", "calculator", "core"]) {
  assert.ok(inventory.surfaceCounts[surface] > 0, `suprafața ${surface} nu a fost acoperită`);
}
assert.ok(inventory.surfaceCounts.faqBlocks > 0, "blocurile FAQ nu au fost inspectate");
assert.deepEqual(audit.classification, Object.fromEntries(NETWORK_CATEGORIES.map((category) => [category, 0])));

console.log(`Link integrity contract PASS: ${siteAudit.links.length} linkuri locale, ${inventory.records.size} URL-uri externe și ${siteAudit.anchorFragmentsChecked} fragmente.`);
