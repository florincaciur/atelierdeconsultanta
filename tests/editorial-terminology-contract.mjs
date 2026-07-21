#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { POLICY, TARGET_ROUTES, auditTerminology, rewriteTerminology, validOpenProgram } = require("../tools/editorial-terminology-governance");
const { collectSiteState } = require("../tools/generate-sitemap");

const audit = auditTerminology();
assert.equal(TARGET_ROUTES.size, 10, "P0.14 must cover the ten named canonical surfaces");
assert.equal(audit.canonicalCount, collectSiteState().entries.length, "absolute claims must be checked on every canonical URL");
assert.equal(audit.targetCount, 10, "contextual terminology must be checked on every P0.14 surface");
assert.deepEqual(audit.issues, [], audit.issues.map((item) => `${item.route} [${item.rule}]: ${item.fragment}`).join("\n"));
assert.equal(rewriteTerminology("Verifică eligibilitatea și cofinanțarea din ghidul activ."), "Cere o verificare inițială și contribuția proprie din documentul oficial aplicabil.");
assert.equal(validOpenProgram({ status: "apel_deschis", verifiedAt: "2026-07-20", sourceUrl: "https://example.test/official", sourceVersion: "v1", applicationStart: "2026-07-01", applicationEnd: "2026-07-31" }, new Date("2026-07-21T12:00:00Z")), true);
assert.equal(validOpenProgram({ status: "apel_deschis", verifiedAt: "2026-07-20", sourceUrl: "https://example.test/official", sourceVersion: "v1", applicationStart: "2026-06-01", applicationEnd: "2026-06-30" }, new Date("2026-07-21T12:00:00Z")), false);
assert.ok(POLICY.legalRoutesExcludedFromAutomaticRewrite.includes("/politica-de-confidentialitate"), "legal pages must remain outside automatic rewriting");

console.log(`Editorial terminology contract passed: ${audit.canonicalCount} canonical URLs and ${audit.targetCount} P0.14 surfaces.`);
