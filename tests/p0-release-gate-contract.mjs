#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { evaluateGovernanceBlockers, parseRedirectRules } = require("../tools/p0-release-gate");
const gateSource = fs.readFileSync(path.join(ROOT, "tools", "p0-release-gate.js"), "utf8");

const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "p0-release-gate.json"), "utf8"));
assert.equal(config.criteria.length, 12, "P0.16 must cover all twelve acceptance criteria");
assert.deepEqual(config.blockSeverities, ["critical"]);

const blockers = evaluateGovernanceBlockers();
for (const id of ["program_status", "legal_identity", "contact_privacy", "robots"]) {
  assert(!blockers.some((item) => item.criterionId === id), `${id} is approved and must not block`);
}

const rules = parseRedirectRules(fs.readFileSync(path.join(ROOT, "_redirects"), "utf8"));
assert(rules.length > 0, "redirect registry must not be empty");
assert(rules.every((rule) => rule.status === 301), "every controlled redirect must be 301");

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
for (const script of ["deploy", "deploy:pages", "deploy:contact-triage", "deploy:cloudflare-domain-worker"]) {
  assert(packageJson.scripts[script].includes("npm run gate:p0:local &&"), `${script} must contain the P0 gate before deployment`);
  assert(packageJson.scripts[script].indexOf("npm run gate:p0:local") < packageJson.scripts[script].indexOf("npx wrangler"), `${script} must run the P0 gate before Wrangler`);
}
const wrangler = JSON.parse(fs.readFileSync(path.join(ROOT, "wrangler.jsonc"), "utf8"));
assert(wrangler.build.command.startsWith("npm run gate:p0:deploy-guard &&"), "Cloudflare build must start with the P0 deployment guard");
assert.match(gateSource, /website:\s*["']qa-release-gate["']/, "production form E2E must use the honeypot QA sink");
assert.match(gateSource, /environment = ["']production-probed["']/, "production gate must record that the safe E2E probe ran");

console.log(`P0 release gate contract passed: ${config.criteria.length} criteria and ${blockers.length} active governance blockers are enforced.`);
