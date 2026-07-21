#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { auditEditorialCopy } = require("../tools/editorial-copy-governance");
const { collectSiteState } = require("../tools/generate-sitemap");

const audit = auditEditorialCopy();
assert.equal(audit.canonicalCount, collectSiteState().entries.length, "editorial gate must inspect every canonical sitemap URL");
assert.deepEqual(audit.pageIssues, [], `public copy issues:\n${audit.pageIssues.map((issue) => `${issue.route}: ${issue.oldFragment}`).join("\n")}`);
assert.deepEqual(audit.sourceIssues, [], `CMS/source copy issues:\n${audit.sourceIssues.map((issue) => `${issue.sourceFile}:${issue.location}: ${issue.oldFragment}`).join("\n")}`);
assert.deepEqual(audit.generatorIssues, [], `generator template issues:\n${audit.generatorIssues.map((issue) => `${issue.sourceFile}: ${issue.type}`).join("\n")}`);

console.log(`Editorial copy contract passed: ${audit.canonicalCount} canonical URLs, zero forbidden template labels or control-list forms.`);
