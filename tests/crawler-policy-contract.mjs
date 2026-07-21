#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { groupFor, validatePolicy } = require("../tools/crawler-policy");

const { policy, parsed, errors } = validatePolicy();
assert.deepEqual(errors, [], `crawler policy errors:\n${errors.join("\n")}`);

const oai = groupFor(parsed, "OAI-SearchBot");
const perplexity = groupFor(parsed, "PerplexityBot");
const gpt = groupFor(parsed, "GPTBot");
assert(oai, "OAI-SearchBot must have an explicit group");
assert(perplexity, "PerplexityBot must have an explicit group");
assert(gpt, "GPTBot must have an explicit group");
assert(oai.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(perplexity.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(gpt.rules.some((rule) => rule.directive === "disallow" && rule.value === "/"));

for (const crawler of policy.crawlers.filter((item) => item.purpose.includes("antrenare") || item.publicAccess === "disallow")) {
  assert.equal(crawler.changeInP015, false, `${crawler.userAgent} training policy must not change in P0.15`);
}
assert.equal(policy.cloudflare.allowUserAgentOnlyException, false);
assert.equal(policy.cloudflare.officialCrawlerLogReview, "DE_VALIDAT_UMAN");

console.log("Crawler policy contract passed: OAI/Perplexity search allowed, GPTBot training blocked, private paths protected.");
