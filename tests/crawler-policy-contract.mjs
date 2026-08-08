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
const deepseek = groupFor(parsed, "DeepSeekBot");
assert(oai, "OAI-SearchBot must have an explicit group");
assert(perplexity, "PerplexityBot must have an explicit group");
assert(gpt, "GPTBot must have an explicit group");
assert(deepseek, "DeepSeekBot must have an explicit group");
assert(oai.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(perplexity.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(gpt.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(deepseek.rules.some((rule) => rule.directive === "allow" && rule.value === "/"));
assert(!gpt.rules.some((rule) => rule.directive === "disallow" && rule.value === "/"));

for (const crawler of policy.crawlers) {
  assert.equal(crawler.publicAccess, "allow", `${crawler.userAgent} must be allowed on public paths`);
  const group = groupFor(parsed, crawler.robotsGroup);
  assert(group.rules.some((rule) => rule.directive === "allow" && rule.value === "/"), `${crawler.userAgent} must declare Allow: /`);
  for (const privatePath of policy.privatePaths) {
    assert(group.rules.some((rule) => rule.directive === "disallow" && rule.value === privatePath), `${crawler.userAgent} must keep ${privatePath} private`);
  }
  for (const pathname of policy.crawlableNoindexPaths) {
    assert(!group.rules.some((rule) => rule.directive === "disallow" && rule.value === pathname), `${crawler.userAgent} must crawl ${pathname} to observe noindex`);
  }
}
for (const group of parsed.groups.filter((item) => item.agents.some((agent) => agent !== "*"))) {
  assert(group.rules.some((rule) => rule.directive === "allow" && rule.value === "/"), `${group.agents.join(", ")} must allow public crawling`);
  assert(!group.rules.some((rule) => rule.directive === "disallow" && rule.value === "/"), `${group.agents.join(", ")} must not block public crawling`);
  for (const privatePath of policy.privatePaths) {
    assert(group.rules.some((rule) => rule.directive === "disallow" && rule.value === privatePath), `${group.agents.join(", ")} must keep ${privatePath} private`);
  }
  for (const pathname of policy.crawlableNoindexPaths) {
    assert(!group.rules.some((rule) => rule.directive === "disallow" && rule.value === pathname), `${group.agents.join(", ")} must crawl ${pathname} to observe noindex`);
  }
}
assert.deepEqual(policy.crawlableNoindexPaths, ["/admin", "/admin/"]);
assert.equal(policy.crawlers.find((item) => item.userAgent === "GPTBot")?.approval, "APROBAT_CACIUR_FLORIN_2026-07-22");
assert.equal(policy.crawlers.find((item) => item.userAgent === "DeepSeekBot")?.approval, "APROBAT_CACIUR_FLORIN_2026-07-28");
assert.equal(policy.cloudflare.allowUserAgentOnlyException, false);
assert.equal(policy.cloudflare.changeApproval, "APROBAT_CACIUR_FLORIN_2026-07-28");

console.log(`Crawler policy contract passed: ${policy.crawlers.length} public crawler policies allowed, private paths protected.`);
