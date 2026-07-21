#!/usr/bin/env node
"use strict";

const { validatePolicy } = require("./crawler-policy");

const LIVE = process.argv.includes("--live");
const { policy, errors } = validatePolicy();

if (errors.length) {
  console.error(errors.map((error) => `FAIL: ${error}`).join("\n"));
  process.exit(1);
}

if (!LIVE) {
  console.log(`Crawler policy passed: ${policy.crawlers.length} crawlers, ${policy.privatePaths.length} private path prefixes.`);
  process.exit(0);
}

async function probe(url, userAgent) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, {
      headers: { "user-agent": userAgent },
      redirect: "manual",
      signal: controller.signal,
    });
    return {
      url,
      userAgent,
      status: response.status,
      server: response.headers.get("server"),
      cfRayPresent: Boolean(response.headers.get("cf-ray")),
    };
  } catch (error) {
    return { url, userAgent, status: null, error: error.message };
  } finally {
    clearTimeout(timeout);
  }
}

(async () => {
  const allowed = policy.crawlers.filter((crawler) => crawler.publicAccess === "allow" && crawler.liveProbe === true);
  let officialPrefixSource;
  try {
    const response = await fetch(policy.cloudflare.perplexityIpListUrl, { signal: AbortSignal.timeout(15000) });
    const data = await response.json();
    officialPrefixSource = {
      url: policy.cloudflare.perplexityIpListUrl,
      status: response.status,
      prefixCount: Array.isArray(data.prefixes) ? data.prefixes.length : null,
    };
  } catch (error) {
    officialPrefixSource = { url: policy.cloudflare.perplexityIpListUrl, error: error.message };
  }
  const results = [];
  for (const crawler of allowed) {
    for (const probePath of policy.publicProbePaths) {
      results.push(await probe(new URL(probePath, policy.siteOrigin).href, crawler.userAgent));
    }
  }

  const failures = results.filter((result) => result.status !== 200);
  console.log(JSON.stringify({
    checkedAt: new Date().toISOString(),
    scope: "synthetic probes; not evidence of official crawler IP access",
    officialPrefixSource,
    results,
    failures,
  }, null, 2));
  if (failures.length) {
    console.error(`Live synthetic audit: REVIEW_REQUIRED (${failures.length}/${results.length} responses were not 200). This is inconclusive for official crawlers; review Cloudflare Security Events using verified IP + User-Agent before changing rules.`);
    process.exit(1);
  }
  console.log(`Live synthetic audit: PASS (${results.length} public responses).`);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
