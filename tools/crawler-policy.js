"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

function parseRobots(text) {
  const groups = [];
  const sitemaps = [];
  let agents = [];
  let rules = [];

  const flush = () => {
    if (agents.length) groups.push({ agents, rules });
    agents = [];
    rules = [];
  };

  for (const sourceLine of text.split(/\r?\n/u)) {
    const line = sourceLine.replace(/\s+#.*$/u, "").trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const directive = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (directive === "user-agent") {
      if (rules.length) flush();
      agents.push(value);
    } else if (directive === "allow" || directive === "disallow") {
      if (agents.length) rules.push({ directive, value });
    } else if (directive === "sitemap") {
      sitemaps.push(value);
    }
  }
  flush();
  return { groups, sitemaps };
}

function groupFor(parsed, groupName) {
  return parsed.groups.find((group) => group.agents.some((agent) => agent.toLowerCase() === groupName.toLowerCase()));
}

function validatePolicy() {
  const policy = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "crawler-access-policy.json"), "utf8"));
  const robotsText = fs.readFileSync(path.join(ROOT, "robots.txt"), "utf8");
  const parsed = parseRobots(robotsText);
  const errors = [];

  if (parsed.sitemaps.length !== 1 || parsed.sitemaps[0] !== policy.sitemapUrl) {
    errors.push(`robots.txt trebuie să conțină o singură declarație Sitemap: ${policy.sitemapUrl}`);
  }

  for (const crawler of policy.crawlers) {
    const group = groupFor(parsed, crawler.robotsGroup);
    if (!group) {
      errors.push(`Lipsește grupul robots pentru ${crawler.robotsGroup}`);
      continue;
    }
    if (crawler.publicAccess === "allow") {
      if (!group.rules.some((rule) => rule.directive === "allow" && rule.value === "/")) {
        errors.push(`${crawler.robotsGroup} trebuie să aibă Allow: /`);
      }
      if (group.rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) {
        errors.push(`${crawler.robotsGroup} nu poate avea Disallow: /`);
      }
      for (const privatePath of policy.privatePaths) {
        if (!group.rules.some((rule) => rule.directive === "disallow" && rule.value === privatePath)) {
          errors.push(`${crawler.robotsGroup} trebuie să blocheze ${privatePath}`);
        }
      }
    } else if (!group.rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) {
      errors.push(`${crawler.robotsGroup} trebuie să păstreze Disallow: /`);
    }
  }

  const renderAssetBlocks = parsed.groups.flatMap((group) => group.rules
    .filter((rule) => rule.directive === "disallow" && /\.(?:css|js|png|jpe?g|webp|svg)(?:$|\?)/iu.test(rule.value))
    .map((rule) => `${group.agents.join(",")}: ${rule.value}`));
  if (renderAssetBlocks.length) errors.push(`Asset-uri de randare blocate: ${renderAssetBlocks.join("; ")}`);
  if (policy.cloudflare.allowUserAgentOnlyException !== false) {
    errors.push("Politica Cloudflare nu poate permite excepții bazate numai pe User-Agent");
  }

  return { policy, parsed, errors };
}

module.exports = { ROOT, groupFor, parseRobots, validatePolicy };
