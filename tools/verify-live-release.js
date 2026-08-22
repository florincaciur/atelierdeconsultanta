#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { groupFor, parseRobots } = require("./crawler-policy");

const ROOT = path.resolve(__dirname, "..");
const ORIGIN = "https://atelierdeconsultanta.ro";
const CRAWLER_POLICY = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "crawler-access-policy.json"), "utf8"));

function argument(name, fallback = "") {
  const prefix = `--${name}=`;
  const inline = process.argv.find((value) => value.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] || fallback : fallback;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function request(route, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    return await fetch(new URL(route, ORIGIN), {
      redirect: "manual",
      ...options,
      headers: {
        "cache-control": "no-cache",
        "user-agent": "FABER-live-release-verifier/1.0",
        ...(options.headers || {}),
      },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForCommit(expectedCommit, waitSeconds) {
  const deadline = Date.now() + waitSeconds * 1000;
  let last = "manifest not checked";
  do {
    try {
      const response = await request(`/release.json?expected=${expectedCommit}&t=${Date.now()}`);
      const release = await response.json();
      last = `HTTP ${response.status}, commit=${release.commit || "missing"}`;
      if (response.status === 200 && release.commit === expectedCommit) return release;
    } catch (error) {
      last = error.message;
    }
    if (Date.now() < deadline) await sleep(10000);
  } while (Date.now() < deadline);
  throw new Error(`Production did not reach commit ${expectedCommit}: ${last}`);
}

function assertCrawlerPolicy(text, agent) {
  const group = groupFor(parseRobots(text), agent);
  if (!group) throw new Error(`robots.txt is missing ${agent}`);
  if (!group.rules.some((rule) => rule.directive === "allow" && rule.value === "/")) throw new Error(`${agent} is not allowed on public pages`);
  if (group.rules.some((rule) => rule.directive === "disallow" && rule.value === "/")) throw new Error(`${agent} is blocked by a conflicting rule`);
  for (const privatePath of CRAWLER_POLICY.privatePaths) {
    if (!group.rules.some((rule) => rule.directive === "disallow" && rule.value === privatePath)) throw new Error(`${agent} does not protect ${privatePath}`);
  }
  for (const pathname of CRAWLER_POLICY.crawlableNoindexPaths || []) {
    if (group.rules.some((rule) => rule.directive === "disallow" && rule.value === pathname)) throw new Error(`${agent} blocks crawlable noindex path ${pathname}`);
  }
}

async function safeFormProbe(contactType) {
  const payload = {
    schema_version: "1.0.0",
    lead_id: `qa-live-${contactType}-${Date.now()}`,
    applicant_type: "societate",
    location: "Iasi",
    investment: "Verificare tehnica automata fara creare de lead",
    email: contactType === "email" ? "qa-live-release@example.invalid" : "",
    phone: contactType === "phone" ? "0769000000" : "",
    privacy_notice_acknowledged: true,
    program_slug: "unknown",
    contact_preference: contactType,
    page_url: "/contact",
    form_started_at: String(Date.now() - 5000),
    website: "qa-live-release",
  };
  const response = await request("/api/contact-triage", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", origin: ORIGIN },
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  if (response.status !== 200 || body.success !== true) throw new Error(`${contactType} form probe failed: HTTP ${response.status}`);
}

async function verifyHtml(route) {
  const verificationRoute = route === "/contact" ? route : `${route}?live_release=${Date.now()}`;
  const response = await request(verificationRoute);
  const html = await response.text();
  if (response.status !== 200) throw new Error(`${route}: HTTP ${response.status}`);
  const canonical = html.match(/<link\b[^>]*rel=["'][^"']*canonical[^"']*["'][^>]*href=["']([^"']+)["']/iu)?.[1]
    || html.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*rel=["'][^"']*canonical[^"']*["']/iu)?.[1];
  const expected = new URL(route, ORIGIN).href;
  if (canonical !== expected) throw new Error(`${route}: canonical ${canonical || "missing"}, expected ${expected}`);
  if (/<meta\b[^>]*name=["']robots["'][^>]*content=["'][^"']*noindex/iu.test(html)) throw new Error(`${route}: noindex detected`);
  return html;
}

async function main() {
  const expectedCommit = argument("commit") || execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim().toLowerCase();
  const waitSeconds = Number(argument("wait-seconds", "0"));
  if (!/^[a-f0-9]{40}$/iu.test(expectedCommit)) throw new Error(`Invalid expected commit: ${expectedCommit}`);
  if (!Number.isFinite(waitSeconds) || waitSeconds < 0 || waitSeconds > 1800) throw new Error(`Invalid wait duration: ${waitSeconds}`);

  const release = await waitForCommit(expectedCommit, waitSeconds);
  const criticalRoutes = ["/", "/contact", "/dr12-afir", "/dr14", "/digitalizare-imm", "/pro-infra"];
  const pages = new Map();
  for (const route of criticalRoutes) pages.set(route, await verifyHtml(route));

  const registry = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8"));
  for (const slug of ["dr12-afir", "dr14-afir", "digitalizare-imm", "pro-infra"]) {
    const program = registry.programs.find((entry) => entry.slug === slug);
    if (!program) throw new Error(`Program registry is missing ${slug}`);
    const html = pages.get(program.pageUrl);
    const expectedAttributes = [
      `data-program-id="${program.id}"`,
      `data-program-status="${program.status}"`,
      `data-verified-at="${program.verifiedAt}"`,
      `data-source-url="${program.sourceUrl.replace(/&/gu, "&amp;")}"`,
    ];
    for (const signal of expectedAttributes) if (!html.includes(signal)) throw new Error(`${program.pageUrl}: missing approved registry signal ${signal}`);
  }

  const sitemapResponse = await request(`/sitemap.xml?t=${Date.now()}`);
  const sitemap = await sitemapResponse.text();
  if (sitemapResponse.status !== 200) throw new Error(`sitemap.xml: HTTP ${sitemapResponse.status}`);
  const sitemapDocuments = [sitemap];
  if (/<sitemapindex\b/iu.test(sitemap)) {
    const childUrls = [...sitemap.matchAll(/<loc>(https:\/\/atelierdeconsultanta\.ro\/[^<]+\.xml)<\/loc>/giu)].map((match) => match[1]);
    if (!childUrls.length) throw new Error("sitemap.xml index does not reference any child sitemap");
    for (const childUrl of childUrls) {
      const childResponse = await request(`${new URL(childUrl).pathname}?t=${Date.now()}`);
      const childXml = await childResponse.text();
      if (childResponse.status !== 200) throw new Error(`${childUrl}: HTTP ${childResponse.status}`);
      sitemapDocuments.push(childXml);
    }
  }
  const sitemapCorpus = sitemapDocuments.join("\n");
  for (const route of criticalRoutes) {
    const url = new URL(route, ORIGIN).href;
    if (!sitemapCorpus.includes(`<loc>${url}</loc>`)) throw new Error(`sitemap set is missing ${url}`);
  }

  const robotsResponse = await request(`/robots.txt?t=${Date.now()}`);
  const robots = await robotsResponse.text();
  if (robotsResponse.status !== 200) throw new Error(`robots.txt: HTTP ${robotsResponse.status}`);
  const namedAgents = parseRobots(robots).groups.flatMap((group) => group.agents).filter((agent) => agent !== "*");
  for (const agent of new Set(namedAgents)) {
    assertCrawlerPolicy(robots, agent);
  }
  const sitemapLines = robots.match(/^Sitemap:\s*https:\/\/atelierdeconsultanta\.ro\/sitemap\.xml\s*$/gimu) || [];
  if (sitemapLines.length !== 1) throw new Error(`robots.txt must contain exactly one canonical Sitemap declaration; found ${sitemapLines.length}`);

  await safeFormProbe("email");
  await safeFormProbe("phone");
  console.log(`Live release verified: ${release.commit} (${criticalRoutes.length} canonical pages, sitemap, crawler policy, email/phone form probes).`);
}

main().catch((error) => {
  console.error(`Live release verification failed: ${error.message}`);
  process.exitCode = 1;
});
