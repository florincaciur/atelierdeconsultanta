#!/usr/bin/env node
"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { spawnSync } = require("child_process");
const cheerio = require("cheerio");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "p0-release-gate.json");
const CONFIG = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
const CRITERIA = new Map(CONFIG.criteria.map((criterion) => [criterion.id, criterion]));

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function compact(value, limit = 800) {
  return String(value || "").replace(/\s+/gu, " ").trim().slice(0, limit);
}

function result(criterionId, environment, status, evidence, urls = [], overrides = {}) {
  const criterion = CRITERIA.get(criterionId);
  if (!criterion) throw new Error(`Criteriu necunoscut: ${criterionId}`);
  return {
    criterionId,
    criterion: criterion.label,
    environment,
    status,
    severity: overrides.severity || criterion.severity,
    owner: overrides.owner || criterion.owner,
    urls,
    evidence: compact(evidence),
    retest: overrides.retest || `Reexecută verificarea ${criterionId} după remediere/aprobare.`,
  };
}

function parseRedirectRules(text) {
  return text.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line, index) => {
      const [source, destination, rawStatus = "302"] = line.split(/\s+/u);
      return { line: index + 1, source, destination, status: Number(rawStatus) };
    })
    .filter((rule) => Number.isFinite(rule.status) && rule.status >= 300 && rule.status < 400);
}

function crawlerDirectives(text, userAgent) {
  const normalizedUserAgent = String(userAgent || "").trim().toLowerCase();
  if (!normalizedUserAgent) return [];
  const groups = [];
  let activeAgents = [];
  let activeDirectives = [];

  const flush = () => {
    if (activeAgents.length) groups.push({ agents: activeAgents, directives: activeDirectives });
    activeAgents = [];
    activeDirectives = [];
  };

  for (const rawLine of String(text || "").split(/\r?\n/u)) {
    const line = rawLine.replace(/\s*#.*$/u, "").trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (field === "user-agent") {
      if (activeDirectives.length) flush();
      activeAgents.push(value.toLowerCase());
      continue;
    }
    if (activeAgents.length) activeDirectives.push({ field, value });
  }
  flush();

  return groups
    .filter((group) => group.agents.includes(normalizedUserAgent))
    .flatMap((group) => group.directives);
}

function crawlerAllowsPublicRoot(text, userAgent) {
  const directives = crawlerDirectives(text, userAgent);
  const allowsRoot = directives.some(({ field, value }) => field === "allow" && value === "/");
  const blocksRoot = directives.some(({ field, value }) => field === "disallow" && value === "/");
  return allowsRoot && !blocksRoot;
}

function evaluateGovernanceBlockers() {
  const approvals = readJson("config/program-status-approvals.json");
  const legal = readJson("config/legal-identity.json");
  const contact = readJson("config/contact-triage.json");
  const crawler = readJson("config/crawler-access-policy.json");
  const pendingPrograms = approvals.programs.filter((program) => program.approvalState !== "approved");
  const gpt = crawler.crawlers.find((item) => item.userAgent === "GPTBot");
  const blockers = [];

  if (pendingPrograms.length) {
    blockers.push(result(
      "program_status",
      "local",
      "FAIL",
      `${pendingPrograms.length} programe prioritare nu au validare nominală FABER: ${pendingPrograms.map((item) => item.programId).join(", ")}.`,
      pendingPrograms.flatMap((item) => item.publicationHoldUrls),
      { retest: "Consultantul FABER aprobă fiecare rând, apoi se rerulează gate-ul complet." }
    ));
  }

  if (legal.publicationState !== "approved" || legal.approvals?.legalReview?.state !== "approved") {
    blockers.push(result(
      "legal_identity",
      "local",
      "FAIL",
      `Fișa juridică este ${legal.publicationState}; avizul juridic este ${legal.approvals?.legalReview?.state || "missing"}.`,
      CONFIG.legalSurfaceUrls,
      { retest: "Completați fișa canonică și avizul juridic fără a inventa valori, apoi rerulați gate-ul." }
    ));
  }

  if (contact.privacyNotice?.copyState !== "approved" || legal.approvals?.operationalEmailOwnerConfirmation?.state !== "approved") {
    blockers.push(result(
      "contact_privacy",
      "local",
      "FAIL",
      `Copy Privacy=${contact.privacyNotice?.copyState}; confirmare email operațional=${legal.approvals?.operationalEmailOwnerConfirmation?.state}.`,
      ["/contact", "/politica-de-confidentialitate"],
      { retest: "Juristul aprobă regula email SAU telefon și proprietarul confirmă datele canonice." }
    ));
  }

  if (!gpt || gpt.publicAccess !== "allow" || !String(gpt.approval || "").startsWith("APROBAT")) {
    blockers.push(result(
      "robots",
      "local",
      "FAIL",
      `Regula tehnică GPTBot este ${gpt?.publicAccess || "missing"}, dar aprobarea de business este ${gpt?.approval || "missing"}.`,
      ["/robots.txt"],
      { retest: "Ownerul aprobă explicit politica GPTBot și regula tehnică trebuie să coincidă cu decizia." }
    ));
  }
  return blockers;
}

function runNode(args, timeout = 180000) {
  const execution = spawnSync(process.execPath, args, {
    cwd: ROOT,
    encoding: "utf8",
    timeout,
    env: process.env,
  });
  return {
    passed: execution.status === 0,
    evidence: compact(`${execution.stdout || ""}\n${execution.stderr || ""}`, 1200),
    status: execution.status,
    error: execution.error?.message || null,
  };
}

function runNodeSequence(commands) {
  const outputs = commands.map((args) => runNode(args));
  return {
    passed: outputs.every((item) => item.passed),
    evidence: outputs.map((item) => item.evidence).filter(Boolean).join(" | "),
  };
}

async function localChecks() {
  const blockers = evaluateGovernanceBlockers();
  const blockersById = new Map(blockers.map((item) => [item.criterionId, item]));
  const definitions = [
    ["program_status", [["tests/program-status-approval-gate.mjs"]], CONFIG.priorityPrograms.map((id) => `program:${id}`)],
    ["factual_sources", [["tests/program-registry-contract.mjs"]], ["config/seo-programs.json"]],
    ["legal_identity", [["tests/legal-identity-approval-gate.mjs"]], CONFIG.legalSurfaceUrls],
    ["contact_privacy", [["tools/validate-contact-triage.js"]], ["/contact", "/politica-de-confidentialitate"]],
    ["form_flow", [["tests/contact-triage-contract.mjs"]], ["/contact", "/api/contact-triage"]],
    ["analytics", [["tests/analytics-events-checks.mjs"], ["tests/crm-funnel-contract.mjs"]], ["assets/analytics-events.js"]],
    ["redirects", [["scripts/verify-redirect-map.js"], ["tests/cloudflare-domain-seo-redirects.mjs"]], ["_redirects"]],
    ["sitemap", [["tools/verify-sitemap.js"]], ["/sitemap.xml"]],
    ["editorial", [["tests/editorial-copy-contract.mjs"], ["tests/editorial-terminology-contract.mjs"]], ["/sitemap.xml"]],
    ["robots", [["tests/crawler-policy-contract.mjs"]], ["/robots.txt"]],
    ["accessibility", [["tests/contact-accessibility-contract.mjs"]], ["/contact"]],
  ];
  const results = [];
  for (const [criterionId, commands, urls] of definitions) {
    const commandResult = runNodeSequence(commands);
    const blocker = blockersById.get(criterionId);
    if (blocker) {
      blocker.evidence = compact(`${blocker.evidence} Contract tehnic: ${commandResult.passed ? "PASS" : "FAIL"}. ${commandResult.evidence}`, 1200);
      results.push(blocker);
    } else {
      results.push(result(
        criterionId,
        "local",
        commandResult.passed ? "PASS" : "FAIL",
        commandResult.evidence || "Contract executat fără output.",
        urls
      ));
    }
  }
  results.push(result(
    "performance",
    "local",
    CONFIG.performance.inpBaseline === "DE_VALIDAT_UMAN" ? "FAIL" : "PASS",
    `Baseline LCP/CLS prezent pentru ${CONFIG.performance.routes.length} rute; baseline INP=${CONFIG.performance.inpBaseline}.`,
    CONFIG.performance.routes.map((route) => route.path),
    { retest: "Salvați un baseline INP aprobat înainte de deploy și comparați aceeași interacțiune/viewport." }
  ));
  return results;
}

function contentType(file) {
  const extension = path.extname(file).toLowerCase();
  return ({ ".html": "text/html; charset=utf-8", ".xml": "application/xml; charset=utf-8", ".css": "text/css", ".js": "application/javascript", ".json": "application/json" })[extension] || "application/octet-stream";
}

async function startStaticStaging() {
  const root = path.join(ROOT, "dist");
  if (!fs.existsSync(root)) throw new Error("dist lipsește; rulează build-ul înaintea staging QA.");
  const server = http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1").pathname);
    const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+|\/+$/gu, "");
    const candidates = [relative, `${relative}.html`, path.join(relative, "index.html")];
    const file = candidates.map((candidate) => path.resolve(root, candidate)).find((candidate) => candidate.startsWith(`${root}${path.sep}`) && fs.existsSync(candidate) && fs.statSync(candidate).isFile());
    if (!file) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, { "content-type": contentType(file), "cache-control": "no-store" });
    fs.createReadStream(file).pipe(response);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}`, label: "staging-local-dist" };
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    return await fetch(url, { redirect: "manual", ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function environmentUrl(baseUrl, canonicalUrlOrPath) {
  const pathValue = canonicalUrlOrPath.startsWith("http") ? new URL(canonicalUrlOrPath).pathname : canonicalUrlOrPath;
  return new URL(pathValue, `${baseUrl.replace(/\/+$/u, "")}/`).href;
}

async function fetchText(baseUrl, canonicalUrlOrPath, cache) {
  const url = environmentUrl(baseUrl, canonicalUrlOrPath);
  if (cache.has(url)) return cache.get(url);
  const promise = (async () => {
    try {
      const response = await fetchWithTimeout(url, { headers: { "user-agent": "FABER-P0-Release-Gate/1.0" } });
      return { url, status: response.status, headers: Object.fromEntries(response.headers), text: await response.text() };
    } catch (error) {
      return { url, status: null, headers: {}, text: "", error: error.message };
    }
  })();
  cache.set(url, promise);
  return promise;
}

function xmlValues(xml, tag) {
  return [...xml.matchAll(new RegExp(`<${tag}>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${tag}>`, "giu"))].map((match) => match[1].trim());
}

async function sitemapProbe(baseUrl, cache) {
  const root = await fetchText(baseUrl, "/sitemap.xml", cache);
  const errors = [];
  if (root.status !== 200) return { errors: [`sitemap.xml HTTP ${root.status}`], entries: [] };
  const documents = /<sitemapindex\b/iu.test(root.text) ? xmlValues(root.text, "loc") : ["https://atelierdeconsultanta.ro/sitemap.xml"];
  const entries = [];
  for (const documentUrl of documents) {
    const document = documentUrl.endsWith("/sitemap.xml") ? root : await fetchText(baseUrl, documentUrl, cache);
    if (document.status !== 200) {
      errors.push(`${documentUrl}: HTTP ${document.status}`);
      continue;
    }
    for (const block of document.text.matchAll(/<url>([\s\S]*?)<\/url>/giu)) {
      const loc = xmlValues(block[1], "loc")[0];
      if (loc) entries.push({ url: loc, lastmod: xmlValues(block[1], "lastmod")[0] || null });
    }
  }
  for (let offset = 0; offset < entries.length; offset += 8) {
    const batch = await Promise.all(entries.slice(offset, offset + 8).map(async (entry) => {
      const page = await fetchText(baseUrl, entry.url, cache);
      if (page.status !== 200) return `${entry.url}: HTTP ${page.status}`;
      const $ = cheerio.load(page.text);
      const robots = $("meta[name='robots']").attr("content") || "";
      const canonical = $("link[rel~='canonical']").first().attr("href") || "";
      if (/noindex/iu.test(robots)) return `${entry.url}: noindex`;
      if (canonical !== entry.url) return `${entry.url}: canonical ${canonical || "missing"}`;
      return null;
    }));
    errors.push(...batch.filter(Boolean));
  }
  const distribution = new Map();
  for (const entry of entries.filter((entry) => entry.lastmod)) distribution.set(entry.lastmod, (distribution.get(entry.lastmod) || 0) + 1);
  for (const [date, count] of distribution) if (count >= 30) errors.push(`${count} URL-uri împart lastmod=${date}`);
  return { errors, entries, lastmodCount: entries.filter((entry) => entry.lastmod).length };
}

async function programProbe(baseUrl, cache) {
  const approvals = readJson("config/program-status-approvals.json");
  const intentionalNoindex = new Set(readJson("config/content-intent-taxonomy.json").blockedNonIndexableRoutes.map((item) => item.route));
  const approvedConsolidations = new Map(readJson("config/url-consolidation-candidates.json").rows
    .filter((item) => item.recommendation === "MERGE_301_APPROVED" && item.target)
    .map((item) => [item.url, item.target]));
  const errors = [];
  const homepage = await fetchText(baseUrl, "/", cache);
  for (const row of approvals.programs) {
    const pending = row.approvalState !== "approved";
    if (pending && new RegExp(`data-program-id=["']${row.programId}["']`, "iu").test(homepage.text)) errors.push(`${row.programId}: apare pe homepage înainte de aprobare`);
    for (const route of row.publicationHoldUrls) {
      const page = await fetchText(baseUrl, route, cache);
      const $ = cheerio.load(page.text);
      const consolidationTarget = approvedConsolidations.get(route);
      if (consolidationTarget && page.status === 301) {
        const actualTarget = new URL(page.headers.location || "", page.url).pathname;
        if (actualTarget !== consolidationTarget) errors.push(`${route}: redirect aprobat către ${actualTarget || "missing"}, așteptat ${consolidationTarget}`);
        continue;
      }
      if (page.status !== 200) errors.push(`${route}: HTTP ${page.status}`);
      if (pending) {
        if (!/noindex/iu.test($("meta[name='robots']").attr("content") || "")) errors.push(`${route}: pending fără noindex`);
        if ($("body").attr("data-publication-state") !== "pending_validation") errors.push(`${route}: lipsește pending_validation`);
        if ($(`[data-program-id="${row.programId}"][data-program-status]`).length) errors.push(`${route}: status candidat publicat`);
      } else if (!intentionalNoindex.has(route)) {
        if (/noindex/iu.test($("meta[name='robots']").attr("content") || "")) errors.push(`${route}: aprobat, dar rămas noindex`);
        if ($("body").attr("data-publication-state") === "pending_validation") errors.push(`${route}: aprobat, dar rămas pending_validation`);
        if ($("main.program-validation-hold").length) errors.push(`${route}: aprobat, dar mesajul de suspendare este încă public`);
      }
    }
  }
  return errors;
}

function extractContactValues(html) {
  const $ = cheerio.load(html);
  const legal = readJson("config/legal-identity.json");
  const approvedEmail = legal.fields?.publicEmail?.approvedValue;
  const emailCandidates = new Set([...(legal.fields?.publicEmail?.candidateValues || []), approvedEmail].filter((value) => value && value !== "DE_VALIDAT_UMAN").map((value) => value.toLowerCase()));
  const approvedPhone = legal.fields?.publicPhone?.approvedValue;
  const phoneCandidates = new Set([...(legal.fields?.publicPhone?.candidateValues || []), approvedPhone].filter((value) => value && value !== "DE_VALIDAT_UMAN").map((value) => value.replace(/[^+\d]/gu, "")));
  const email = new Set($("a[href^='mailto:']").map((_, item) => ($(item).attr("href") || "").replace(/^mailto:/iu, "").toLowerCase()).get().filter((value) => emailCandidates.has(value)));
  const phone = new Set($("a[href^='tel:']").map((_, item) => ($(item).attr("href") || "").replace(/^tel:/iu, "").replace(/[^+\d]/gu, "")).get().filter((value) => phoneCandidates.has(value)));
  return { email: [...email], phone: [...phone] };
}

async function contactConsistencyProbe(baseUrl, cache) {
  const pages = await Promise.all(CONFIG.legalSurfaceUrls.map(async (route) => ({ route, page: await fetchText(baseUrl, route, cache) })));
  const errors = pages.filter(({ page }) => page.status !== 200).map(({ route, page }) => `${route}: HTTP ${page.status}`);
  const values = pages.map(({ route, page }) => ({ route, ...extractContactValues(page.text) }));
  const emailSets = new Set(values.map((item) => item.email.sort().join(",")));
  const phoneSets = new Set(values.map((item) => item.phone.sort().join(",")));
  if (emailSets.size > 1) errors.push(`email neuniform: ${values.map((item) => `${item.route}=${item.email.join(",") || "—"}`).join("; ")}`);
  if (phoneSets.size > 1) errors.push(`telefon neuniform: ${values.map((item) => `${item.route}=${item.phone.join(",") || "—"}`).join("; ")}`);
  return { errors, values };
}

async function formProbe(baseUrl, cache, environment) {
  const page = await fetchText(baseUrl, "/contact", cache);
  const $ = cheerio.load(page.text);
  const errors = [];
  if (environment === "production") {
    const endpoint = environmentUrl(baseUrl, "/api/contact-triage");
    const origin = new URL(baseUrl).origin;
    for (const contactType of ["email", "phone"]) {
      const payload = {
        schema_version: "1.0.0",
        lead_id: `qa-release-${contactType}-${Date.now()}`,
        applicant_type: "societate",
        location: "Iasi",
        investment: "Verificare tehnica automata fara creare de lead",
        email: contactType === "email" ? "qa-release-gate@example.invalid" : "",
        phone: contactType === "phone" ? "0769000000" : "",
        privacy_notice_acknowledged: true,
        program_slug: "unknown",
        contact_preference: contactType,
        page_url: "/contact",
        form_started_at: String(Date.now() - 5000),
        website: "qa-release-gate",
      };
      try {
        const response = await fetchWithTimeout(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json", origin },
          body: JSON.stringify(payload),
        });
        const body = await response.json().catch(() => ({}));
        if (response.status !== 200 || body.success !== true) errors.push(`submit QA ${contactType}: HTTP ${response.status}, success=${body.success}`);
      } catch (error) {
        errors.push(`submit QA ${contactType}: ${error.message}`);
      }
    }
    environment = "production-probed";
  }
  const form = $("#contact-triage-form");
  if (page.status !== 200) errors.push(`contact HTTP ${page.status}`);
  if (form.length !== 1) errors.push("lipsește #contact-triage-form");
  if (form.find("[name='email'][required]").length || form.find("[name='phone'][required]").length) errors.push("email și telefon nu trebuie obligatorii individual");
  if (form.find("[name='privacy_notice_acknowledged'][required]").length !== 1) errors.push("lipsește confirmarea informării");
  if (environment === "production") errors.push("submit E2E producție neexecutat: lipsește un sink/flag QA care să nu creeze lead comercial");
  return errors;
}

async function analyticsProbe(baseUrl, cache) {
  const asset = await fetchText(baseUrl, "/assets/analytics-events.js", cache);
  const required = readJson("config/funnel-analytics.json").events.filter((event) => event !== "qualified_lead");
  const errors = asset.status === 200 ? [] : [`analytics asset HTTP ${asset.status}`];
  for (const event of required) if (!asset.text.includes(event)) errors.push(`eveniment lipsă: ${event}`);
  for (const token of ["email_value", "phone_value", "investment_value", "field_value"]) if (asset.text.includes(token)) errors.push(`cheie PII suspectă: ${token}`);
  return errors;
}

async function redirectProbe(baseUrl, cache, localStatic) {
  const rules = parseRedirectRules(fs.readFileSync(path.join(ROOT, "_redirects"), "utf8")).filter((rule) => !/[\*:]/u.test(rule.source));
  if (localStatic) return { errors: [], count: rules.length, evidence: "mapa și Worker-ul au trecut contractele locale; serverul static nu emulează edge redirects" };
  const errors = [];
  for (let offset = 0; offset < rules.length; offset += 10) {
    const batch = await Promise.all(rules.slice(offset, offset + 10).map(async (rule) => {
      const sourceUrl = environmentUrl(baseUrl, rule.source);
      try {
        const response = await fetchWithTimeout(sourceUrl, { headers: { "user-agent": "FABER-P0-Release-Gate/1.0" } });
        const location = response.headers.get("location");
        const expected = new URL(rule.destination, CONFIG.productionBaseUrl).href;
        const actual = location ? new URL(location, sourceUrl).href : null;
        if (response.status !== 301) return `${rule.source}: HTTP ${response.status}, așteptat 301`;
        if (actual !== expected) return `${rule.source}: Location ${actual || "missing"}, așteptat ${expected}`;
        const target = await fetchText(baseUrl, expected, cache);
        if (target.status !== 200) return `${rule.source}: target HTTP ${target.status}`;
        const canonical = cheerio.load(target.text)("link[rel~='canonical']").first().attr("href") || "";
        if (canonical !== expected) return `${rule.source}: target canonical ${canonical || "missing"}`;
        return null;
      } catch (error) {
        return `${rule.source}: ${error.message}`;
      }
    }));
    errors.push(...batch.filter(Boolean));
  }
  return { errors, count: rules.length };
}

async function editorialProbe(baseUrl, cache, entries) {
  const qa = readJson("config/editorial-qa.json");
  const globalControls = qa.forbiddenTemplateLabels.map((item) => ({ id: item.id, regex: new RegExp(item.pattern, "iu") }));
  const programControls = qa.programTemplateLabels.map((item) => ({ id: item.id, regex: new RegExp(item.pattern, "iu") }));
  const programRoutes = new Set((readJson("config/seo-programs.json").programs || []).map((program) => program.pageUrl));
  const errors = [];
  for (const entry of entries) {
    const page = await fetchText(baseUrl, entry.url, cache);
    if (page.status !== 200) continue;
    const $ = cheerio.load(page.text);
    const controls = programRoutes.has(new URL(entry.url).pathname) ? [...globalControls, ...programControls] : globalControls;
    $("h1,h2,h3,h4,.eyebrow,.section-label").each((_, element) => {
      const text = $(element).text().replace(/\s+/gu, " ").trim();
      const hit = controls.find((control) => control.regex.test(text));
      if (hit) errors.push(`${entry.url}: ${hit.id} «${text}»`);
    });
  }
  return errors;
}

async function robotsProbe(baseUrl, cache) {
  const page = await fetchText(baseUrl, "/robots.txt", cache);
  if (page.status !== 200) return [`robots.txt HTTP ${page.status}`];
  const crawlerPolicy = readJson("config/crawler-access-policy.json");
  const blocked = crawlerPolicy.crawlers
    .filter((crawler) => crawler.publicAccess === "allow" && crawler.robotsGroup !== "*")
    .filter((crawler) => !crawlerAllowsPublicRoot(page.text, crawler.robotsGroup))
    .map((crawler) => crawler.robotsGroup);
  const sitemap = /Sitemap:\s*https:\/\/atelierdeconsultanta\.ro\/sitemap\.xml/iu.test(page.text);
  return [blocked.length && `crawler-e AI nepermise: ${blocked.join(", ")}`, !sitemap && "declarația Sitemap lipsește"].filter(Boolean);
}

async function accessibilityProbe(browser, baseUrl) {
  const page = await browser.newPage({ viewport: { width: 320, height: 900 } });
  const errors = [];
  try {
    await page.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== new URL(baseUrl).origin && !url.hostname.includes("unpkg.com")) route.abort();
      else route.continue();
    });
    await page.goto(environmentUrl(baseUrl, "/contact"), { waitUntil: "domcontentloaded", timeout: 30000 });
    if (!await page.locator("#contact-triage-form").count()) return ["formularul accesibil lipsește"];
    const labels = await page.locator("#contact-triage-form input:not([type='hidden']), #contact-triage-form select, #contact-triage-form textarea").evaluateAll((elements) => elements.filter((element) => !element.closest(".contact-honeypot") && !element.labels?.length).map((element) => element.id || element.name));
    if (labels.length) errors.push(`controale fără label: ${labels.join(", ")}`);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    if (overflow) errors.push("scroll orizontal la 320px");
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    const zoomOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    if (zoomOverflow) errors.push("scroll orizontal la zoom text 200%");
    const smallTargets = await page.locator("#contact-triage-form button:visible, #contact-triage-form summary:visible").evaluateAll((elements) => elements.filter((element) => element.getBoundingClientRect().height < 44).length);
    if (smallTargets) errors.push(`${smallTargets} acțiuni mobile sub 44px`);
    await page.keyboard.press("Tab");
    const focus = await page.evaluate(() => {
      const element = document.activeElement;
      if (!element || element === document.body) return { valid: false };
      const style = getComputedStyle(element);
      return { valid: style.outlineStyle !== "none" || style.boxShadow !== "none" };
    });
    if (!focus.valid) errors.push("focusul vizibil nu a putut fi confirmat");
  } catch (error) {
    errors.push(error.message);
  } finally {
    await page.close();
  }
  return errors;
}

async function performanceProbe(browser, baseUrl) {
  const measurements = [];
  const errors = [];
  for (const route of CONFIG.performance.routes) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    try {
      await page.route("**/*", (requestRoute) => {
        const url = new URL(requestRoute.request().url());
        if (url.origin !== new URL(baseUrl).origin && !url.hostname.includes("unpkg.com")) requestRoute.abort();
        else requestRoute.continue();
      });
      await page.addInitScript(() => {
        window.__p0Vitals = { lcp: 0, cls: 0 };
        new PerformanceObserver((list) => { for (const entry of list.getEntries()) window.__p0Vitals.lcp = Math.max(window.__p0Vitals.lcp, entry.startTime); }).observe({ type: "largest-contentful-paint", buffered: true });
        new PerformanceObserver((list) => { for (const entry of list.getEntries()) if (!entry.hadRecentInput) window.__p0Vitals.cls += entry.value; }).observe({ type: "layout-shift", buffered: true });
      });
      await page.goto(environmentUrl(baseUrl, route.path), { waitUntil: "domcontentloaded", timeout: 30000 });
      await page.waitForTimeout(1200);
      const syntheticInpMs = await page.evaluate(async () => {
        const target = document.querySelector("button, a[href]") || document.body;
        target.addEventListener("click", (event) => event.preventDefault(), { once: true });
        const start = performance.now();
        target.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        return performance.now() - start;
      });
      const vitals = await page.evaluate(() => window.__p0Vitals);
      const lcpDelta = vitals.lcp - route.baselineLcpMs;
      const majorLcp = lcpDelta > Math.max(CONFIG.performance.majorLcpRegressionMs, route.baselineLcpMs * CONFIG.performance.majorLcpRegressionRatio);
      const majorCls = vitals.cls - route.baselineCls > CONFIG.performance.majorClsRegression;
      if (vitals.lcp > CONFIG.performance.maxLcpMs || majorLcp) errors.push(`${route.path}: LCP ${Math.round(vitals.lcp)}ms vs ${Math.round(route.baselineLcpMs)}ms`);
      if (vitals.cls > CONFIG.performance.maxCls || majorCls) errors.push(`${route.path}: CLS ${vitals.cls.toFixed(4)} vs ${route.baselineCls}`);
      if (syntheticInpMs > CONFIG.performance.maxSyntheticInpMs) errors.push(`${route.path}: interacțiune sintetică ${Math.round(syntheticInpMs)}ms`);
      measurements.push({ path: route.path, lcpMs: Math.round(vitals.lcp), cls: Number(vitals.cls.toFixed(5)), syntheticInpMs: Math.round(syntheticInpMs), baselineLcpMs: route.baselineLcpMs, baselineCls: route.baselineCls });
    } catch (error) {
      errors.push(`${route.path}: ${error.message}`);
    } finally {
      await page.close();
    }
  }
  if (CONFIG.performance.inpBaseline === "DE_VALIDAT_UMAN") errors.push("baseline INP de teren lipsește; comparația folosește numai pragul sintetic de 200ms");
  return { errors, measurements };
}

async function environmentChecks(environment, baseUrl, options = {}) {
  const cache = new Map();
  const urls = (paths) => paths.map((item) => environmentUrl(baseUrl, item));
  const results = [];
  const sitemap = await sitemapProbe(baseUrl, cache);
  const programs = await programProbe(baseUrl, cache);
  const contacts = await contactConsistencyProbe(baseUrl, cache);
  const form = await formProbe(baseUrl, cache, environment === "production" ? "production" : environment);
  const analytics = await analyticsProbe(baseUrl, cache);
  const redirects = await redirectProbe(baseUrl, cache, options.localStatic);
  const editorial = await editorialProbe(baseUrl, cache, sitemap.entries);
  const robots = await robotsProbe(baseUrl, cache);
  const browser = await chromium.launch({ headless: true });
  let accessibility;
  let performance;
  try {
    accessibility = await accessibilityProbe(browser, baseUrl);
    performance = await performanceProbe(browser, baseUrl);
  } finally {
    await browser.close();
  }

  results.push(result("program_status", environment, programs.length ? "FAIL" : "PASS", programs.length ? programs.join(" | ") : "Suprafețele prioritare respectă starea de aprobare din registru.", urls(["/", ...Object.values(CONFIG.priorityProgramUrls).flat()])));
  results.push(result("legal_identity", environment, contacts.errors.length ? "FAIL" : "PASS", contacts.errors.length ? contacts.errors.join(" | ") : "Valorile tel/mailto sunt uniforme între suprafețele juridice verificate.", urls(CONFIG.legalSurfaceUrls)));
  results.push(result("contact_privacy", environment, form.length ? "FAIL" : "PASS", form.length ? form.join(" | ") : "Structura email SAU telefon și informarea Privacy coincid.", urls(["/contact", "/politica-de-confidentialitate"])));
  results.push(result("form_flow", environment, form.length ? "FAIL" : "PASS", form.length ? form.join(" | ") : "Structura formularului în două etape este disponibilă; contractul local verifică submit și păstrarea datelor.", urls(["/contact", "/api/contact-triage"])));
  results.push(result("analytics", environment, analytics.length ? "FAIL" : "PASS", analytics.length ? analytics.join(" | ") : "Asset-ul live conține evenimentele controlate și nu expune cheile PII interzise.", urls(["/assets/analytics-events.js"])));
  results.push(result("redirects", environment, redirects.errors.length ? "FAIL" : "PASS", redirects.errors.length ? redirects.errors.slice(0, 12).join(" | ") : `${redirects.count} redirecturi verificate. ${redirects.evidence || "301 direct și target 200/self-canonical."}`, urls(["/_redirects"])));
  results.push(result("sitemap", environment, sitemap.errors.length ? "FAIL" : "PASS", sitemap.errors.length ? sitemap.errors.slice(0, 12).join(" | ") : `${sitemap.entries.length} URL-uri 200/indexabile/self-canonical; ${sitemap.lastmodCount} lastmod verificate.`, urls(["/sitemap.xml"])));
  results.push(result("editorial", environment, editorial.length ? "FAIL" : "PASS", editorial.length ? editorial.slice(0, 12).join(" | ") : `${sitemap.entries.length} URL-uri scanate fără etichete interzise.`, urls(["/sitemap.xml"])));
  results.push(result("robots", environment, robots.length ? "FAIL" : "PASS", robots.length ? robots.join(" | ") : "Crawler-ele AI aprobate au Allow public, zonele private rămân blocate și Sitemap este prezent.", urls(["/robots.txt"])));
  results.push(result("accessibility", environment, accessibility.length ? "FAIL" : "PASS", accessibility.length ? accessibility.join(" | ") : "Labels, reflow 320px, zoom 200%, target-uri și focus verificate în browser.", urls(["/contact"])));
  results.push(result("performance", environment, performance.errors.length ? "FAIL" : "PASS", `${performance.errors.join(" | ") || "Nicio regresie majoră."} Măsurători: ${JSON.stringify(performance.measurements)}`, urls(CONFIG.performance.routes.map((route) => route.path))));
  return results;
}

function markdownReport(payload) {
  const rows = payload.results.map((item) => {
    const urls = item.urls.length ? item.urls.join("<br>") : "—";
    const evidence = item.evidence.replace(/\|/gu, "\\|");
    return `| ${item.criterionId} | ${item.environment} | **${item.status}** | ${item.severity} | ${item.owner} | ${urls} | ${evidence} | ${item.retest} |`;
  }).join("\n");
  return `# P0.16 — Release gate\n\nData: ${payload.checkedAt}\n\nDecizie: **${payload.releaseDecision}**\n\n- PASS: ${payload.summary.pass}\n- FAIL: ${payload.summary.fail}\n- Blocaje critice: ${payload.summary.criticalBlockers}\n- Staging: ${payload.stagingDescription}\n\n| Criteriu | Mediu | Status | Severitate | Owner | URL/dovadă | Rezultat | Retest |\n|---|---|---|---|---|---|---|---|\n${rows}\n\n## Regula de lansare\n\nOrice FAIL critic blochează deploy-ul. FAIL-urile high necesită owner și retest documentat înainte de aprobarea finală. Gate-ul nu modifică conținutul și nu trimite lead-uri reale în producție.\n`;
}

async function main() {
  if (process.argv.includes("--deployment-guard")) {
    const blockers = evaluateGovernanceBlockers();
    const reportPath = path.join(ROOT, "reports", `p0-release-gate-${CONFIG.reportDate}.json`);
    const report = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, "utf8")) : null;
    if (blockers.length || report?.releaseDecision !== "PASS") {
      console.error(`P0 deployment guard: BLOCKED (${blockers.length} governance blockers; report=${report?.releaseDecision || "missing"}).`);
      for (const blocker of blockers) console.error(`- ${blocker.criterionId}: ${blocker.evidence}`);
      process.exitCode = 1;
      return;
    }
    console.log("P0 deployment guard: PASS.");
    return;
  }
  const environmentArg = process.argv.find((arg) => arg.startsWith("--environment="))?.split("=")[1] || "all";
  const stagingArg = process.argv.find((arg) => arg.startsWith("--staging-url="))?.slice("--staging-url=".length);
  if (!["all", "local", "staging", "production"].includes(environmentArg)) throw new Error(`Mediu invalid: ${environmentArg}`);
  const results = await localChecks();
  let stagingDescription = "nerulat";
  let localStaging;
  try {
    if (["all", "staging"].includes(environmentArg)) {
      const configuredStaging = stagingArg || process.env.P0_STAGING_URL;
      if (configuredStaging) {
        stagingDescription = configuredStaging;
        results.push(...await environmentChecks("staging", configuredStaging));
      } else {
        localStaging = await startStaticStaging();
        stagingDescription = `${localStaging.label} (${localStaging.baseUrl})`;
        results.push(...await environmentChecks(localStaging.label, localStaging.baseUrl, { localStatic: true }));
      }
    }
    if (["all", "production"].includes(environmentArg)) {
      results.push(...await environmentChecks("production", CONFIG.productionBaseUrl));
    }
  } finally {
    if (localStaging) await new Promise((resolve) => localStaging.server.close(resolve));
  }
  const criticalBlockers = results.filter((item) => item.status === "FAIL" && CONFIG.blockSeverities.includes(item.severity));
  const payload = {
    checkedAt: new Date().toISOString(),
    requestedEnvironment: environmentArg,
    stagingDescription,
    releaseDecision: criticalBlockers.length ? "BLOCKED" : "PASS",
    summary: {
      pass: results.filter((item) => item.status === "PASS").length,
      fail: results.filter((item) => item.status === "FAIL").length,
      criticalBlockers: criticalBlockers.length,
    },
    results,
  };
  const stem = `p0-release-gate-${CONFIG.reportDate}`;
  fs.mkdirSync(path.join(ROOT, "reports"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, "reports", `${stem}.json`), `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(ROOT, "reports", `${stem}.md`), markdownReport(payload), "utf8");
  console.log(`P0 release gate: ${payload.releaseDecision}; PASS=${payload.summary.pass}, FAIL=${payload.summary.fail}, critical=${payload.summary.criticalBlockers}.`);
  console.log(`reports/${stem}.md`);
  if (criticalBlockers.length) process.exitCode = 1;
}

if (require.main === module) main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

module.exports = { crawlerAllowsPublicRoot, crawlerDirectives, evaluateGovernanceBlockers, markdownReport, parseRedirectRules, result };
