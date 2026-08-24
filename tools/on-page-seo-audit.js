#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { SITE, cleanText, comparableText, fileForRoute, sitemapRoutes } = require("./structured-data-utils");
const { loadProgramConfig, programForRoute } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const REQUIRED_OG_FIELDS = ["title", "description", "type", "url", "image", "image:alt"];
const REQUIRED_TWITTER_FIELDS = ["card", "title", "description", "image", "image:alt"];

function exactMeta($, selector, label, errors) {
  const elements = $(selector);
  if (elements.length !== 1) {
    errors.push(`${label} apare de ${elements.length} ori`);
    return "";
  }
  const value = cleanText(elements.first().attr("content"));
  if (!value) errors.push(`${label} este gol`);
  return value;
}

function exactLink($, selector, label, errors) {
  const elements = $(selector);
  if (elements.length !== 1) {
    errors.push(`${label} apare de ${elements.length} ori`);
    return "";
  }
  const value = cleanText(elements.first().attr("href"));
  if (!value) errors.push(`${label} este gol`);
  return value;
}

function isHiddenHeading($, element) {
  return $(element).parents().addBack().toArray().some((node) => {
    const current = $(node);
    if (current.is("[hidden], [aria-hidden='true' i], template, nav, aside, footer")) return true;
    const style = current.attr("style") || "";
    return /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\s*(?:;|$)/iu.test(style);
  });
}

function auditHeadings($, errors) {
  const allH1 = $("h1").filter((_, element) => !isHiddenHeading($, element));
  if (allH1.length !== 1) errors.push(`H1 vizibil apare de ${allH1.length} ori`);
  if (allH1.length === 1 && !cleanText(allH1.first().text())) errors.push("H1 este gol");

  const headings = $("body h1, body h2, body h3, body h4, body h5, body h6")
    .filter((_, element) => !isHiddenHeading($, element))
    .toArray();
  if (!headings.length) return [];
  const levels = headings.map((element) => Number(element.tagName.slice(1)));
  if (levels[0] !== 1) errors.push(`primul heading de conținut este H${levels[0]}, nu H1`);
  headings.forEach((element, index) => {
    if (!cleanText($(element).text())) errors.push(`heading gol la poziția ${index + 1}`);
    if (index > 0 && levels[index] > levels[index - 1] + 1) {
      errors.push(`ierarhie întreruptă: H${levels[index - 1]} urmat de H${levels[index]}`);
    }
  });
  return levels;
}

function auditShareImage(root, rawUrl, label, errors) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    errors.push(`${label} nu este URL absolut valid`);
    return;
  }
  if (url.protocol !== "https:") errors.push(`${label} nu folosește HTTPS`);
  if (url.origin !== SITE) return;
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  if (!relative || !fs.existsSync(path.join(root, relative))) errors.push(`${label} indică un asset local inexistent: ${url.pathname}`);
}

function programIdentityIsPresent(title, program) {
  const generic = new Set(["program", "programul", "schema", "fondul", "pentru", "investitii", "finantari", "apel", "apeluri"]);
  const titleTokens = new Set(comparableText(title).split(/\s+/u).filter(Boolean));
  const candidates = comparableText([program.acronym, program.shortName, program.displayName, program.name].filter(Boolean).join(" "))
    .split(/\s+/u)
    .filter((value) => value.length >= 3 && !generic.has(value));
  return candidates.some((candidate) => titleTokens.has(candidate));
}

function factualYears(program) {
  const source = [program.name, program.shortName, program.displayName, program.statusLabel, program.statusRationale,
    program.sourceVersion, program.applicationStart, program.applicationEnd, program.verifiedAt, program.lastMeaningfulUpdate]
    .filter(Boolean).join(" ");
  return new Set(source.match(/\b20\d{2}\b/gu) || []);
}

function auditProgramMetadata(page, program, errors) {
  if (page.title !== cleanText(program.metaTitle)) errors.push("title diferă de metaTitle din registrul factual al programului");
  if (page.description !== cleanText(program.metaDescription)) errors.push("meta description diferă de metaDescription din registrul factual al programului");
  if (!programIdentityIsPresent(page.title, program)) errors.push("title nu include denumirea sau acronimul programului");

  const claims = [page.title, page.description, page.ogTitle, page.ogDescription, page.h1].join(" ");
  const claimsOpen = /\b(?:apel(?:ul)?|sesiun(?:ea|e)|depuner(?:ea|ile)|înscrier(?:ea|ile))\s+(?:sunt\s+|este\s+)?deschis(?:ă|e)?\b/iu.test(claims);
  if (claimsOpen && program.status !== "apel_deschis") errors.push(`metadata afirmă depuneri deschise, dar statusul este ${program.status}`);

  const allowedYears = factualYears(program);
  const claimedYears = new Set([page.title, page.description, page.h1].join(" ").match(/\b20\d{2}\b/gu) || []);
  for (const year of claimedYears) if (!allowedYears.has(year)) errors.push(`anul ${year} nu este susținut de registrul factual al programului`);
}

function auditRoute(root, route, programs) {
  const file = fileForRoute(root, route);
  const errors = [];
  if (!fs.existsSync(file)) return { route, file, errors: ["fișierul HTML canonic lipsește"] };
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const expectedCanonical = `${SITE}${route === "/" ? "/" : route}`;

  const titles = $("head > title");
  if (titles.length !== 1) errors.push(`title apare de ${titles.length} ori`);
  const title = cleanText(titles.first().text());
  if (!title) errors.push("title este gol");
  const description = exactMeta($, "head meta[name='description' i]", "meta description", errors);
  const canonical = exactLink($, "head link[rel='canonical' i]", "canonical", errors);
  if (canonical && canonical !== expectedCanonical) errors.push(`canonical nu este self-referencing: ${canonical}`);

  const robots = exactMeta($, "head meta[name='robots' i]", "meta robots", errors);
  if (/\bnoindex\b/iu.test(robots)) errors.push("ruta din sitemap are noindex");
  if (/\bnofollow\b/iu.test(robots)) errors.push("ruta indexabilă are nofollow");

  const og = {};
  for (const field of REQUIRED_OG_FIELDS) og[field] = exactMeta($, `head meta[property='og:${field}' i]`, `og:${field}`, errors);
  if (og.url && og.url !== canonical) errors.push(`og:url diferă de canonical: ${og.url}`);
  if (og.image) auditShareImage(root, og.image, "og:image", errors);

  const twitterElements = $("head meta").filter((_, element) => /^twitter:/iu.test($(element).attr("name") || $(element).attr("property") || ""));
  if (twitterElements.length) {
    for (const field of REQUIRED_TWITTER_FIELDS) {
      const value = exactMeta($, `head meta[name='twitter:${field}' i], head meta[property='twitter:${field}' i]`, `twitter:${field}`, errors);
      if (field === "image" && value) auditShareImage(root, value, "twitter:image", errors);
    }
  }

  const headingLevels = auditHeadings($, errors);
  const h1 = cleanText($("h1").filter((_, element) => !isHiddenHeading($, element)).first().text());
  const page = { route, title, description, canonical, robots, ogTitle: og.title, ogDescription: og.description,
    ogImage: og.image, h1, headingLevels };
  const program = programForRoute(route, programs);
  if (program) auditProgramMetadata(page, program, errors);
  return { ...page, file: path.relative(root, file).split(path.sep).join("/"), programId: program?.id || null, errors };
}

function duplicateTitleErrors(pages) {
  const byTitle = new Map();
  for (const page of pages) {
    const key = comparableText(page.title);
    if (!key) continue;
    if (!byTitle.has(key)) byTitle.set(key, []);
    byTitle.get(key).push(page.route);
  }
  return [...byTitle.values()].filter((routes) => routes.length > 1).map((routes) => `title duplicat: ${routes.join(", ")}`);
}

function auditSite(root = ROOT) {
  const programs = loadProgramConfig().programs;
  const pages = sitemapRoutes(root).map((route) => auditRoute(root, route, programs));
  const globalErrors = duplicateTitleErrors(pages);
  return {
    auditedAt: new Date().toISOString(), routes: pages.length,
    programRoutes: pages.filter((page) => page.programId).length, pages, globalErrors,
    errorCount: globalErrors.length + pages.reduce((sum, page) => sum + page.errors.length, 0)
  };
}

function main() {
  const result = auditSite();
  if (process.argv.includes("--report")) {
    const reportPath = path.join(ROOT, "reports", "on-page-seo-audit.json");
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
    console.log(`Raport: ${path.relative(ROOT, reportPath).split(path.sep).join("/")}`);
  }
  for (const error of result.globalErrors) console.error(`ERROR ${error}`);
  for (const page of result.pages.filter((item) => item.errors.length)) {
    for (const error of page.errors) console.error(`ERROR ${page.route}: ${error}`);
  }
  if (result.errorCount) {
    console.error(`Audit on-page eșuat: ${result.routes} rute, ${result.programRoutes} programe, ${result.errorCount} abateri.`);
    process.exitCode = 1;
    return;
  }
  console.log(`Audit on-page PASS: ${result.routes} rute indexabile, ${result.programRoutes} rute de program, titluri unice, H1/heading-uri și metadata socială valide.`);
}

if (require.main === module) main();
module.exports = { auditRoute, auditSite, duplicateTitleErrors, programIdentityIsPresent };
