#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { auditSiteLinks, parseRedirects, redirectDestination } = require("./audit-site-links");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");
const { loadConfig, resolvedLinks } = require("./sync-program-contextual-links");
const { backlinkGroups } = require("./sync-topic-cluster-backlinks");
const { SITE, fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const DEFAULT_ROOT = path.resolve(__dirname, "..");
const SITE_HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const MANAGED_RELATIONS = new Set(["parent", "related", "service", "instrument", "guide", "conversion"]);
const HOMEPAGE_CORE_ROUTES = [
  "/fonduri-europene",
  "/afir",
  "/fonduri-regionale",
  "/fonduri-europene-digitalizare",
  "/finantari-panouri-fotovoltaice",
  "/fonduri-europene-imm",
  "/verificare-eligibilitate-fonduri-europene",
  "/calculator-soc",
  "/metodologie-verificare-eligibilitate",
  "/contact"
];

function canonicalPath(pathname) {
  if (!pathname || pathname === "/") return "/";
  return pathname.replace(/\/+$/u, "") || "/";
}

function internalAnchorTarget(rawHref, sourceRoute) {
  const href = String(rawHref || "").trim();
  if (!href || href.startsWith("#")) return null;
  if (/^(?:mailto|tel|sms|javascript|data|blob):/iu.test(href)) return null;
  try {
    const url = new URL(href, `${SITE}${sourceRoute}`);
    if (!/^https?:$/iu.test(url.protocol) || !SITE_HOSTS.has(url.hostname)) return null;
    return { href, pathname: url.pathname || "/", route: canonicalPath(url.pathname), hash: url.hash };
  } catch {
    return null;
  }
}

function pageData(root, route) {
  const file = fileForRoute(root, route);
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const anchors = $("a[href]").toArray().map((element) => ({
    href: $(element).attr("href") || "",
    text: $(element).text().replace(/\s+/gu, " ").trim(),
    relation: $(element).attr("data-link-relation") || "",
    programId: $(element).attr("data-target-program-id") || ""
  }));
  return { route, file, html, $, anchors };
}

function directRoutes(page) {
  return new Set(page.anchors
    .map((anchor) => internalAnchorTarget(anchor.href, page.route))
    .filter(Boolean)
    .map((target) => target.route));
}

function legacyReason(target, redirects) {
  if (/\/index\.html$/iu.test(target.pathname)) return "URL /index.html";
  if (/\.html$/iu.test(target.pathname)) return "URL .html";
  const redirect = redirects.find((rule) => rule.status >= 300
    && rule.status < 400
    && redirectDestination(rule, target.pathname));
  return redirect ? `redirect _redirects:${redirect.line}` : "";
}

function relationCounts(programs, config) {
  const counts = Object.fromEntries([...MANAGED_RELATIONS].map((relation) => [relation, 0]));
  for (const program of programs) {
    for (const link of resolvedLinks(program, config, programs)) counts[link.relation] += 1;
  }
  return counts;
}

function auditInternalLinkGraph(options = {}) {
  const root = path.resolve(options.root || DEFAULT_ROOT);
  const routes = sitemapRoutes(root);
  const sitemapSet = new Set(routes);
  const redirects = parseRedirects(root);
  const pages = new Map(routes.map((route) => [route, pageData(root, route)]));
  const incoming = new Map(routes.map((route) => [route, new Set()]));
  const outgoing = new Map(routes.map((route) => [route, new Set()]));
  const legacyLinks = [];
  const nonCanonicalLinks = [];
  const canonicalIssues = [];

  for (const [sourceRoute, page] of pages) {
    const canonical = page.$("link[rel='canonical']").first().attr("href") || "";
    if (canonical !== `${SITE}${sourceRoute}`) canonicalIssues.push({ route: sourceRoute, canonical });
    if (/noindex/iu.test(page.$("meta[name='robots']").attr("content") || "")) {
      canonicalIssues.push({ route: sourceRoute, canonical, reason: "rută sitemap marcată noindex" });
    }
    for (const anchor of page.anchors) {
      const target = internalAnchorTarget(anchor.href, sourceRoute);
      if (!target) continue;
      const reason = legacyReason(target, redirects);
      if (reason) legacyLinks.push({ source: sourceRoute, href: anchor.href, reason });
      if (!sitemapSet.has(target.route)) continue;
      if (reason || target.pathname !== target.route) {
        nonCanonicalLinks.push({ source: sourceRoute, href: anchor.href, target: target.route, reason: reason || "trailing slash" });
        continue;
      }
      outgoing.get(sourceRoute).add(target.route);
      if (sourceRoute !== target.route) incoming.get(target.route).add(sourceRoute);
    }
  }

  const zeroIncoming = routes
    .filter((route) => route !== "/" && incoming.get(route).size === 0)
    .map((route) => ({ route, outgoing: outgoing.get(route).size }));

  const config = loadConfig();
  const programRegistry = loadProgramConfig();
  const programs = programRegistry.programs
    .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
  const programRoutes = new Set(programs.map((program) => program.pageUrl));
  const programIssues = [];
  const duplicateRelatedLinks = [];

  for (const program of programs) {
    const page = pages.get(program.pageUrl);
    if (!page) {
      programIssues.push(`${program.pageUrl}: ruta programului lipsește din sitemap`);
      continue;
    }
    const block = page.$("main [data-program-contextual-links]");
    const actual = block.find("a[data-link-relation]").toArray().map((element) => ({
      relation: page.$(element).attr("data-link-relation") || "",
      href: page.$(element).attr("href") || "",
      programId: page.$(element).attr("data-target-program-id") || ""
    }));
    const expected = resolvedLinks(program, config, programs);
    if (block.length !== 1) programIssues.push(`${program.pageUrl}: ${block.length} blocuri program, necesar 1`);
    if (actual.length !== expected.length) programIssues.push(`${program.pageUrl}: ${actual.length} relații, necesar ${expected.length}`);
    expected.forEach((link, index) => {
      const current = actual[index];
      if (!current || current.relation !== link.relation || current.href !== link.href) {
        programIssues.push(`${program.pageUrl}: relația ${index + 1} nu corespunde registrului`);
      }
      if (link.programId && current?.programId !== link.programId) {
        programIssues.push(`${program.pageUrl}: programul asociat ${link.programId} nu este identificat semantic`);
      }
    });
    const targets = actual.map((link) => link.href);
    if (new Set(targets).size !== targets.length) programIssues.push(`${program.pageUrl}: destinații duplicate în bloc`);
    const related = actual.filter((link) => link.relation === "related");
    const relatedTargets = related.map((link) => link.href);
    if (new Set(relatedTargets).size !== relatedTargets.length) {
      duplicateRelatedLinks.push({ route: program.pageUrl, targets: relatedTargets });
    }
    const availableRelated = programs.filter((candidate) => candidate.id !== program.id
      && candidate.pageUrl !== program.discovery?.parentHub
      && candidate.discovery?.parentHub === program.discovery?.parentHub).length;
    if (related.length !== Math.min(4, availableRelated) || (availableRelated >= 2 && related.length < 2)) {
      programIssues.push(`${program.pageUrl}: ${related.length} programe asociate pentru ${availableRelated} relații reale disponibile`);
    }
    for (const relation of ["parent", "service", "instrument", "guide", "conversion"]) {
      if (actual.filter((link) => link.relation === relation).length !== 1) {
        programIssues.push(`${program.pageUrl}: relația ${relation} nu este unică`);
      }
    }
  }

  const familyConfig = JSON.parse(fs.readFileSync(path.join(root, "config", "program-family-hubs.json"), "utf8"));
  const familyIssues = [];
  for (const hub of familyConfig.hubs || []) {
    const page = pages.get(hub.route);
    if (!page) {
      familyIssues.push(`${hub.route}: hub absent din sitemap`);
      continue;
    }
    const targets = directRoutes(page);
    const members = programs.filter((program) => program.discovery?.parentHub === hub.route && program.pageUrl !== hub.route);
    for (const program of members) {
      if (!targets.has(program.pageUrl)) familyIssues.push(`${hub.route}: nu trimite direct la ${program.pageUrl}`);
    }
  }

  const groups = backlinkGroups(programs, config);
  const clusterIssues = [];
  const clusterCoverage = [];
  for (const [route, group] of groups) {
    if (programRoutes.has(route)) continue;
    const page = pages.get(route);
    if (!page) {
      clusterIssues.push(`${route}: destinația derivată lipsește din sitemap`);
      continue;
    }
    const targets = directRoutes(page);
    const associated = [...group.programs.values()].filter((program) => targets.has(program.pageUrl));
    clusterCoverage.push({ route, relations: [...group.relations].sort(), associatedPrograms: associated.map((program) => program.id) });
    if (!associated.length) clusterIssues.push(`${route}: nu trimite înapoi la niciun program asociat`);
    const managed = page.$("main [data-topic-cluster-backlinks]");
    if (managed.length > 1) clusterIssues.push(`${route}: ${managed.length} blocuri backlink gestionate`);
    if (managed.length) {
      const hrefs = managed.find("a[href]").toArray().map((element) => page.$(element).attr("href") || "");
      if (hrefs.length > 4) clusterIssues.push(`${route}: blocul gestionat depășește 4 linkuri`);
      if (new Set(hrefs).size !== hrefs.length) clusterIssues.push(`${route}: destinații duplicate în blocul gestionat`);
      for (const href of hrefs) {
        if (!programRoutes.has(href)) clusterIssues.push(`${route}: backlink necanonic sau non-program ${href}`);
      }
    }
  }

  const serviceRoutes = (programRegistry.config.pages || [])
    .filter((page) => page.type === "service" && !page.redirectTo)
    .map((page) => `/${String(page.slug).replace(/^\/+|\/+$/gu, "")}`);
  const derivedClusterRoutes = new Set(groups.keys());
  const uncoveredServices = serviceRoutes.filter((route) => !derivedClusterRoutes.has(route));
  for (const route of uncoveredServices) clusterIssues.push(`${route}: serviciu fără relație derivată către programe`);

  const homepageTargets = directRoutes(pages.get("/"));
  const missingHomepageCore = HOMEPAGE_CORE_ROUTES.filter((route) => !homepageTargets.has(route));
  const siteAudit = auditSiteLinks({ root });
  const errors = [
    ...canonicalIssues.map((issue) => `${issue.route}: ${issue.reason || `canonical ${issue.canonical || "lipsește"}`}`),
    ...legacyLinks.map((issue) => `${issue.source}: ${issue.href} (${issue.reason})`),
    ...zeroIncoming.map((issue) => `${issue.route}: zero incoming links`),
    ...programIssues,
    ...duplicateRelatedLinks.map((issue) => `${issue.route}: related links duplicate`),
    ...familyIssues,
    ...clusterIssues,
    ...missingHomepageCore.map((route) => `/: lipsește legătura către entitatea centrală ${route}`),
    ...siteAudit.issues.map((issue) => `${issue.sourceFile || "_redirects"}: ${issue.type} ${issue.value || issue.from || ""}`)
  ];

  return {
    generatedFor: "Task 19",
    root,
    summary: {
      canonicalPages: routes.length,
      canonicalEdges: [...outgoing.values()].reduce((sum, targets) => sum + targets.size, 0),
      zeroIncoming: zeroIncoming.length,
      legacyLinks: legacyLinks.length,
      nonCanonicalLinks: nonCanonicalLinks.length,
      programPages: programs.length,
      familyHubs: (familyConfig.hubs || []).length,
      derivedClusterTargets: groups.size,
      reciprocalClusterTargets: clusterCoverage.length,
      services: serviceRoutes.length,
      uncoveredServices: uncoveredServices.length,
      homepageCoreEntities: HOMEPAGE_CORE_ROUTES.length,
      brokenOrRedirectedLinks: siteAudit.issues.length,
      relationCounts: relationCounts(programs, config),
      errors: [...new Set(errors)].length
    },
    zeroIncoming,
    legacyLinks,
    nonCanonicalLinks,
    duplicateRelatedLinks,
    canonicalIssues,
    familyIssues,
    clusterIssues,
    clusterCoverage,
    serviceRoutes,
    uncoveredServices,
    missingHomepageCore,
    siteLinkIssues: siteAudit.issues,
    errors: [...new Set(errors)]
  };
}

function printReport(report) {
  const status = report.errors.length ? "FAIL" : "PASS";
  console.log(`Internal link graph ${status}: ${report.summary.canonicalPages} pagini canonice, ${report.summary.canonicalEdges} muchii distincte.`);
  console.log(`Programe: ${report.summary.programPages}; familii: ${report.summary.familyHubs}; servicii: ${report.summary.services}; destinații cluster: ${report.summary.derivedClusterTargets}.`);
  console.log(`Orfani: ${report.summary.zeroIncoming}; URL-uri legacy: ${report.summary.legacyLinks}; linkuri rupte/redirectate: ${report.summary.brokenOrRedirectedLinks}; erori: ${report.summary.errors}.`);
  if (report.errors.length) console.error(report.errors.slice(0, 80).map((error) => `- ${error}`).join("\n"));
}

function main() {
  const rootArgument = process.argv.find((argument) => argument.startsWith("--root="));
  const report = auditInternalLinkGraph({ root: rootArgument ? rootArgument.slice("--root=".length) : DEFAULT_ROOT });
  printReport(report);
  if (report.errors.length) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { HOMEPAGE_CORE_ROUTES, auditInternalLinkGraph, internalAnchorTarget, printReport };
