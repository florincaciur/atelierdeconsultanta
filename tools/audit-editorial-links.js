#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const cheerio = require("cheerio");
const { SITE, fileForRoute, sitemapRoutes, parseJsonLd } = require("./structured-data-utils");
const { parseRedirects, redirectDestination } = require("./audit-site-links");
const { isPublicProgram, loadProgramConfig } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const GLOBAL = "#navbar, #mobileMenu, [data-navigation-config]";
const BREADCRUMB = "[data-breadcrumb], .breadcrumb";
const HIDDEN = "[hidden], [inert], [aria-hidden='true']";
const BUTTON = ".btn, .program-button, [role='button'], [data-analytics-event='cta_click']";
const clean = value => String(value || "").replace(/\s+/gu, " ").trim();

function loadPages(root, read = file => fs.readFileSync(file, "utf8")) {
  return new Map(sitemapRoutes(root).map(route => {
    const file = fileForRoute(root, route);
    return [route, cheerio.load(read(file, route))];
  }));
}

function classifyTarget(href, source, pages, redirects) {
  let url;
  try { url = new URL(href, `${SITE}${source}`); } catch { return null; }
  if (!/^https?:$/u.test(url.protocol) || !["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"].includes(url.hostname)) return null;
  const route = url.pathname;
  const redirected = redirects.find(rule => rule.status >= 300 && rule.status < 400 && redirectDestination(rule, route));
  if (redirected) return { issue: "redirect", target: redirectDestination(redirected, route) };
  if (route !== "/" && (route.endsWith("/") || /\.html$/iu.test(route))) return { issue: "historic_path", target: route };
  if (!pages.has(route)) return null; // Assets and download endpoints are checked by audit-site-links.
  if (url.origin !== SITE) return { issue: "host_or_protocol", target: route };
  if (pages.get(route)("head link[rel=canonical]").attr("href") !== `${SITE}${route}`) return { issue: "canonical", target: route };
  return { route, fragment: url.hash };
}

function inspectGraph({ root = ROOT, pages = loadPages(root) } = {}) {
  const redirects = parseRedirects(root);
  const edges = new Map();
  const pagesByRoute = new Map([...pages.keys()].map(route => [route, { route, mainSources: [], paragraphSources: [], menuSources: [] }]));
  const rejected = [];
  const breadcrumbIssues = [];
  for (const [route, $] of pages) {
    const nav = $(BREADCRUMB);
    const crumbs = parseJsonLd($).flatMap(block => block.nodes).filter(node => [node["@type"]].flat().includes("BreadcrumbList"));
    if (route !== "/") {
      const links = nav.find("a[href]").map((_, el) => $(el).attr("href")).get();
      const current = nav.find('[aria-current="page"]');
      const schema = crumbs[0]?.itemListElement || [];
      const parents = links.map(href => classifyTarget(href, route, pages, redirects));
      const expectedUrls = [...parents.map(parent => parent?.route && SITE + parent.route), SITE + route];
      if (nav.length !== 1 || current.length !== 1 || crumbs.length !== 1 || parents.some(parent => !parent?.route)
        || new Set(expectedUrls).size !== expectedUrls.length
        || JSON.stringify(schema.map(item => item.item)) !== JSON.stringify(expectedUrls)
        || schema.some((item, index) => item.position !== index + 1)) breadcrumbIssues.push(route);
    } else if (nav.length || crumbs.length) breadcrumbIssues.push(route);

    $("a[href]").each((_, node) => {
      const anchor = $(node);
      const href = anchor.attr("href");
      const inMenu = anchor.closest(GLOBAL).length > 0;
      const inMain = anchor.closest("main").length > 0 && !anchor.closest(`${BREADCRUMB}, ${HIDDEN}`).length;
      if (!inMenu && !inMain) return;
      const target = classifyTarget(href, route, pages, redirects);
      if (!target) return;
      if (target.issue) { rejected.push({ source: route, href, ...target }); return; }
      if (target.route === route) return;
      const key = `${route}\n${target.route}`;
      if (!edges.has(key)) edges.set(key, { source: route, target: target.route, main: 0, paragraph: 0, globalMenu: 0 });
      const edge = edges.get(key);
      if (inMenu) edge.globalMenu++;
      else if (inMain) {
        edge.main++;
        if (anchor.closest("p").length && !anchor.closest("nav").length && !anchor.is(BUTTON)) edge.paragraph++;
      }
    });
  }
  for (const edge of edges.values()) {
    const node = pagesByRoute.get(edge.target);
    if (edge.main) node.mainSources.push(edge.source);
    if (edge.paragraph) node.paragraphSources.push(edge.source);
    if (edge.globalMenu) node.menuSources.push(edge.source);
  }
  const rows = [...pagesByRoute.values()].map(row => ({ ...row,
    mainSources: row.mainSources.sort(), paragraphSources: row.paragraphSources.sort(), menuSources: row.menuSources.sort()
  }));
  const connections = [...edges.values()];
  const hasMainEdge = (source, target) => Boolean(edges.get(`${source}\n${target}`)?.main);
  const programPaths = loadProgramConfig().programs.filter(program => isPublicProgram(program) && !program.discovery?.redirectTarget).map(program => {
    const route = program.pageUrl;
    const $ = pages.get(route);
    const guide = $("main a[data-link-relation=guide]").attr("href");
    const service = $("main a[data-link-relation=service]").attr("href");
    const contact = $("main a[data-link-relation=conversion]").attr("href");
    const context = new URLSearchParams(contact?.split("#")[1]);
    return {
      route, guide, service, contact,
      programToGuide: hasMainEdge(route, guide),
      programToService: hasMainEdge(route, service),
      guideToService: hasMainEdge(guide, service),
      serviceToContact: hasMainEdge(service, "/contact"),
      attributedContact: contact?.startsWith("/contact#") && context.get("source_page") === route && Boolean(context.get("program_slug"))
    };
  });
  return { summary: { routes: rows.length,
    mainLinks: connections.reduce((sum, edge) => sum + edge.main, 0), mainEdges: connections.filter(edge => edge.main).length,
    paragraphLinks: connections.reduce((sum, edge) => sum + edge.paragraph, 0), paragraphEdges: connections.filter(edge => edge.paragraph).length,
    globalMenuLinks: connections.reduce((sum, edge) => sum + edge.globalMenu, 0), globalMenuEdges: connections.filter(edge => edge.globalMenu).length,
    weakMain: rows.filter(row => row.mainSources.length < 2).length, zeroMain: rows.filter(row => !row.mainSources.length).length,
    weakParagraph: rows.filter(row => row.paragraphSources.length < 2).length,
    rejected: rejected.length, breadcrumbIssues: breadcrumbIssues.length,
    programPaths: programPaths.length,
    completeProgramPaths: programPaths.filter(row => row.programToGuide && row.programToService && row.guideToService && row.serviceToContact && row.attributedContact).length
  }, rows, edges: connections, programPaths, rejected, breadcrumbIssues };
}

if (require.main === module) {
  const report = inspectGraph();
  const output = process.argv.find(arg => arg.startsWith("--output="))?.slice("--output=".length);
  if (output) fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report.summary));
  for (const row of report.rows.filter(row => row.mainSources.length < 2)) console.log(`${row.route}\t${row.mainSources.length}\t${row.mainSources.join(", ")}`);
  if (process.argv.includes("--check") && (report.summary.weakMain || report.summary.completeProgramPaths !== report.summary.programPaths)) {
    console.error("Unele canonice au mai puțin de două surse sau traseul unui program este incomplet.");
    process.exitCode = 1;
  }
  if (report.rejected.length || report.breadcrumbIssues.length) {
    console.error(JSON.stringify({ rejected: report.rejected.slice(0, 20), breadcrumbIssues: report.breadcrumbIssues }));
    process.exitCode = 1;
  }
}

module.exports = { inspectGraph, loadPages, classifyTarget, clean };
