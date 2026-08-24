#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ORGANIZATION_ID,
  PAGE_KINDS,
  WEBSITE_ID,
  organizationSchema,
  pageKindForPath,
  serializeJsonLd,
  websiteSchema
} = require("./schema-helpers");
const { normalizeJsonLdValue } = require("./normalize-copy-ro");
const {
  SITE,
  cleanText,
  comparableText,
  fileForRoute,
  graphNodes,
  hasType,
  loadPageHints,
  parseJsonLd,
  sitemapRoutes,
  typesOf,
  visibleFaqItems
} = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_PATH = path.join(ROOT, "reports", "structured-data-audit.json");
const EXCLUDED_DIRS = new Set([".git", ".github", ".wrangler", "dist", "node_modules", "reports"]);
const FORBIDDEN_TYPES = new Set(["AggregateRating", "Review", "GovernmentService", "BlogPosting", "NewsArticle"]);
const FORBIDDEN_PROPERTIES = new Set(["aggregateRating", "review", "reviews", "award", "awards", "employee", "employees"]);
const CONTENT_TYPES = new Set(["Article", "Service", "WebApplication"]);

function bucharestIsoDate(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Bucharest",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(date);
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

const AUDIT_TODAY = process.env.STRUCTURED_DATA_AUDIT_TODAY || bucharestIsoDate();
const TODAY = new Date(`${AUDIT_TODAY}T23:59:59Z`);

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function walkHtmlFiles(root) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && EXCLUDED_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) files.push(full);
    }
  }
  walk(root);
  return files.sort((left, right) => toPosix(left).localeCompare(toPosix(right)));
}

function collectTypes(nodes) {
  const counts = {};
  function visit(value) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) return value.forEach(visit);
    for (const type of typesOf(value)) counts[type] = (counts[type] || 0) + 1;
    for (const child of Object.values(value)) visit(child);
  }
  nodes.forEach(visit);
  return counts;
}

function collectLanguageIssues(value, pathLabel = "$", key = "") {
  const issues = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => issues.push(...collectLanguageIssues(item, `${pathLabel}[${index}]`, key)));
    return issues;
  }
  if (!value || typeof value !== "object") {
    if (typeof value !== "string") return issues;
    const normalized = normalizeJsonLdValue(value, key);
    if (normalized !== value) issues.push(`${pathLabel}: '${cleanText(value)}' -> '${cleanText(normalized)}'`);
    if (key !== "url" && key !== "@id" && key !== "item" && /\b(?:Atelier de Consultanta|Romania|Romanian)\b/u.test(value)) {
      issues.push(`${pathLabel}: variantă lingvistică necanonică '${cleanText(value)}'`);
    }
    return issues;
  }
  for (const [childKey, child] of Object.entries(value)) {
    issues.push(...collectLanguageIssues(child, `${pathLabel}.${childKey}`, childKey));
  }
  return issues;
}

function collectDateIssues(nodes) {
  const issues = [];
  function visit(value, pathLabel) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) return value.forEach((item, index) => visit(item, `${pathLabel}[${index}]`));
    for (const [key, child] of Object.entries(value)) {
      if (/^date(?:Published|Modified|Created)$/iu.test(key)) {
        const date = String(child || "");
        if (!/^\d{4}-\d{2}-\d{2}(?:T.*)?$/u.test(date)) issues.push(`${pathLabel}.${key}: dată invalidă '${date}'`);
        else if (new Date(`${date.slice(0, 10)}T12:00:00Z`) > TODAY) issues.push(`${pathLabel}.${key}: dată viitoare '${date}'`);
      }
      if (child && typeof child === "object") visit(child, `${pathLabel}.${key}`);
    }
  }
  nodes.forEach((node, index) => visit(node, `$[${index}]`));
  return issues;
}

function collectForbiddenPropertyIssues(value, pathLabel = "$") {
  const issues = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => issues.push(...collectForbiddenPropertyIssues(item, `${pathLabel}[${index}]`)));
    return issues;
  }
  if (!value || typeof value !== "object") return issues;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_PROPERTIES.has(key)) issues.push(`${pathLabel}.${key}: proprietate neverificabilă/nepermisă`);
    issues.push(...collectForbiddenPropertyIssues(child, `${pathLabel}.${key}`));
  }
  return issues;
}

function validateArticleAttribution($, nodes, issues) {
  for (const article of nodes.filter((node) => hasType(node, "Article"))) {
    for (const [property, label] of [["author", "autor"], ["reviewedBy", "reviewer"]]) {
      const value = article[property];
      if (!value) continue;
      if (!hasType(value, "Person") || !cleanText(value.name) || !/^https:\/\//iu.test(String(value.url || ""))) {
        issues.push(`Article.${property}: ${label}ul trebuie să fie un profil Person real, nominal și vizibil`);
        continue;
      }
      const visible = $(`a[href='${value.url}']`).filter((_, element) => comparableText($(element).text()).includes(comparableText(value.name)));
      if (!visible.length) issues.push(`Article.${property}: profilul ${value.name} nu este vizibil în pagină`);
    }
  }
}

function validateWebApplication($, nodes, route, canonical, issues) {
  const applications = nodes.filter((node) => hasType(node, "WebApplication"));
  if (route !== "/calculator-soc" && applications.length) issues.push("WebApplication este permis numai pentru /calculator-soc");
  if (route !== "/calculator-soc") return;
  if (applications.length !== 1) {
    issues.push(`Calculator SO: WebApplication găsite ${applications.length}, necesar exact 1`);
    return;
  }
  const application = applications[0];
  if (application.url !== canonical) issues.push(`WebApplication.url diferă de canonical: ${application.url}`);
  if (application.name !== cleanText($("h1").first().text())) issues.push("WebApplication.name diferă de H1-ul vizibil");
  if (application.description !== cleanText($("meta[name='description']").attr("content"))) issues.push("WebApplication.description diferă de meta description");
  if (application.applicationCategory !== "BusinessApplication") issues.push("WebApplication.applicationCategory trebuie să descrie prudent un instrument business");
  if (application.operatingSystem !== "Web") issues.push("WebApplication.operatingSystem trebuie să fie Web");
  if (application.offers || application.aggregateRating || application.review) issues.push("WebApplication conține ofertă/rating/review neverificabil");
}

function brandedOrganization(node) {
  if (!hasType(node, "Organization")) return false;
  if (node["@id"] === ORGANIZATION_ID) return true;
  return comparableText(node.name || "").includes("atelier de consultanta") || comparableText(node.name || "") === "faber";
}

function validateEntity(nodes, route, issues) {
  const organizations = nodes.filter((node) => node?.["@id"] === ORGANIZATION_ID);
  if (organizations.length !== 1) issues.push(`Entitate FABER: găsite ${organizations.length}, necesar exact 1`);
  else {
    if (!hasType(organizations[0], "Organization") || !hasType(organizations[0], "ProfessionalService")) {
      issues.push("Entitatea FABER trebuie să combine Organization și ProfessionalService");
    }
    if (serializeJsonLd(organizations[0]) !== serializeJsonLd(organizationSchema())) issues.push("Entitatea FABER diferă de sursa juridică aprobată");
  }

  const competingEntities = nodes.filter((node) => {
    return (hasType(node, "Organization") || hasType(node, "ProfessionalService")) && node?.["@id"] !== ORGANIZATION_ID;
  });
  if (competingEntities.length) issues.push(`entități FABER concurente: ${competingEntities.map((node) => node["@id"] || node.name || "fără @id").join(", ")}`);

  const websites = nodes.filter((node) => hasType(node, "WebSite") || node["@id"] === WEBSITE_ID);
  if (websites.length !== 1) issues.push(`WebSite: găsite ${websites.length}, necesar exact 1`);
  else if (serializeJsonLd(websites[0]) !== serializeJsonLd(websiteSchema())) issues.push("WebSite diferă de sursa canonică");

  void route;
}

function validateFaq($, nodes, issues) {
  const visible = visibleFaqItems($);
  const faqNodes = nodes.filter((node) => hasType(node, "FAQPage"));
  if (faqNodes.length > 1) issues.push(`FAQPage duplicat: ${faqNodes.length}`);
  if (visible.length >= 2 && faqNodes.length !== 1) issues.push(`FAQ vizibil cu ${visible.length} întrebări, dar FAQPage găsite: ${faqNodes.length}`);
  if (visible.length < 2 && faqNodes.length) issues.push("FAQPage fără minimum două întrebări FAQ vizibile reale");
  const visibleSeen = new Set();
  for (const item of visible) {
    const key = comparableText(item.question);
    if (visibleSeen.has(key)) issues.push(`FAQ vizibil duplicat: '${item.question}'`);
    visibleSeen.add(key);
  }
  for (const faq of faqNodes) {
    const entities = Array.isArray(faq.mainEntity) ? faq.mainEntity : [];
    if (!entities.length) issues.push("FAQPage fără întrebări");
    if (entities.length !== visible.length) issues.push(`FAQPage are ${entities.length} întrebări, HTML are ${visible.length}`);
    const seen = new Set();
    for (const [index, entity] of entities.entries()) {
      const question = cleanText(entity.name || entity.question);
      const answer = cleanText(entity.acceptedAnswer?.text || entity.answer);
      const key = comparableText(question);
      if (!key || !answer) issues.push(`FAQ incomplet: '${question || "întrebare goală"}'`);
      if (seen.has(key)) issues.push(`FAQ duplicat: '${question}'`);
      seen.add(key);
      if (!visible[index]) issues.push(`FAQ fără întrebare vizibilă: '${question}'`);
      else if (key !== comparableText(visible[index].question)) issues.push(`FAQ în altă ordine sau cu întrebare diferită la poziția ${index + 1}`);
      else if (comparableText(visible[index].answer) !== comparableText(answer)) issues.push(`FAQ cu răspuns diferit de cel vizibil: '${question}'`);
    }
  }
}

function validateBreadcrumb(nodes, route, canonical, issues) {
  const breadcrumbs = nodes.filter((node) => hasType(node, "BreadcrumbList"));
  if (route === "/") {
    if (breadcrumbs.length) issues.push(`homepage publică ${breadcrumbs.length} BreadcrumbList fără echivalent vizibil; necesar 0`);
    return;
  }
  if (breadcrumbs.length !== 1) {
    issues.push(`BreadcrumbList: găsite ${breadcrumbs.length}, necesar exact 1`);
    return;
  }
  const items = breadcrumbs[0].itemListElement || [];
  const expectedLength = [2, 3, 4];
  if (!expectedLength.includes(items.length)) issues.push(`breadcrumb are ${items.length} niveluri, necesar 2–4`);
  items.forEach((item, index) => {
    if (item.position !== index + 1) issues.push(`breadcrumb poziție invalidă la nivelul ${index + 1}`);
    if (!cleanText(item.name)) issues.push(`breadcrumb fără nume la nivelul ${index + 1}`);
    try {
      const target = new URL(item.item);
      if (target.origin !== SITE || target.hash || target.search || target.pathname.endsWith(".html")) {
        issues.push(`breadcrumb necanonic la nivelul ${index + 1}: ${item.item}`);
      }
    } catch {
      issues.push(`breadcrumb URL invalid la nivelul ${index + 1}: ${item.item}`);
    }
  });
  if (items.length && items.at(-1).item !== canonical) issues.push(`ultima destinație breadcrumb nu este canonicalul paginii: ${items.at(-1).item}`);
}

function validateTypes(nodes, route, hints, issues) {
  const pageNodes = nodes.filter((node) => hasType(node, "WebPage"));
  if (pageNodes.length !== 1) issues.push(`WebPage: găsite ${pageNodes.length}, necesar exact 1`);
  const content = nodes.filter((node) => typesOf(node).some((type) => CONTENT_TYPES.has(type)));
  if (content.length > 1) issues.push(`tipuri de conținut simultane: ${content.map((node) => typesOf(node).join("+")).join(", ")}`);
  for (const node of nodes) {
    for (const type of typesOf(node)) if (FORBIDDEN_TYPES.has(type)) issues.push(`tip schema nepermis sau nejustificat: ${type}`);
  }

  const expected = pageKindForPath(route, hints || {});
  if (expected === PAGE_KINDS.WEB_APPLICATION && !content.some((node) => hasType(node, "WebApplication"))) issues.push("calculatorul trebuie să aibă WebApplication");
  if (expected === PAGE_KINDS.SERVICE && !content.some((node) => hasType(node, "Service"))) issues.push("pagina de serviciu trebuie să aibă Service");
  if (expected === PAGE_KINDS.ARTICLE && !content.some((node) => hasType(node, "Article"))) issues.push("pagina editorială trebuie să aibă Article");
  if (expected === PAGE_KINDS.WEB_PAGE && content.some((node) => hasType(node, "WebApplication"))) issues.push("WebApplication nejustificat pe pagină generală");
}

function auditIndexable(route, file, hints) {
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const blocks = parseJsonLd($);
  const relative = toPosix(path.relative(ROOT, file));
  const issues = [];
  if (!blocks.length) issues.push("lipsește JSON-LD");
  blocks.filter((block) => block.error).forEach((block) => issues.push(`JSON-LD invalid în blocul ${block.index + 1}: ${block.error}`));
  if (blocks.length !== 1) issues.push(`blocuri JSON-LD: ${blocks.length}, necesar exact 1 determinist`);
  const nodes = blocks.flatMap((block) => block.nodes);
  const canonical = `${SITE}${route}`;
  if ($("link[rel='canonical']").first().attr("href") !== canonical) issues.push(`canonical diferit de rută: ${$("link[rel='canonical']").first().attr("href")}`);
  validateEntity(nodes, route, issues);
  validateFaq($, nodes, issues);
  validateBreadcrumb(nodes, route, canonical, issues);
  validateTypes(nodes, route, hints, issues);
  validateArticleAttribution($, nodes, issues);
  validateWebApplication($, nodes, route, canonical, issues);
  issues.push(...collectDateIssues(nodes));
  issues.push(...nodes.flatMap((node, index) => collectForbiddenPropertyIssues(node, `$[${index}]`)));
  issues.push(...nodes.flatMap((node, index) => collectLanguageIssues(node, `$[${index}]`)).slice(0, 20));

  const modified = nodes.map((node) => node.dateModified).filter(Boolean);
  if (hints?.updatedAt) {
    if (!modified.length) issues.push(`lipsește dateModified din lastMeaningfulUpdate ${hints.updatedAt}`);
    if (modified.some((date) => date !== hints.updatedAt)) {
      issues.push(`dateModified nu corespunde lastMeaningfulUpdate ${hints.updatedAt}: ${[...new Set(modified)].join(", ")}`);
    }
    const expectedSource = hints.citation?.[0]?.url;
    const editorialNodes = nodes.filter((node) => hasType(node, "WebPage") || hasType(node, "Article"));
    for (const node of editorialNodes) {
      if (!Array.isArray(node.citation) || !node.citation.some((citation) => citation.url === expectedSource)) {
        issues.push(`${typesOf(node).join("+")}: sursa oficială nu este sincronizată cu registrul editorial`);
      }
    }
  } else if (modified.length) {
    issues.push(`dateModified publicat fără lastMeaningfulUpdate verificat: ${[...new Set(modified)].join(", ")}`);
  }
  return { file: relative, route, blocks: blocks.length, types: collectTypes(nodes), modified, issues };
}

function validateAllJsonLd(files) {
  const issues = [];
  for (const file of files) {
    const relative = toPosix(path.relative(ROOT, file));
    const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
    for (const block of parseJsonLd($)) if (block.error) issues.push({ file: relative, issue: `JSON-LD invalid în blocul ${block.index + 1}: ${block.error}` });
  }
  return issues;
}

function validateReviewedSources() {
  const issues = [];
  for (const relative of ["config/seo-programs.json", "config/seo-programmatic-pages.json", "config/priority-pages.json", "config/editorial-pages.json"]) {
    const data = JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8"));
    if (!/^\d{4}-\d{2}-\d{2}$/u.test(data.lastReviewed || "")) issues.push({ file: relative, issue: "lipsește lastReviewed în sursa generată" });
  }
  return issues;
}

function main() {
  const files = walkHtmlFiles(ROOT);
  const routes = sitemapRoutes(ROOT);
  const hints = loadPageHints(ROOT);
  const results = routes.map((route) => auditIndexable(route, fileForRoute(ROOT, route), hints.get(route)));
  const globalIssues = [...validateAllJsonLd(files), ...validateReviewedSources()];

  const modifiedToday = results.filter((result) => result.modified.includes(AUDIT_TODAY)).length;
  if (modifiedToday >= Math.ceil(results.length * 0.8)) {
    globalIssues.push({ file: "sitemap.xml", issue: `${modifiedToday}/${results.length} pagini folosesc data auditului ca dateModified; posibilă dată de build` });
  }

  const typeCounts = {};
  for (const result of results) for (const [type, count] of Object.entries(result.types)) typeCounts[type] = (typeCounts[type] || 0) + count;
  const filesWithIssues = results.filter((result) => result.issues.length).length + globalIssues.length;
  const report = {
    generatedAt: new Date().toISOString(),
    summary: {
      htmlFilesChecked: files.length,
      indexablePagesChecked: results.length,
      filesWithIssues,
      organizationVariants: new Set(results.map((result) => {
        const file = fileForRoute(ROOT, result.route);
        const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
        const org = parseJsonLd($).flatMap((block) => block.nodes).find(brandedOrganization);
        return org ? serializeJsonLd(org) : "missing";
      })).size,
      types: typeCounts
    },
    globalIssues,
    results
  };
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log(`Structured data report written to ${toPosix(path.relative(ROOT, REPORT_PATH))}`);
  console.log(`HTML: ${files.length}; indexabile: ${results.length}; cu probleme: ${filesWithIssues}; variante Organization: ${report.summary.organizationVariants}`);
  console.log(`Tipuri: ${Object.entries(typeCounts).map(([type, count]) => `${type}:${count}`).join(", ")}`);
  const failures = [...globalIssues.map((entry) => ({ file: entry.file, issues: [entry.issue] })), ...results.filter((result) => result.issues.length)];
  for (const failure of failures.slice(0, 15)) {
    console.log(`- ${failure.file}`);
    for (const issue of failure.issues.slice(0, 8)) console.log(`  * ${issue}`);
    if (failure.issues.length > 8) console.log(`  * ... încă ${failure.issues.length - 8}`);
  }
  if (failures.length) process.exitCode = 1;
}

if (require.main === module) main();
