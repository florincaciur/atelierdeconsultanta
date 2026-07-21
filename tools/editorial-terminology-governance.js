"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { collectSiteState } = require("./generate-sitemap");

const ROOT = path.resolve(__dirname, "..");
const POLICY_PATH = path.join(ROOT, "config", "editorial-terminology.json");
const PROGRAMS_PATH = path.join(ROOT, "config", "seo-programs.json");
const POLICY = JSON.parse(fs.readFileSync(POLICY_PATH, "utf8"));
const PROGRAM_CONFIG = JSON.parse(fs.readFileSync(PROGRAMS_PATH, "utf8"));
const TARGET_ROUTES = new Set(POLICY.targetRoutes);
const TARGET_PAGE_SLUGS = new Set(POLICY.targetRoutes.filter((route) => route !== "/").map((route) => route.slice(1)));
const PROTECTED_SOURCE_KEYS = new Set([
  "applicationend", "applicationstart", "canonical", "currency", "family", "factualgovernanceref",
  "href", "id", "lastmeaningfulupdate", "lastreviewed", "nextreviewat", "officialguidekey",
  "output", "pageurl", "programid", "publicationstate", "route", "slug", "sourcename", "sourceurl",
  "sourceversion", "status", "statuslabel", "target", "type", "updatedat", "url", "verifiedat"
]);

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function preserveInitial(source, replacement) {
  return /^\p{Lu}/u.test(source) ? `${replacement.charAt(0).toUpperCase()}${replacement.slice(1)}` : replacement;
}

function replacePreservingInitial(value, regex, replacement) {
  return value.replace(regex, (match) => preserveInitial(match, replacement));
}

function rewriteTerminology(value) {
  let output = String(value || "");
  const exact = [
    [/Verifică eligibilitatea fermei tale cu un consultant FABER/gu, "Cere o verificare inițială a fermei cu un consultant FABER"],
    [/Verifică eligibilitatea fermei/gu, "Cere verificarea inițială a fermei"],
    [/Verifică eligibilitatea DR14/gu, "Cere verificarea inițială pentru DR14"],
    [/Verifică eligibilitatea proiectului/gu, "Cere o verificare inițială a proiectului"],
    [/Solicită verificare eligibilitate/gu, "Solicită verificare inițială"],
    [/Verifică eligibilitatea/gu, "Cere o verificare inițială"],
    [/verificarea eligibilității/gu, "verificarea inițială a eligibilității"],
    [/Verificarea eligibilității/gu, "Verificarea inițială a eligibilității"],
    [/verificare eligibilitate/gu, "verificare inițială a eligibilității"],
    [/Verificare eligibilitate/gu, "Verificare inițială a eligibilității"]
  ];
  for (const [regex, replacement] of exact) output = output.replace(regex, replacement);

  output = replacePreservingInitial(output, /\bcofinanțării\b/giu, "contribuției proprii");
  output = replacePreservingInitial(output, /\bcofinanțarea\b/giu, "contribuția proprie");
  output = replacePreservingInitial(output, /\bcofinanțare\b/giu, "contribuție proprie");
  output = replacePreservingInitial(output, /\baportului\b/giu, "contribuției proprii");
  output = replacePreservingInitial(output, /\baportul\b/giu, "contribuția proprie");
  output = replacePreservingInitial(output, /\baport\b/giu, "contribuție proprie");

  const statePhrases = [
    [/\bghidul apelului activ\b/giu, "documentul oficial al apelului analizat"],
    [/\bghidul activ\b/giu, "documentul oficial aplicabil"],
    [/\bghid activ\b/giu, "document oficial aplicabil"],
    [/\bapelului activ\b/giu, "apelului analizat"],
    [/\bapelul activ\b/giu, "apelul analizat"],
    [/\bapeluri active\b/giu, "apeluri analizate"],
    [/\bapel activ\b/giu, "apel analizat"],
    [/\bprogramului activ\b/giu, "programului analizat"],
    [/\bprogramul activ\b/giu, "programul analizat"],
    [/\bprogram activ\b/giu, "program analizat"],
    [/\bdocumentul oficial activ\b/giu, "documentul oficial aplicabil"],
    [/\bdocument oficial activ\b/giu, "document oficial aplicabil"],
    [/\bdocumentele AFIR active\b/giu, "documentele AFIR aplicabile"],
    [/\bcriteriile active\b/giu, "criteriile aplicabile"]
  ];
  for (const [regex, replacement] of statePhrases) output = replacePreservingInitial(output, regex, replacement);
  return output;
}

function recursivelyRewrite(value, context = { path: [] }, changes = []) {
  if (typeof value === "string") {
    const key = String(context.key || "").toLowerCase();
    if (PROTECTED_SOURCE_KEYS.has(key) || /^(?:https?:|mailto:|tel:|\/)/iu.test(value.trim())) return value;
    const next = rewriteTerminology(value);
    if (next !== value) changes.push({ route: context.route, location: context.path.join("."), before: value, after: next, reason: "Lexic controlat P0.14" });
    return next;
  }
  if (Array.isArray(value)) return value.map((item, index) => recursivelyRewrite(item, { ...context, path: [...context.path, String(index)] }, changes));
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, child] of Object.entries(value)) {
    result[key] = recursivelyRewrite(child, { ...context, key, path: [...context.path, key] }, changes);
  }
  return result;
}

function migrateTargetSources({ write = false } = {}) {
  const before = fs.readFileSync(PROGRAMS_PATH, "utf8");
  const parsed = JSON.parse(before);
  const changes = [];
  parsed.pages = (parsed.pages || []).map((page, index) => {
    if (!TARGET_PAGE_SLUGS.has(page.slug)) return page;
    return recursivelyRewrite(page, { route: `/${page.slug}`, key: "", path: ["pages", String(index)] }, changes);
  });
  const after = `${JSON.stringify(parsed, null, 2)}\n`;
  if (write && after !== before) fs.writeFileSync(PROGRAMS_PATH, after, "utf8");
  return { changed: after !== before, changes, content: after };
}

function addChange(changes, route, location, before, after, reason = "Lexic controlat P0.14") {
  if (before === after) return;
  changes.push({ route, location, before: cleanText(before), after: cleanText(after), reason });
}

function rewriteJsonLd(value, route, changes, jsonPath = "$" ) {
  if (typeof value === "string") {
    if (/^(?:https?:|mailto:|tel:|\/)/iu.test(value.trim())) return value;
    const next = rewriteTerminology(value);
    addChange(changes, route, `json-ld:${jsonPath}`, value, next);
    return next;
  }
  if (Array.isArray(value)) return value.map((item, index) => rewriteJsonLd(item, route, changes, `${jsonPath}[${index}]`));
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, child] of Object.entries(value)) result[key] = rewriteJsonLd(child, route, changes, `${jsonPath}.${key}`);
  return result;
}

function applyRouteRequirements($, route, changes) {
  if (POLICY.requiredPositioningRoutes.includes(route)) {
    const selector = route === "/" ? ".hero-subtitle" : ".hero.hero--generic > p";
    const element = $(selector).first();
    if (element.length && !cleanText(element.text()).includes(POLICY.positioning)) {
      const before = element.text();
      element.text(`${POLICY.positioning} ${cleanText(before)}`);
      addChange(changes, route, "positioning", before, element.text(), "Poziționare centrală FABER");
    }
  }
  if (route === "/fonduri-europene" && $("[data-terminology-note='own-contribution']").length === 0) {
    const anchor = $("#funding-filter").closest("section");
    if (anchor.length) {
      const note = `<p data-terminology-note="own-contribution">${POLICY.contributionExplanation}</p>`;
      anchor.append(note);
      addChange(changes, route, "terminology-note", "[lipsea explicația]", POLICY.contributionExplanation, "Explicație unică pentru sinonimele financiare");
    }
  }
}

function rewriteHtml(html, route) {
  const preferredEol = html.includes("\r\n") ? "\r\n" : "\n";
  const $ = cheerio.load(html, { decodeEntities: false });
  const changes = [];
  applyRouteRequirements($, route, changes);

  $("title").each((_, element) => {
    const before = $(element).text();
    const after = rewriteTerminology(before);
    if (after !== before) $(element).text(after);
    addChange(changes, route, "title", before, after);
  });
  $("meta[name='description'],meta[property='og:title'],meta[property='og:description'],meta[name='twitter:title'],meta[name='twitter:description']").each((_, element) => {
    const before = $(element).attr("content") || "";
    const after = rewriteTerminology(before);
    if (after !== before) $(element).attr("content", after);
    addChange(changes, route, "metadata", before, after);
  });
  $("body").find("*").addBack().contents().each((_, node) => {
    if (node.type !== "text") return;
    const parent = node.parent?.name ? String(node.parent.name).toLowerCase() : "";
    if (["script", "style", "code", "pre", "textarea"].includes(parent)) return;
    const element = $(node.parent);
    if (element.closest("[data-terminology-note='own-contribution'],.program-factual-status").length) return;
    const before = node.data;
    const after = rewriteTerminology(before);
    if (after !== before) node.data = after;
    addChange(changes, route, "visible-copy", before, after);
  });
  $("script[type='application/ld+json']").each((_, element) => {
    try {
      const parsed = JSON.parse($(element).html() || "null");
      const rewritten = rewriteJsonLd(parsed, route, changes);
      $(element).text(JSON.stringify(rewritten, null, 2));
    } catch {
      // Invalid JSON-LD is handled by the structured-data contract.
    }
  });
  if (changes.length === 0) return { html, changes };
  let output = $.html().replace(/[ \t]+$/gmu, "");
  if (preferredEol === "\r\n") output = output.replace(/\r?\n/gu, "\r\n");
  return { html: output, changes };
}

function applyTargetPages({ write = false } = {}) {
  const state = collectSiteState();
  const entries = targetEntries(state);
  const changes = [];
  const changedFiles = [];
  for (const entry of entries) {
    const filePath = path.join(ROOT, entry.sourceFile);
    const before = fs.readFileSync(filePath, "utf8");
    const result = rewriteHtml(before, entry.route);
    changes.push(...result.changes.map((change) => ({ ...change, sourceFile: entry.sourceFile })));
    if (result.html === before) continue;
    changedFiles.push(entry.sourceFile);
    if (write) fs.writeFileSync(filePath, result.html, "utf8");
  }
  return { targetCount: entries.length, changes, changedFiles };
}

function targetEntries(state = collectSiteState()) {
  const canonicalByRoute = new Map(state.entries.map((entry) => [entry.route, entry]));
  return POLICY.targetRoutes.map((route) => {
    if (canonicalByRoute.has(route)) return canonicalByRoute.get(route);
    const sourceFile = route === "/" ? "index.html" : `${route.slice(1)}/index.html`;
    if (!fs.existsSync(path.join(ROOT, sourceFile))) throw new Error(`Suprafața P0.14 lipsește: ${route} (${sourceFile})`);
    return { route, sourceFile, indexable: false };
  });
}

function collectStrings(value, output = [], currentPath = "$" ) {
  if (typeof value === "string") {
    if (!/^(?:https?:|mailto:|tel:|\/)/iu.test(value.trim())) output.push({ path: currentPath, text: value });
    return output;
  }
  if (Array.isArray(value)) value.forEach((item, index) => collectStrings(item, output, `${currentPath}[${index}]`));
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, child]) => {
    if (!PROTECTED_SOURCE_KEYS.has(key.toLowerCase())) collectStrings(child, output, `${currentPath}.${key}`);
  });
  return output;
}

function patternIssues(text, rules, context) {
  const issues = [];
  for (const rule of rules) {
    const regex = new RegExp(rule.pattern, "giu");
    const matches = [...String(text || "").matchAll(regex)];
    for (const match of matches) {
      const prefix = String(text || "").slice(Math.max(0, (match.index || 0) - 30), match.index || 0);
      const widerPrefix = String(text || "").slice(Math.max(0, (match.index || 0) - 180), match.index || 0);
      const suffix = String(text || "").slice((match.index || 0) + match[0].length, (match.index || 0) + match[0].length + 2);
      if (rule.id === "guaranteed-outcome" && /\b(?:nu|nici|fără\s+să)\s*$/iu.test(prefix)) continue;
      if (rule.id === "guaranteed-outcome" && /^\s*\?/u.test(suffix)) continue;
      if (rule.id === "guaranteed-outcome" && /\b(?:eroare|erori|greșeală|greșeli|greseala|greseli|mit)\b/iu.test(widerPrefix)) continue;
      issues.push({ ...context, rule: rule.id, fragment: cleanText(match[0]), message: rule.message });
    }
  }
  return issues;
}

function contentForAudit($) {
  const body = $("body").clone();
  body.find("script,style,code,pre,textarea,#navbar,#mobileMenu,footer,.program-factual-status,[data-terminology-note='own-contribution']").remove();
  return cleanText(body.text());
}

function jsonLdStrings($) {
  const strings = [];
  $("script[type='application/ld+json']").each((_, element) => {
    try { collectStrings(JSON.parse($(element).html() || "null"), strings); } catch { /* other tests report invalid JSON-LD */ }
  });
  return strings;
}

function validOpenProgram(program, today = new Date()) {
  if (!program || program.status !== "apel_deschis") return false;
  if (!program.verifiedAt || !program.sourceUrl || !program.sourceVersion || !program.applicationStart || !program.applicationEnd) return false;
  const start = new Date(`${program.applicationStart}T00:00:00Z`);
  const end = new Date(`${program.applicationEnd}T23:59:59Z`);
  return Number.isFinite(start.getTime()) && Number.isFinite(end.getTime()) && start <= today && today <= end;
}

function auditTerminology() {
  const state = collectSiteState();
  const entries = targetEntries(state);
  const canonicalRoutes = new Set(state.entries.map((entry) => entry.route));
  const auditEntries = [...state.entries, ...entries.filter((entry) => !canonicalRoutes.has(entry.route))];
  const allCanonicalIssues = [];
  const targetIssues = [];
  const requirementIssues = [];
  const openProgramsChecked = new Set();

  for (const entry of auditEntries) {
    const html = fs.readFileSync(path.join(ROOT, entry.sourceFile), "utf8");
    const $ = cheerio.load(html, { decodeEntities: false });
    const visible = contentForAudit($);
    if (canonicalRoutes.has(entry.route)) {
      allCanonicalIssues.push(...patternIssues(visible, POLICY.absoluteForbiddenPatterns, { route: entry.route, sourceFile: entry.sourceFile, scope: "canonical" }));
      for (const item of jsonLdStrings($)) allCanonicalIssues.push(...patternIssues(item.text, POLICY.absoluteForbiddenPatterns, { route: entry.route, sourceFile: entry.sourceFile, scope: `json-ld:${item.path}` }));
    }
    if (!TARGET_ROUTES.has(entry.route)) continue;

    targetIssues.push(...patternIssues(visible, POLICY.targetContextPatterns, { route: entry.route, sourceFile: entry.sourceFile, scope: "target-copy" }));
    if (/\b(?:cofinanț(?:are|area|ării)|aport(?:ul|ului)?)\b/iu.test(visible)) targetIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "target-copy", rule: "non-primary-contribution-term", fragment: "cofinanțare/aport", message: "Folosește «contribuție proprie»; sinonimele sunt permise doar în nota controlată." });
    if (/\bActiv\b/u.test(visible)) targetIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "target-copy", rule: "standalone-active", fragment: "Activ", message: "Nu folosi statusul generic «Activ»." });
    if (/\bdocument oficial verificat la\b/iu.test(visible) && !/\bdocument oficial verificat la\s+(?:\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2})\b/iu.test(visible)) requirementIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "target-copy", rule: "verification-date-missing", fragment: "document oficial verificat la", message: "Data verificării trebuie completată explicit." });
    if (POLICY.requiredPositioningRoutes.includes(entry.route) && !cleanText($("body").text()).includes(POLICY.positioning)) requirementIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "requirement", rule: "positioning-missing", fragment: POLICY.positioning, message: "Poziționarea centrală lipsește." });
    if (entry.route === "/fonduri-europene") {
      const notes = $("[data-terminology-note='own-contribution']");
      if (notes.length !== 1 || cleanText(notes.text()) !== POLICY.contributionExplanation) requirementIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "requirement", rule: "contribution-explanation", fragment: cleanText(notes.text()), message: "Explicația sinonimelor trebuie să existe exact o dată." });
    }
    $("[data-program-status='apel_deschis'][data-program-id]").each((_, element) => {
      const programId = $(element).attr("data-program-id");
      if (!programId || openProgramsChecked.has(programId)) return;
      openProgramsChecked.add(programId);
      const program = (PROGRAM_CONFIG.programs || []).find((item) => item.slug === programId);
      if (!validOpenProgram(program)) requirementIssues.push({ route: entry.route, sourceFile: entry.sourceFile, scope: "controlled-status", rule: "open-call-without-current-interval", fragment: programId, message: "«Apel deschis» cere interval oficial curent și proveniență completă în registru." });
    });
  }

  const sourceIssues = [];
  for (const page of PROGRAM_CONFIG.pages || []) {
    if (!TARGET_PAGE_SLUGS.has(page.slug)) continue;
    for (const item of collectStrings(page)) {
      const context = { route: `/${page.slug}`, sourceFile: "config/seo-programs.json", scope: item.path };
      sourceIssues.push(...patternIssues(item.text, POLICY.absoluteForbiddenPatterns, context));
      sourceIssues.push(...patternIssues(item.text, POLICY.targetContextPatterns, context));
      if (/\b(?:cofinanț(?:are|area|ării)|aport(?:ul|ului)?)\b/iu.test(item.text)) sourceIssues.push({ ...context, rule: "non-primary-contribution-term", fragment: cleanText(item.text), message: "Sursa editorială trebuie să folosească «contribuție proprie»." });
    }
  }

  const issues = [...allCanonicalIssues, ...targetIssues, ...requirementIssues, ...sourceIssues];
  return {
    canonicalCount: state.entries.length,
    targetCount: entries.length,
    absoluteIssueCount: allCanonicalIssues.length,
    contextualIssueCount: targetIssues.length,
    requirementIssueCount: requirementIssues.length,
    sourceIssueCount: sourceIssues.length,
    openProgramsChecked: [...openProgramsChecked],
    issues,
    issueCount: issues.length
  };
}

module.exports = {
  POLICY,
  TARGET_ROUTES,
  applyTargetPages,
  auditTerminology,
  migrateTargetSources,
  rewriteTerminology,
  validOpenProgram
};
