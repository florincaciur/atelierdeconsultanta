"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { collectSiteState } = require("./generate-sitemap");
const {
  normalizeJsonLdScripts,
  normalizeRomanianCopy
} = require("./normalize-copy-ro");

const ROOT = path.resolve(__dirname, "..");
const POLICY_PATH = path.join(ROOT, "config", "editorial-qa.json");
const POLICY = JSON.parse(fs.readFileSync(POLICY_PATH, "utf8"));
const PROGRAM_CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const PROGRAM_CONFIG = JSON.parse(fs.readFileSync(PROGRAM_CONFIG_PATH, "utf8"));
const PROGRAM_ROUTES = new Set((PROGRAM_CONFIG.programs || []).map((program) => program.pageUrl).filter(Boolean));

const PROTECTED_SOURCE_KEYS = new Set([
  "applicationend",
  "applicationstart",
  "canonical",
  "currency",
  "factualgovernanceref",
  "family",
  "file",
  "href",
  "icon",
  "id",
  "image",
  "lastmeaningfulupdate",
  "lastreviewed",
  "nextreviewat",
  "officialguidekey",
  "officialguidekeys",
  "output",
  "pageurl",
  "programid",
  "publicationstate",
  "route",
  "schemaType".toLowerCase(),
  "slug",
  "sourceoftruth",
  "sourcename",
  "sourcetype",
  "sourceurl",
  "sourceversion",
  "status",
  "statuslabel",
  "target",
  "type",
  "updatedat",
  "url",
  "verifiedat"
]);

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function shortFragment(value, limit = 220) {
  const text = cleanText(value);
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function normalizedLabel(value) {
  return cleanText(value).toLowerCase();
}

function compiledRules(programContext = false) {
  const rules = [...POLICY.forbiddenTemplateLabels];
  if (programContext) rules.push(...POLICY.programTemplateLabels);
  return rules.map((rule) => ({ ...rule, regex: new RegExp(rule.pattern, "iu") }));
}

function labelRule(value, programContext = false) {
  const label = normalizedLabel(value);
  return compiledRules(programContext).find((rule) => rule.regex.test(label)) || null;
}

function canonicalRouteFromOutput(value) {
  const output = String(value || "").replace(/\\/gu, "/").replace(/^\/+|\/+$/gu, "");
  if (!output) return null;
  const route = output.replace(/\/index\.html$/iu, "").replace(/\.html$/iu, "");
  return route ? `/${route}` : "/";
}

function routeForObject(value, fallback = null) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fallback;
  if (typeof value.pageUrl === "string" && value.pageUrl.startsWith("/")) return value.pageUrl;
  if (typeof value.route === "string" && value.route.startsWith("/")) return value.route;
  if (typeof value.output === "string") return canonicalRouteFromOutput(value.output) || fallback;
  if (typeof value.slug === "string" && value.slug && !value.slug.includes("/")) return `/${value.slug}`;
  return fallback;
}

function isProtectedSourceValue(key, value) {
  const normalizedKey = String(key || "").toLowerCase();
  if (PROTECTED_SOURCE_KEYS.has(normalizedKey)) return true;
  const text = String(value || "").trim();
  if (!text) return true;
  if (/^(?:https?:|mailto:|tel:|\/)/iu.test(text)) return true;
  if (/^\d{4}-\d{2}-\d{2}(?:T.*)?$/u.test(text)) return true;
  if (/^[a-z0-9_.-]+(?:\/[a-z0-9_.-]+)*$/u.test(text) && !/\s/u.test(text)) return true;
  return false;
}

function addChange(changes, seen, change) {
  const normalized = {
    route: change.route || "DE_VALIDAT_UMAN",
    sourceFile: String(change.sourceFile || "").replace(/\\/gu, "/"),
    location: change.location || "visible-copy",
    oldFragment: shortFragment(change.oldFragment),
    newFragment: shortFragment(change.newFragment),
    reason: change.reason
  };
  const key = JSON.stringify(normalized);
  if (seen.has(key)) return;
  seen.add(key);
  changes.push(normalized);
}

function normalizeDom($, context) {
  const { route, sourceFile, programContext, changes, seen } = context;
  let changed = false;

  $(".audit-design-summary").each((_, element) => {
    const oldFragment = $(element).text();
    addChange(changes, seen, {
      route,
      sourceFile,
      location: "legacy-summary",
      oldFragment,
      newFragment: "[bloc eliminat]",
      reason: "Etichetă internă și rezumat generic redundant"
    });
    $(element).remove();
    changed = true;
  });

  $("h1,h2,h3,h4,h5,h6,.section-label,.eyebrow,.audit-design-summary__label").each((_, element) => {
    const current = cleanText($(element).text());
    const rule = labelRule(current, programContext);
    if (!rule) return;
    addChange(changes, seen, {
      route,
      sourceFile,
      location: "heading",
      oldFragment: current,
      newFragment: rule.replacement,
      reason: `Înlocuire etichetă internă (${rule.id})`
    });
    $(element).text(rule.replacement);
    changed = true;
  });

  function normalizeValue(value, location) {
    if (/^https?:\/\/\S+$/iu.test(String(value || "").trim())) return value;
    const next = normalizeRomanianCopy(value);
    if (next === value) return value;
    addChange(changes, seen, {
      route,
      sourceFile,
      location,
      oldFragment: value,
      newFragment: next,
      reason: "Diacritice și normă editorială română"
    });
    changed = true;
    return next;
  }

  $("title").each((_, element) => {
    const current = $(element).text();
    const next = normalizeValue(current, "title");
    if (next !== current) $(element).text(next);
  });

  $("meta[name='description'],meta[property='og:title'],meta[property='og:description'],meta[name='twitter:title'],meta[name='twitter:description']").each((_, element) => {
    const current = $(element).attr("content");
    if (!current) return;
    const next = normalizeValue(current, "metadata");
    if (next !== current) $(element).attr("content", next);
  });

  $("[aria-label],[alt],[title],[placeholder]").each((_, element) => {
    for (const attribute of ["aria-label", "alt", "title", "placeholder"]) {
      const current = $(element).attr(attribute);
      if (!current) continue;
      const next = normalizeValue(current, `attribute:${attribute}`);
      if (next !== current) $(element).attr(attribute, next);
    }
  });

  $("body").find("*").addBack().contents().each((_, node) => {
    if (node.type !== "text") return;
    const parent = node.parent?.name ? String(node.parent.name).toLowerCase() : "";
    if (["script", "style", "code", "pre", "textarea"].includes(parent)) return;
    const next = normalizeValue(node.data, "visible-copy");
    if (next !== node.data) node.data = next;
  });

  return changed;
}

function normalizeHtmlDocument(html, context) {
  const preferredEol = html.includes("\r\n") ? "\r\n" : "\n";
  const $ = cheerio.load(html, { decodeEntities: false });
  const changed = normalizeDom($, context);
  let output = changed ? $.html() : html;
  const jsonLd = normalizeJsonLdScripts(output);
  if (jsonLd.changed) {
    addChange(context.changes, context.seen, {
      route: context.route,
      sourceFile: context.sourceFile,
      location: "json-ld",
      oldFragment: "Text JSON-LD fără normalizarea editorială curentă",
      newFragment: "Text JSON-LD sincronizat cu forma editorială",
      reason: "Sincronizare date structurate cu textul corectat"
    });
    output = jsonLd.html;
  }
  output = output.replace(/[ \t]+$/gmu, "");
  return preferredEol === "\r\n" ? output.replace(/\r?\n/gu, "\r\n") : output;
}

function normalizeHtmlFragment(fragment, context) {
  const $ = cheerio.load(`<div data-editorial-fragment-root>${fragment}</div>`, { decodeEntities: false }, false);
  const root = $("[data-editorial-fragment-root]");
  let changed = false;

  root.find("h1,h2,h3,h4,h5,h6,.section-label,.eyebrow").each((_, element) => {
    const current = cleanText($(element).text());
    const rule = labelRule(current, context.programContext);
    if (!rule) return;
    addChange(context.changes, context.seen, {
      route: context.route,
      sourceFile: context.sourceFile,
      location: context.location,
      oldFragment: current,
      newFragment: rule.replacement,
      reason: `Înlocuire etichetă internă (${rule.id})`
    });
    $(element).text(rule.replacement);
    changed = true;
  });

  root.find("*").addBack().contents().each((_, node) => {
    if (node.type !== "text") return;
    const parent = node.parent?.name ? String(node.parent.name).toLowerCase() : "";
    if (["script", "style", "code", "pre", "textarea"].includes(parent)) return;
    if (/^https?:\/\/\S+$/iu.test(String(node.data || "").trim())) return;
    const next = normalizeRomanianCopy(node.data);
    if (next === node.data) return;
    addChange(context.changes, context.seen, {
      route: context.route,
      sourceFile: context.sourceFile,
      location: context.location,
      oldFragment: node.data,
      newFragment: next,
      reason: "Diacritice și normă editorială română"
    });
    node.data = next;
    changed = true;
  });

  return { value: changed ? root.html() : fragment, changed };
}

function processCanonicalPages({ write = false } = {}) {
  const state = collectSiteState();
  const changes = [];
  const seen = new Set();
  const changedFiles = [];

  for (const entry of state.entries) {
    const filePath = path.join(ROOT, entry.sourceFile);
    const before = fs.readFileSync(filePath, "utf8");
    const programContext = PROGRAM_ROUTES.has(entry.route)
      || /data-analytics-page-type=["']program["']/iu.test(before)
      || /data-program-route=/iu.test(before);
    const after = normalizeHtmlDocument(before, {
      route: entry.route,
      sourceFile: entry.sourceFile,
      programContext,
      changes,
      seen
    });
    if (after === before) continue;
    changedFiles.push(entry.sourceFile);
    if (write) fs.writeFileSync(filePath, after, "utf8");
  }

  return { canonicalCount: state.entries.length, changedFiles, changes };
}

function processEditorialSources({ write = false } = {}) {
  const changes = [];
  const seen = new Set();
  const changedFiles = [];

  for (const relative of POLICY.sourceFiles) {
    const filePath = path.join(ROOT, relative);
    if (!fs.existsSync(filePath)) continue;
    const before = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(before);

    function visit(value, context) {
      if (typeof value === "string") {
        if (isProtectedSourceValue(context.key, value)) return value;
        let next = value;
        const rule = labelRule(value, context.programContext);
        if (rule) next = rule.replacement;
        if (/<[a-z][\s\S]*>/iu.test(next)) {
          next = normalizeHtmlFragment(next, {
            route: context.route,
            sourceFile: relative,
            location: context.path.join("."),
            programContext: context.programContext,
            changes,
            seen
          }).value;
        } else {
          next = normalizeRomanianCopy(next);
        }
        if (next !== value) {
          addChange(changes, seen, {
            route: context.route,
            sourceFile: relative,
            location: context.path.join("."),
            oldFragment: value,
            newFragment: next,
            reason: rule ? `Înlocuire etichetă internă (${rule.id})` : "Diacritice și normă editorială română"
          });
        }
        return next;
      }
      if (Array.isArray(value)) return value.map((item, index) => visit(item, { ...context, path: [...context.path, String(index)] }));
      if (!value || typeof value !== "object") return value;

      const route = routeForObject(value, context.route);
      const programContext = context.programContext
        || PROGRAM_ROUTES.has(route)
        || value.type === "program"
        || Boolean(value.programId && PROGRAM_ROUTES.has(route));
      const output = {};
      for (const [key, child] of Object.entries(value)) {
        const childPath = [...context.path, key];
        const skipRegistryFact = relative === "config/seo-programs.json" && childPath[0] === "programs";
        if (skipRegistryFact) {
          output[key] = child;
          continue;
        }
        output[key] = visit(child, { route, programContext, path: childPath, key });
      }
      return output;
    }

    const normalized = visit(parsed, { route: null, programContext: false, path: [], key: "" });
    const after = `${JSON.stringify(normalized, null, 2)}\n`;
    if (after === before) continue;
    changedFiles.push(relative);
    if (write) fs.writeFileSync(filePath, after, "utf8");
  }

  return { changedFiles, changes };
}

function auditGeneratorSources() {
  const issues = [];
  for (const relative of POLICY.generatorFiles) {
    const source = fs.readFileSync(path.join(ROOT, relative), "utf8");
    const checks = [
      { id: "rendered-short-answer", regex: />\s*R(?:a|ă)spuns scurt\s*</iu },
      { id: "rendered-program-short-label", regex: />\s*Pe scurt\s*</iu },
      { id: "generic-context-card", regex: /["']Context["']\s*,\s*["']rolul paginii["']/iu },
      { id: "generic-update-card", regex: /["']Actualizare["']\s*,\s*["']informa(?:t|ț)ie structurat(?:a|ă)["']/iu },
      { id: "generic-links-card", regex: /["']Leg(?:a|ă)turi["']\s*,\s*["']traseu intern clar["']/iu },
      { id: "generic-next-card", regex: /["']Urm(?:a|ă)tor["']\s*,\s*["']ac(?:t|ț)iune potrivit(?:a|ă)["']/iu }
    ];
    for (const check of checks) {
      if (check.regex.test(source)) issues.push({ sourceFile: relative, type: check.id });
    }
  }
  return issues;
}

function auditEditorialCopy() {
  const pages = processCanonicalPages({ write: false });
  const sources = processEditorialSources({ write: false });
  const generators = auditGeneratorSources();
  return {
    canonicalCount: pages.canonicalCount,
    pageIssues: pages.changes,
    sourceIssues: sources.changes,
    generatorIssues: generators,
    issueCount: pages.changes.length + sources.changes.length + generators.length
  };
}

module.exports = {
  POLICY,
  PROGRAM_ROUTES,
  auditEditorialCopy,
  auditGeneratorSources,
  cleanText,
  labelRule,
  processCanonicalPages,
  processEditorialSources,
  shortFragment
};
