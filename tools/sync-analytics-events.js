#!/usr/bin/env node
"use strict";

require("./fs-write-retry");

const fs = require("fs");
const path = require("path");
const { ROOT, findPublicHtmlFiles } = require("./sync-global-header");
const { synchronizeGoogleTag } = require("./sync-google-tag");

const ANALYTICS_SCRIPT = '<script src="/assets/analytics-events.js" defer></script>';
const ATTRIBUTION_SCRIPT = '<script src="/assets/lead-attribution.js" defer></script>';
const FUNNEL_EVENT_ALIASES = Object.freeze({
  eligibility_cta_click: "cta_click",
  contact_page_click: "cta_click",
  whatsapp_number_click: "contact_whatsapp",
  phone_click: "contact_phone",
  email_click: "contact_email",
  form_submit_success: "form_submit",
  form_validation_error: "field_error"
});
const PROGRAMS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs || [];
const PROGRAM_FAMILIES = new Map(PROGRAMS.map((program) => [program.slug, program.family || ""]));
const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  "archive",
  "dist",
  "node_modules",
  "rapoarte",
  "reports"
]);
const SOCIAL_HOSTS = new Set([
  "facebook.com",
  "www.facebook.com",
  "instagram.com",
  "www.instagram.com",
  "linkedin.com",
  "www.linkedin.com",
  "youtube.com",
  "www.youtube.com",
  "youtu.be",
  "maps.google.com",
  "www.google.com"
]);

function listHtmlFiles(directory = ROOT, relativeDirectory = "") {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
      files.push(...listHtmlFiles(path.join(directory, entry.name), path.posix.join(relativeDirectory, entry.name)));
      continue;
    }
    if (entry.isFile() && path.extname(entry.name).toLowerCase() === ".html") {
      files.push(path.posix.join(relativeDirectory, entry.name));
    }
  }
  return files.sort((left, right) => left.localeCompare(right));
}

function count(text, token) {
  return text.split(token).length - 1;
}

function stripInlineClarity(html) {
  return html.replace(/\s*<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi, (script) => {
    return /https:\/\/www\.clarity\.ms\/tag\//i.test(script) ? "" : script;
  });
}

function removeAnalyticsScripts(html) {
  return html
    .replace(/[ \t]*<script\b[^>]*\bsrc=["']\/assets\/analytics-events\.js(?:\?[^"']*)?["'][^>]*>[ \t]*<\/script>[ \t]*(?:\r?\n)?/gi, "")
    .replace(/[ \t]*<script\b[^>]*\bsrc=["']\/assets\/lead-attribution\.js(?:\?[^"']*)?["'][^>]*>[ \t]*<\/script>[ \t]*(?:\r?\n)?/gi, "");
}

function getAttribute(tag, name) {
  const pattern = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = tag.match(pattern);
  return match ? (match[1] ?? match[2] ?? match[3] ?? "") : "";
}

function hasAttribute(tag, name) {
  return new RegExp(`\\s${name}(?:\\s*=|\\s|/?>)`, "i").test(tag);
}

function escapeAttribute(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}

function addAttributes(tag, attributes) {
  const additions = Object.entries(attributes)
    .filter(([name, value]) => value !== "" && !hasAttribute(tag, name))
    .map(([name, value]) => ` ${name}="${escapeAttribute(value)}"`)
    .join("");
  if (!additions) return tag;
  return tag.replace(/\s*\/?>$/, (closing) => `${additions}${closing.startsWith(" /") ? " />" : ">"}`);
}

function setAttribute(tag, name, value) {
  const escaped = escapeAttribute(value);
  const pattern = new RegExp(`(\\s${name}\\s*=\\s*)(?:"[^"]*"|'[^']*'|[^\\s>]+)`, "i");
  if (pattern.test(tag)) return tag.replace(pattern, `$1"${escaped}"`);
  return addAttributes(tag, { [name]: value });
}

function normalizeEventNames(tag) {
  const current = getAttribute(tag, "data-analytics-event").trim();
  if (!current) return tag;
  const normalized = current
    .split(/\s+/)
    .filter(Boolean)
    .map((name) => FUNNEL_EVENT_ALIASES[name] || name)
    .filter((name, index, names) => names.indexOf(name) === index)
    .join(" ");
  let output = setAttribute(tag, "data-analytics-event", normalized);
  if (normalized.split(/\s+/).includes("cta_click")) {
    output = addAttributes(output, {
      "data-analytics-cta-view": "true",
      "data-analytics-copy-variant": "default"
    });
  }
  return output;
}

function sanitizedExternalTarget(href) {
  try {
    const url = new URL(href);
    if (!/^https?:$/.test(url.protocol)) return "";
    return `${url.protocol}//${url.hostname}${url.pathname || "/"}`;
  } catch {
    return "";
  }
}

function annotateAnchor(tag) {
  if (hasAttribute(tag, "data-analytics-event")) return normalizeEventNames(tag);
  const href = getAttribute(tag, "href").trim();
  if (!href) return tag;

  if (hasAttribute(tag, "data-whatsapp-dialog-open")) {
    return addAttributes(tag, {
      "data-analytics-event": "cta_click",
      "data-analytics-component": "eligibility_cta",
      "data-analytics-cta-id": "eligibility_whatsapp",
      "data-analytics-cta-view": "true",
      "data-analytics-copy-variant": "default"
    });
  }

  if (/^https:\/\/(?:api\.)?wa\.me\//i.test(href)) {
    return addAttributes(tag, {
      "data-analytics-event": "contact_whatsapp",
      "data-analytics-component": "whatsapp_link",
      "data-analytics-cta-id": "whatsapp_contact"
    });
  }

  if (/^tel:/i.test(href)) {
    return addAttributes(tag, {
      "data-analytics-event": "contact_phone",
      "data-analytics-component": "contact_link",
      "data-analytics-cta-id": "phone_contact"
    });
  }

  if (/^mailto:/i.test(href)) {
    return addAttributes(tag, {
      "data-analytics-event": "contact_email",
      "data-analytics-component": "contact_link",
      "data-analytics-cta-id": "email_contact"
    });
  }

  if (/^\/contact(?:[?#].*)?$/.test(href)) {
    return addAttributes(tag, {
      "data-analytics-event": "cta_click",
      "data-analytics-component": "contact_cta",
      "data-analytics-cta-id": "contact_page",
      "data-analytics-target": "/contact",
      "data-analytics-cta-view": "true",
      "data-analytics-copy-variant": "default"
    });
  }

  if (/^https?:\/\//i.test(href)) {
    try {
      const url = new URL(href.replace(/&amp;/g, "&"));
      if (url.hostname === "atelierdeconsultanta.ro" || url.hostname === "www.atelierdeconsultanta.ro") return tag;
      if (SOCIAL_HOSTS.has(url.hostname.toLowerCase())) return tag;
      return addAttributes(tag, {
        "data-analytics-event": "source_document_click",
        "data-analytics-component": "official_source",
        "data-analytics-cta-id": "source_document",
        "data-analytics-target": sanitizedExternalTarget(url.href)
      });
    } catch {
      return tag;
    }
  }

  return tag;
}

function routeSlug(relativePath) {
  const normalized = relativePath.replace(/\\/g, "/");
  if (normalized === "index.html") return "home";
  if (normalized.endsWith("/index.html")) return normalized.slice(0, -"/index.html".length).replace(/[^a-z0-9]+/gi, "_");
  return normalized.replace(/\.html$/i, "").replace(/[^a-z0-9]+/gi, "_");
}

function annotateAnchors(html, relativePath) {
  let contactCtaIndex = 0;
  const route = routeSlug(relativePath);
  return html.replace(/<a\b[^>]*>/gi, (tag) => {
    let output = annotateAnchor(tag);
    const events = getAttribute(output, "data-analytics-event").split(/\s+/);
    const ctaId = getAttribute(output, "data-analytics-cta-id");
    if (events.includes("cta_click") && (ctaId === "contact_page" || new RegExp(`^${route}_contact_[0-9]+$`).test(ctaId))) {
      contactCtaIndex += 1;
      output = setAttribute(output, "data-analytics-cta-id", `${route}_contact_${contactCtaIndex}`);
    }
    return output;
  });
}

function annotateForms(html, relativePath) {
  let index = 0;
  return html.replace(/<form\b[^>]*>/gi, (tag) => {
    index += 1;
    let formId = getAttribute(tag, "id").replace(/form$/i, "").replace(/[^a-z0-9]+/gi, "_").toLowerCase();
    if (relativePath === "index.html" && formId === "newsletter") formId = "homepage_newsletter";
    else if (relativePath === "index.html" && formId === "contact") formId = "homepage_contact";
    else if (!formId) formId = `${routeSlug(relativePath)}_form_${index}`;
    return addAttributes(tag, {
      "data-analytics-form": formId,
      "data-analytics-form-version": formId === "contact_triage" ? "short_v1" : "legacy_v1",
      "data-analytics-component": "public_form",
      "data-clarity-mask": "true"
    });
  });
}

function pageTypeFor(relativePath, bodyTag) {
  const route = relativePath.replace(/\\/g, "/").replace(/(?:\/index)?\.html$/i, "");
  if (relativePath === "index.html") return "home";
  if (route === "contact") return "contact";
  if (getAttribute(bodyTag, "data-program-id")) return "program";
  if (/calculator|instrumente|verificare-eligibilitate/.test(route)) return "tool";
  if (/blog|ghid|intrebari|cheltuieli|documente|conditii|greseli/.test(route)) return "content";
  return "page";
}

function annotateBody(html, relativePath) {
  return html.replace(/<body\b[^>]*>/i, (tag) => {
    const programSlug = getAttribute(tag, "data-program-id");
    return addAttributes(tag, {
      "data-analytics-page-type": pageTypeFor(relativePath, tag),
      "data-analytics-program-slug": programSlug,
      "data-analytics-program-family": PROGRAM_FAMILIES.get(programSlug) || ""
    });
  });
}

function synchronizePublicHtml(html, relativePath) {
  const eol = html.includes("\r\n") ? "\r\n" : "\n";
  let output = synchronizeGoogleTag(stripInlineClarity(html), relativePath);
  output = removeAnalyticsScripts(output);
  output = annotateAnchors(output, relativePath);
  output = annotateForms(output, relativePath);
  output = annotateBody(output, relativePath);
  if (!/<\/head>/i.test(output)) throw new Error(`${relativePath}: lipsește </head>`);
  return output.replace(/<\/head>/i, `  ${ATTRIBUTION_SCRIPT}${eol}  ${ANALYTICS_SCRIPT}${eol}</head>`);
}

function main() {
  const check = process.argv.includes("--check");
  const publicFiles = findPublicHtmlFiles();
  const publicSet = new Set(publicFiles);
  const allHtmlFiles = listHtmlFiles();
  const changed = [];

  for (const relativePath of allHtmlFiles) {
    const filePath = path.join(ROOT, ...relativePath.split("/"));
    const before = fs.readFileSync(filePath, "utf8");
    const after = publicSet.has(relativePath)
      ? synchronizePublicHtml(before, relativePath)
      : stripInlineClarity(before);
    if (after === before) continue;
    changed.push(relativePath);
    if (!check) fs.writeFileSync(filePath, after, "utf8");
  }

  if (check && changed.length) {
    console.error(`Analytics sync FAILED: ${changed.length} fișiere nesincronizate.`);
    changed.slice(0, 20).forEach((file) => console.error(` - ${file}`));
    process.exitCode = 1;
    return;
  }

  console.log(`Analytics sync ${check ? "PASS" : "completat"}: ${publicFiles.length} pagini publice, ${changed.length} fișiere ${check ? "deja conforme" : "actualizate"}.`);
}

if (require.main === module) main();

module.exports = {
  ANALYTICS_SCRIPT,
  ATTRIBUTION_SCRIPT,
  annotateAnchor,
  annotateAnchors,
  annotateBody,
  annotateForms,
  listHtmlFiles,
  stripInlineClarity,
  synchronizePublicHtml
};
