"use strict";

const fs = require("fs");
const path = require("path");
const {
  loadProgramConfig,
  programForRoute
} = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const GUIDES_PATH = path.join(ROOT, "official-guides.json");
const TODO_SOURCE = "TODO_SURSA_OFICIALA";
const PUBLIC_PLACEHOLDER = "";
const RO_MONTHS = [
  "ianuarie",
  "februarie",
  "martie",
  "aprilie",
  "mai",
  "iunie",
  "iulie",
  "august",
  "septembrie",
  "octombrie",
  "noiembrie",
  "decembrie"
];

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function publicText(value, fallback = PUBLIC_PLACEHOLDER) {
  const text = String(value || "").trim();
  if (!text || /^TODO_/i.test(text)) return fallback;
  return text;
}

function readOfficialGuides() {
  if (!fs.existsSync(GUIDES_PATH)) return {};
  return JSON.parse(fs.readFileSync(GUIDES_PATH, "utf8"));
}

function asGuide(entry) {
  if (!entry) return {};
  if (typeof entry === "string") return { url: entry };
  return entry;
}

function isHttpUrl(value) {
  return /^https?:\/\//i.test(String(value || "").trim());
}

function hasValue(value) {
  const text = String(value || "").trim();
  return Boolean(text) && !text.startsWith("TODO_");
}

function normalizeOfficialSource(key, entry) {
  const guide = asGuide(entry);
  const url = String(guide.url || "").trim();
  const title = publicText(guide.title || guide.name, "Sursa oficiala");
  const source = {
    key,
    title,
    name: guide.name || title,
    institution: publicText(guide.institution || guide.authority),
    documentType: publicText(guide.documentType || guide.type),
    url: url || "",
    accessedAt: publicText(guide.accessedAt || guide.lastVerifiedAt),
    note: guide.note || "",
    programIds: Array.isArray(guide.programIds) ? guide.programIds : [],
    sourceStatus: publicText(guide.sourceStatus),
    reviewedAt: publicText(guide.reviewedAt || guide.accessedAt || guide.lastVerifiedAt)
  };

  source.isComplete = isHttpUrl(source.url)
    && hasValue(source.title)
    && hasValue(source.institution)
    && hasValue(source.documentType)
    && hasValue(source.accessedAt);

  return source;
}

function sourcesForProgram(programOrRoute, options = {}) {
  const programs = options.programs || loadProgramConfig().programs;
  const program = typeof programOrRoute === "string"
    ? programForRoute(programOrRoute, programs)
    : programOrRoute;
  if (!program) return [];
  return sourcesForKeys(program.officialGuideKeys || [], options.guides || readOfficialGuides());
}

function sourcesForKeys(keys, guides = readOfficialGuides()) {
  const sourceKeys = Array.isArray(keys) ? keys : [];
  const uniqueKeys = [...new Set(sourceKeys.filter(Boolean))];
  return uniqueKeys
    .map((key) => normalizeOfficialSource(key, guides[key]))
    .filter((source) => source.isComplete);
}

function formatDate(value) {
  const raw = String(value || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return publicText(raw);
  const date = new Date(`${raw}T12:00:00Z`);
  return `${date.getUTCDate()} ${RO_MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
}

function renderDate(value) {
  const raw = String(value || "").trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    return `<time datetime="${esc(raw)}">${esc(formatDate(raw))}</time>`;
  }
  return esc(formatDate(raw));
}

function renderSourceTitle(source) {
  if (!source.isComplete || !isHttpUrl(source.url)) {
    return `<span class="official-sources__title">${esc(publicText(source.title, "Sursa oficiala"))}</span>`;
  }

  return `<a class="official-sources__title" href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.title)}</a>`;
}

function renderSourceUrl(source) {
  if (!isHttpUrl(source.url)) return esc(PUBLIC_PLACEHOLDER);
  return `<a href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.url)}</a>`;
}

function renderOfficialSourceItem(source) {
  return `<li class="official-sources__item" data-source-key="${esc(source.key)}">
          ${renderSourceTitle(source)}
          <dl class="official-sources__meta">
            <div><dt>Institutie</dt><dd>${esc(source.institution)}</dd></div>
            <div><dt>Tip document</dt><dd>${esc(source.documentType)}</dd></div>
            <div><dt>Verificat</dt><dd>${renderDate(source.accessedAt)}</dd></div>
            <div class="official-sources__url"><dt>URL</dt><dd>${renderSourceUrl(source)}</dd></div>
          </dl>
          ${source.note ? `<p class="official-sources__note">${esc(source.note)}</p>` : ""}
        </li>`;
}

function renderOfficialSources(keys, options = {}) {
  const sources = sourcesForKeys(keys, options.guides);
  if (!sources.length) return "";
  const id = options.id || "official-sources";
  const title = options.title || "Surse oficiale consultate";

  return `<section class="official-sources" aria-labelledby="${esc(id)}">
        <h2 id="${esc(id)}">${esc(title)}</h2>
        <ul class="official-sources__list">
        ${sources.map(renderOfficialSourceItem).join("\n        ")}
        </ul>
      </section>`;
}

function officialSourceCitations(keys, guides = readOfficialGuides()) {
  return sourcesForKeys(keys, guides).map((source) => ({
    "@type": "CreativeWork",
    name: source.title,
    url: source.url,
    publisher: {
      "@type": "Organization",
      name: source.institution
    }
  }));
}

module.exports = {
  TODO_SOURCE,
  officialSourceCitations,
  readOfficialGuides,
  renderOfficialSources,
  sourcesForProgram,
  sourcesForKeys
};
