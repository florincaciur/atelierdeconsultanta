"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "editorial-pages.json");

const TODO_SOURCE = {
  url: "TODO_SURSA_OFICIALA_URL",
  title: "TODO_SURSA_OFICIALA_TITLU",
  accessedAt: "TODO_DATA_ACCESARII"
};

const STATUS_LABELS = {
  actualizat: "Actualizat",
  in_curs_de_verificare: "In curs de verificare",
  arhivat: "Arhivat"
};

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

function readEditorialConfig() {
  if (!fs.existsSync(CONFIG_PATH)) return { pages: [] };
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function normalizeSources(sources) {
  const items = Array.isArray(sources) && sources.length ? sources : [TODO_SOURCE];
  return items.map((source) => ({
    url: source.url || "",
    title: publicText(source.title, "Sursa oficiala"),
    accessedAt: publicText(source.accessedAt, PUBLIC_PLACEHOLDER)
  }));
}

function getEditorialMetadata(slug) {
  const config = readEditorialConfig();
  return (config.pages || []).find((page) => page.slug === slug) || null;
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

function statusLabel(status) {
  return STATUS_LABELS[status] || status || STATUS_LABELS.in_curs_de_verificare;
}

function isPlaceholder(value) {
  return !value || /^TODO_/i.test(String(value));
}

function renderSource(source) {
  const url = source.url || "";
  const title = publicText(source.title, "Sursa oficiala");
  const titleHtml = /^https?:\/\//i.test(url)
    ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(title)}</a>`
    : `<span>${esc(title)}</span>`;
  return `<li>${titleHtml}<span class="editorial-meta__source-date">Accesat: ${renderDate(source.accessedAt)}</span></li>`;
}

function renderEditorialSection(metadata) {
  if (!metadata) return "";
  return `<section class="editorial-meta" aria-label="Metadate editoriale">
        <div class="editorial-meta__header">
          <p class="editorial-meta__eyebrow">Transparenta editoriala</p>
          <span class="editorial-meta__status" data-status="${esc(metadata.status || "in_curs_de_verificare")}">${esc(statusLabel(metadata.status))}</span>
        </div>
        <dl class="editorial-meta__grid">
          <div><dt>Autor</dt><dd>${esc(publicText(metadata.author))}</dd></div>
          <div><dt>Verificat de</dt><dd>${esc(publicText(metadata.reviewer))}</dd></div>
          <div><dt>Data publicarii</dt><dd>${renderDate(metadata.publishedAt)}</dd></div>
          <div><dt>Ultima actualizare</dt><dd>${renderDate(metadata.updatedAt)}</dd></div>
          <div><dt>Ultima verificare</dt><dd>${renderDate(metadata.lastVerifiedAt)}</dd></div>
          ${metadata.readingTime ? `<div><dt>Timp de lectura</dt><dd>${esc(publicText(metadata.readingTime))} min</dd></div>` : ""}
        </dl>
        <p class="editorial-meta__note">Informatiile pot fi modificate de autoritati; verificam periodic ghidurile oficiale.</p>
      </section>`;
}

function editorialSchemaProperties(metadata) {
  if (!metadata) return {};
  const sources = normalizeSources(metadata.officialSources);
  const schema = {};
  if (!isPlaceholder(metadata.publishedAt)) schema.datePublished = metadata.publishedAt;
  if (!isPlaceholder(metadata.updatedAt)) schema.dateModified = metadata.updatedAt;
  if (!isPlaceholder(metadata.author)) {
    schema.author = {
      "@type": "Organization",
      name: metadata.author
    };
  }
  if (!isPlaceholder(metadata.reviewer)) {
    schema.reviewedBy = {
      "@type": "Organization",
      name: metadata.reviewer
    };
  }
  const citations = sources
    .filter((source) => !isPlaceholder(source.title) && !isPlaceholder(source.url))
    .map((source) => ({
      "@type": "CreativeWork",
      name: source.title,
      url: source.url
    }));
  if (citations.length) schema.citation = citations;
  return schema;
}

module.exports = {
  TODO_SOURCE,
  editorialSchemaProperties,
  getEditorialMetadata,
  normalizeSources,
  renderEditorialSection
};
