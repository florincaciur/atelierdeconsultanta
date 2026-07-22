#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_FILE = path.join(ROOT, "config", "aeo-question-blocks.json");
const REPORT_FILE = path.join(ROOT, "reports", "p1-18-aeo-question-mapping.md");
const CSV_FILE = path.join(ROOT, "reports", "p1-18-aeo-question-mapping.csv");
const STYLE_HREF = "/assets/aeo-question-blocks.css?v=20260722-1";
const START = "<!-- P1_18_AEO_QUESTIONS_START -->";
const END = "<!-- P1_18_AEO_QUESTIONS_END -->";
const CHECK = process.argv.includes("--check");

function escapeHtml(value) {
  return String(value)
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

function words(value) {
  return String(value).match(/[\p{L}\p{N}]+(?:[’'-][\p{L}\p{N}]+)*/gu) || [];
}

function displayDate(value) {
  const [year, month, day] = value.split("-");
  return `${day}.${month}.${year}`;
}

function renderSource(source) {
  const label = `${source.name}, ${source.document} (${source.version})`;
  return `        <li>Sursă oficială: <a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" data-aeo-official-source>${escapeHtml(label)}</a>. Verificat la <time datetime="${escapeHtml(source.verifiedAt)}">${escapeHtml(displayDate(source.verifiedAt))}</time>.</li>`;
}

function renderQuestion(question) {
  const evidence = question.evidence.map((item) => `          <li>${escapeHtml(item)}</li>`).join("\n");
  const sources = question.sources.map(renderSource).join("\n");
  const links = question.detailLinks
    .map((link) => `        <a href="${escapeHtml(link.href)}" data-aeo-detail-link>${escapeHtml(link.label)}</a>`)
    .join("\n");
  return `  <article class="aeo-question" data-aeo-question="${escapeHtml(question.id)}">
    <h2 id="${escapeHtml(question.id)}">${escapeHtml(question.question)}</h2>
    <p class="aeo-question__direct" data-aeo-direct-answer>${escapeHtml(question.answer)}</p>
    <div class="aeo-question__evidence">
      <h3>${escapeHtml(question.evidenceTitle)}</h3>
      <ul>
${evidence}
      </ul>
    </div>
    <ul class="aeo-question__sources" aria-label="Surse și data verificării">
${sources}
    </ul>
    <p class="aeo-question__details">
${links}
    </p>
  </article>`;
}

function renderBlock(page) {
  return `${START}
<section class="aeo-question-set" aria-label="${escapeHtml(page.label)}" data-aeo-question-set data-aeo-route="${escapeHtml(page.route)}">
${page.questions.map(renderQuestion).join("\n")}
</section>
${END}`;
}

function ensureStyle(html) {
  const link = `  <link rel="stylesheet" href="${STYLE_HREF}">`;
  const stylePattern = /<link\s+rel="stylesheet"\s+href="\/assets\/aeo-question-blocks\.css(?:\?[^"]*)?"\s*>/iu;
  if (stylePattern.test(html)) return html.replace(stylePattern, link.trim());
  if (!html.includes("</head>")) throw new Error("Document fără </head> pentru stilurile P1.18.");
  return html.replace("</head>", `${link}\n</head>`);
}

function ensurePrerequisites(html, page) {
  if (page.route !== "/calculator-soc" || /<section\s+class="section section-alt"\s+id="calculator">/iu.test(html)) return html;
  const marker = /(<!-- Calculator -->\s*)<section\s+class="section section-alt">/iu;
  if (!marker.test(html)) throw new Error(`${page.route}: secțiunea calculatorului nu poate primi ancora stabilă.`);
  return html.replace(marker, '$1<section class="section section-alt" id="calculator">');
}

function injectBlock(html, page) {
  const expected = renderBlock(page);
  const markerPattern = new RegExp(`${START}[\\s\\S]*?${END}`, "u");
  if (markerPattern.test(html)) return html.replace(markerPattern, expected);
  const index = html.indexOf(page.insertAfter);
  if (index < 0) throw new Error(`${page.route}: reperul de inserare nu există: ${page.insertAfter}`);
  const insertionPoint = index + page.insertAfter.length;
  return `${html.slice(0, insertionPoint)}\n${expected}${html.slice(insertionPoint)}`;
}

function markdownCell(value) {
  return String(value).replace(/\|/gu, "\\|").replace(/\s+/gu, " ").trim();
}

function csvCell(value) {
  return `"${String(value).replace(/"/gu, '""').replace(/[\r\n]+/gu, " ")}"`;
}

function renderReport(config) {
  const rows = [];
  for (const page of config.pages) {
    for (const question of page.questions) {
      const source = question.sources.map((item) => `${item.name}: ${item.document} — ${item.url}`).join("; ");
      rows.push(`| ${markdownCell(page.route)} | ${markdownCell(question.question)} | ${markdownCell(question.answer)} | ${markdownCell(source)} | ${markdownCell(question.selectionBasis)} |`);
    }
  }
  return `# P1.18 — Mapping întrebări AEO

Generat din \`config/aeo-question-blocks.json\`. Revizie editorială: **${displayDate(config.reviewedAt)}**.

## Baza selecției

- Export GSC: \`${config.gscEvidence.source}\`, arhiva \`${config.gscEvidence.exportArchive}\`, perioada ${config.gscEvidence.period}.
- ${config.gscEvidence.note}
- Întrebările fără semnal GSC explicit sunt marcate ca provenind din brief/discuții cu clienții și sunt validate numai prin surse oficiale.
- Blocurile sunt HTML editorial obișnuit; nu adaugă markup „AI” și nu promit featured snippets sau apariții în People Also Ask.

## Întrebare → URL → răspuns → sursă

| URL | Întrebare | Răspuns direct | Sursă oficială | Baza selecției |
| --- | --- | --- | --- | --- |
${rows.join("\n")}

## Contract de publicare

- fiecare pagină conține între 3 și 6 întrebări;
- primul răspuns are 40–80 de cuvinte;
- afirmațiile temporale au sursă oficială și dată în același bloc;
- răspunsurile sunt prezente în HTML și nu depind de JavaScript sau de FAQPage;
- întrebările trimit spre detalii existente, fără pagini separate create doar pentru query.
`;
}

function renderCsv(config) {
  const rows = [["url", "question", "answer", "source_name", "source_url", "verified_at", "selection_basis"]];
  for (const page of config.pages) {
    for (const question of page.questions) {
      rows.push([
        page.route,
        question.question,
        question.answer,
        question.sources.map((source) => source.name).join("; "),
        question.sources.map((source) => source.url).join("; "),
        question.sources.map((source) => source.verifiedAt).join("; "),
        question.selectionBasis
      ]);
    }
  }
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

function validateConfig(config) {
  const errors = [];
  const routes = new Set();
  const ids = new Set();
  const policy = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "external-link-policy.json"), "utf8"));
  const allowedHosts = new Set(policy.allowedExactHosts.map((host) => host.toLowerCase()));
  const allowedSuffixes = policy.allowedHostSuffixes;
  const hostAllowed = (host) => allowedHosts.has(host) || allowedSuffixes.some((suffix) => host.endsWith(suffix));

  for (const page of config.pages) {
    if (routes.has(page.route)) errors.push(`${page.route}: rută duplicată`);
    routes.add(page.route);
    if (page.questions.length < 3 || page.questions.length > 6) errors.push(`${page.route}: sunt necesare 3–6 întrebări`);
    if (!fs.existsSync(path.join(ROOT, page.file))) errors.push(`${page.route}: fișier inexistent ${page.file}`);
    for (const question of page.questions) {
      if (ids.has(question.id)) errors.push(`${question.id}: id duplicat`);
      ids.add(question.id);
      const count = words(question.answer).length;
      if (count < 40 || count > 80) errors.push(`${page.route} / ${question.question}: răspunsul are ${count} cuvinte`);
      if (!question.question.endsWith("?")) errors.push(`${page.route}: H2 nu este întrebare: ${question.question}`);
      if (!Array.isArray(question.evidence) || question.evidence.length < 2) errors.push(`${page.route} / ${question.id}: dovadă insuficientă`);
      if (!Array.isArray(question.sources) || !question.sources.length) errors.push(`${page.route} / ${question.id}: sursă lipsă`);
      if (!Array.isArray(question.detailLinks) || !question.detailLinks.length) errors.push(`${page.route} / ${question.id}: link de detaliu lipsă`);
      for (const source of question.sources || []) {
        let sourceUrl;
        try { sourceUrl = new URL(source.url); } catch { errors.push(`${question.id}: URL oficial invalid ${source.url}`); continue; }
        if (sourceUrl.protocol !== "https:" || !hostAllowed(sourceUrl.hostname.toLowerCase())) errors.push(`${question.id}: sursă nepermisă ${source.url}`);
        if (!/^\d{4}-\d{2}-\d{2}$/u.test(source.verifiedAt)) errors.push(`${question.id}: verifiedAt invalid`);
      }
    }
  }
  if (errors.length) throw new Error(`Config P1.18 invalid:\n- ${errors.join("\n- ")}`);
}

function updateFile(file, expected, changed) {
  const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  if (current === expected) return;
  changed.push(path.relative(ROOT, file).replace(/\\/gu, "/"));
  if (!CHECK) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, expected, "utf8");
  }
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  validateConfig(config);
  const changed = [];

  for (const page of config.pages) {
    const file = path.join(ROOT, page.file);
    const current = fs.readFileSync(file, "utf8");
    const expected = ensureStyle(injectBlock(ensurePrerequisites(current, page), page));
    updateFile(file, expected, changed);
  }

  updateFile(REPORT_FILE, renderReport(config), changed);
  updateFile(CSV_FILE, renderCsv(config), changed);

  if (CHECK && changed.length) {
    console.error(`Blocurile P1.18 nu sunt sincronizate:\n- ${changed.join("\n- ")}`);
    process.exit(1);
  }
  console.log(`${CHECK ? "Verificare" : "Sincronizare"} P1.18 PASS: ${config.pages.length} pagini, ${config.pages.reduce((sum, page) => sum + page.questions.length, 0)} întrebări${changed.length ? `; ${changed.length} fișiere actualizate` : "; fără diferențe"}.`);
}

main();
