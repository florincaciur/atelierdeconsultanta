#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadProgramConfig } = require("./program-factual-governance");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "long-form-layout.json");
const CONFIG = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
const INVENTORY_PATH = path.join(ROOT, CONFIG.inventoryPath);
const REPORT_PATH = path.join(ROOT, CONFIG.reportPath);
const CHECK_ONLY = process.argv.includes("--check");
const TOC_START = "<!-- P1_09_LONG_FORM_TOC_START -->";
const TOC_END = "<!-- P1_09_LONG_FORM_TOC_END -->";
const ACTION_START = "<!-- P1_09_DECISION_ACTION_START -->";
const ACTION_END = "<!-- P1_09_DECISION_ACTION_END -->";
const CSS_LINK = '<link rel="stylesheet" href="/assets/long-form-layout.css?v=20260721-6" data-long-form-layout-style="p1_09">';
const JS_LINK = '<script src="/assets/long-form-layout.js?v=20260721-6" defer="" data-long-form-layout-script="p1_09"></script>';

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function normalizeRoute(value) {
  const route = String(value || "/").replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/)[0] || "/";
  return route === "/" ? route : route.replace(/\/$/, "");
}

function stripMarkup(value) {
  return cheerio.load(`<body>${value}</body>`, { decodeEntities: false })("body").text().replace(/\s+/g, " ").trim();
}

function countWords(html, route) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const source = route === "/" ? $("main").first() : ($("main").first().length ? $("main").first() : $(".post-container").first());
  const root = source.clone();
  root.find("script,style,noscript,nav,footer,header,svg,[hidden],[aria-hidden='true'],.global-header,.footer,.site-footer,[data-long-form-toc],.long-form-decision-action").remove();
  root.find("h1,h2,h3,h4,p,li,td,th,dt,dd,summary,blockquote").append(" ");
  const matches = root.text().match(/[\p{L}\p{N}][\p{L}\p{N}’'\-]*/gu);
  return matches ? matches.length : 0;
}

function removeInjected(html) {
  return html
    .replace(new RegExp(`${TOC_START}[\\s\\S]*?${TOC_END}\\s*`, "g"), "")
    .replace(new RegExp(`${ACTION_START}[\\s\\S]*?${ACTION_END}\\s*`, "g"), "")
    .replace(/[ \t]*<link\b[^>]*data-long-form-layout-style=["']p1_09["'][^>]*>[ \t]*(?:\r?\n)?/gi, "")
    .replace(/[ \t]*<script\b[^>]*data-long-form-layout-script=["']p1_09["'][^>]*><\/script>[ \t]*(?:\r?\n)?/gi, "")
    .replace(/\s*<nav\b[^>]*class=["'][^"']*\barticle-toc\b[^"']*["'][^>]*>[\s\S]*?<\/nav>/gi, "")
    .replace(/<div class="long-form-table-region"[^>]*>\s*(<table\b[\s\S]*?<\/table>)\s*<\/div>/gi, "$1")
    .replace(/\sdata-long-form-page=(?:"[^"]*"|'[^']*')/gi, "")
    .replace(/\sdata-long-form-type=(?:"[^"]*"|'[^']*')/gi, "")
    .replace(/\sdata-long-form-word-count=(?:"[^"]*"|'[^']*')/gi, "")
    .replace(/\sdata-long-form-layout=(?:"[^"]*"|'[^']*')/gi, "")
    .replace(/\sdata-long-form-content=(?:"[^"]*"|'[^']*')/gi, "");
}

function slugify(value) {
  return String(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "sectiune";
}

function uniqueId(base, usedIds) {
  let candidate = base;
  let suffix = 2;
  while (usedIds.has(candidate)) candidate = `${base}-${suffix++}`;
  usedIds.add(candidate);
  return candidate;
}

function isExcludedHeading(label) {
  return CONFIG.excludedTocHeadingPatterns.some((pattern) => new RegExp(pattern, "i").test(label));
}

function isSecondaryHeading(label) {
  return CONFIG.secondarySectionPatterns.some((pattern) => new RegExp(pattern, "i").test(label));
}

function enhanceRegion(region, pageTitle, usedIds) {
  const items = [];
  const seenTocIds = new Set();
  let tableIndex = 0;
  let output = region.replace(/<section\b[^>]*class=["'][^"']*\bofficial-sources\b[^"']*["'][^>]*>\s*<h2\b[^>]*>([\s\S]*?)<\/h2>([\s\S]*?)<\/section>/gi, (_, title, body) => {
    return `<details class="official-sources long-form-secondary-detail long-form-secondary-section"><summary>${title}</summary><div class="long-form-secondary-detail__body">${body.trim()}</div></details>`;
  });

  output = output.replace(/<section\b[^>]*class=["'][^"']*\bfaq-item\b[^"']*["'][^>]*>\s*<h3\b[^>]*>([\s\S]*?)<\/h3>([\s\S]*?)<\/section>/gi, (_, title, body) => {
    return `<details class="faq-item long-form-secondary-detail"><summary>${title}</summary><div class="long-form-secondary-detail__body">${body.trim()}</div></details>`;
  });

  output = output.replace(/<h2\b[^>]*>([\s\S]*?)<\/h2>([\s\S]*?)(?=<h2\b|$)/gi, (full, title, body) => {
    const label = stripMarkup(title);
    if (!isSecondaryHeading(label)) return full;
    return `<details class="long-form-secondary-detail long-form-secondary-section"><summary>${title}</summary><div class="long-form-secondary-detail__body">${body.trim()}</div></details>`;
  });

  output = output.replace(/<h2\b([^>]*)>([\s\S]*?)<\/h2>/gi, (full, attrs, inner) => {
    const label = stripMarkup(inner);
    if (!label || isExcludedHeading(label)) return full;
    const idMatch = attrs.match(/\bid=["']([^"']+)["']/i);
    let id = idMatch ? idMatch[1] : "";
    let nextAttrs = attrs;
    if (!id || seenTocIds.has(id)) {
      id = uniqueId(`sectiune-${slugify(label)}`, usedIds);
      if (idMatch) nextAttrs = attrs.replace(idMatch[0], `id="${id}"`);
      else nextAttrs = `${attrs} id="${id}"`;
    } else {
      usedIds.add(id);
    }
    seenTocIds.add(id);
    items.push({ id, label });
    return `<h2${nextAttrs}>${inner}</h2>`;
  });

  output = output.replace(/<table\b[\s\S]*?<\/table>/gi, (table) => {
    tableIndex += 1;
    const label = `Tabel: ${pageTitle} (${tableIndex})`;
    return `<div class="long-form-table-region" role="region" tabindex="0" aria-label="${escapeHtml(label)}">${table}</div>`;
  });

  return { output, items, tableCount: tableIndex };
}

function renderToc(items, variant) {
  const links = items.map((item, index) => `        <li><a href="#${escapeHtml(item.id)}" data-long-form-toc-link=""${index === 0 ? ' aria-current="location"' : ""}>${escapeHtml(item.label)}</a></li>`).join("\n");
  return `${TOC_START}
  <aside class="long-form-toc${variant === "home" ? " long-form-toc--home" : ""}" data-long-form-toc="" aria-label="Navigare în pagina lungă">
    <details>
      <summary>Cuprins</summary>
      <nav aria-label="Cuprinsul paginii">
        <ol>
${links}
        </ol>
      </nav>
    </details>
  </aside>
${TOC_END}`;
}

function renderDecisionAction(program) {
  const target = `/contact#program=${encodeURIComponent(program.slug)}`;
  return `${ACTION_START}
      <aside class="long-form-decision-action" aria-label="Următorul pas după rezumat">
        <p><strong>Ai parcurs datele esențiale?</strong> Continuă cu o verificare orientativă a solicitantului, investiției, bugetului și documentelor.</p>
        <a href="${escapeHtml(target)}" data-analytics-event="cta_click" data-analytics-component="long_form_decision" data-analytics-cta-id="${escapeHtml(program.slug)}_long_form_decision" data-analytics-target="${escapeHtml(target)}" data-analytics-program-slug="${escapeHtml(program.slug)}" data-analytics-program-family="${escapeHtml(program.family)}">Verifică proiectul</a>
      </aside>
${ACTION_END}`;
}

function addAttributes(openingTag, attributes) {
  return openingTag.replace(/>$/, ` ${attributes}>`);
}

function locateRoot(html, route) {
  const pattern = route === "/"
    ? /<main\b[^>]*>/i
    : (/<main\b[^>]*>/i.test(html) ? /<main\b[^>]*>/i : /<div\b[^>]*class=["'][^"']*\bpost-container\b[^"']*["'][^>]*>/i);
  const match = pattern.exec(html);
  if (!match) throw new Error(`${route}: nu există container editorial principal.`);
  const variant = route === "/" ? "home" : "rail";
  const start = match.index;
  const contentStart = start + match[0].length;
  const contentEnd = route === "/" || match[0].toLowerCase().startsWith("<main")
    ? html.indexOf("</main>", contentStart)
    : html.indexOf("</body>", contentStart);
  if (contentEnd < 0) throw new Error(`${route}: containerul editorial nu are închidere.`);
  return { pattern, opening: match[0], start, contentStart, contentEnd, variant };
}

function insertToc(html, route, root, toc) {
  if (route !== "/") {
    const match = root.pattern.exec(html);
    if (!match) throw new Error(`${route}: containerul pentru cuprins a dispărut.`);
    const insertionPoint = match.index + match[0].length;
    return `${html.slice(0, insertionPoint)}\n${toc}\n    ${html.slice(insertionPoint).replace(/^\s*/, "")}`;
  }
  if (!/data-homepage-navbar-toc/i.test(html)) {
    throw new Error("home: cuprinsul trebuie să existe în navbar, nu ca secțiune separată în hero.");
  }
  return html;
}

function addAssets(html) {
  if (!/<\/head>/i.test(html)) throw new Error("Document fără </head>.");
  return html.replace(/[ \t\r\n]*<\/head>/i, `\n  ${CSS_LINK}\n  ${JS_LINK}\n</head>`);
}

function addBodyMetadata(html, type, words) {
  return html.replace(/<body\b[^>]*>/i, (tag) => addAttributes(tag, `data-long-form-page="true" data-long-form-type="${escapeHtml(type)}" data-long-form-word-count="${words}"`));
}

function synchronizePage(source, row, programByRoute) {
  if (/data-program-template-version=(?:"p1_11"|'p1_11')/i.test(source)) {
    const $ = cheerio.load(source, { decodeEntities: false });
    const route = normalizeRoute(row.route);
    const tocItems = $("[data-program-template-toc] [data-long-form-toc-link]");
    const words = countWords(removeInjected(source), route);
    return {
      html: source,
      report: {
        route,
        type: row.type,
        sourceFile: row.sourceFile,
        wordCount: words,
        tocItemCount: tocItems.length,
        tableCount: $("main .long-form-table-region table").length,
        variant: "rail",
        decisionActionAdded: $(".long-form-decision-action[data-program-template-section='cta']").length === 1,
        contentActionCount: $("main [data-analytics-event='cta_click']").length,
        managedBy: "program-page-template"
      }
    };
  }
  const clean = removeInjected(source);
  const route = normalizeRoute(row.route);
  const words = countWords(clean, route);
  const qualifies = CONFIG.forcedRoutes.includes(route) || (CONFIG.includedTypes.includes(row.type) && words > CONFIG.wordThreshold);
  if (!qualifies) return { html: clean, report: null };

  const $ = cheerio.load(clean, { decodeEntities: false });
  const pageTitle = $("h1").first().text().replace(/\s+/g, " ").trim() || route;
  const usedIds = new Set($("[id]").map((_, node) => $(node).attr("id")).get());
  const root = locateRoot(clean, route);
  const region = clean.slice(root.contentStart, root.contentEnd);
  const enhanced = enhanceRegion(region, pageTitle, usedIds);
  if (enhanced.items.length < 3) throw new Error(`${route}: prea puține secțiuni pentru cuprins (${enhanced.items.length}).`);

  let output = `${clean.slice(0, root.contentStart)}${enhanced.output}${clean.slice(root.contentEnd)}`;
  output = output.replace(root.pattern, (tag) => addAttributes(tag, `data-long-form-layout="${root.variant}" data-long-form-content="true"`));
  output = insertToc(output, route, root, renderToc(enhanced.items, root.variant));

  const program = programByRoute.get(route);
  if (row.type === "program" && program) {
    const decisionAnchor = output.includes("<!-- ANSWER_READINESS_END -->")
      ? "<!-- ANSWER_READINESS_END -->"
      : "<!-- PROGRAM_FACTUAL_STATUS_END -->";
    if (!output.includes(decisionAnchor)) throw new Error(`${route}: lipsește rezumatul decizional.`);
    const decisionIndex = output.indexOf(decisionAnchor) + decisionAnchor.length;
    output = `${output.slice(0, decisionIndex)}\n${renderDecisionAction(program)}\n${output.slice(decisionIndex).replace(/^\s*/, "")}`;
  }

  output = addBodyMetadata(output, row.type, words);
  output = addAssets(output);
  const after$ = cheerio.load(output, { decodeEntities: false });
  return {
    html: output,
    report: {
      route,
      type: row.type,
      sourceFile: row.sourceFile,
      wordCount: words,
      tocItemCount: enhanced.items.length,
      tableCount: enhanced.tableCount,
      variant: root.variant,
      decisionActionAdded: Boolean(row.type === "program" && program),
      contentActionCount: after$("main [data-analytics-event='cta_click'], .post-container [data-analytics-event='cta_click']").length
    }
  };
}

function buildReport(entries) {
  return {
    schemaVersion: 1,
    generatedFor: "P1.09",
    generatedAt: CONFIG.reportDate,
    wordThreshold: CONFIG.wordThreshold,
    pageCount: entries.length,
    byType: entries.reduce((result, entry) => {
      result[entry.type] = (result[entry.type] || 0) + 1;
      return result;
    }, {}),
    pilotRoute: CONFIG.pilotRoute,
    pages: entries
  };
}

function main() {
  if (!fs.existsSync(INVENTORY_PATH)) throw new Error(`Lipsește inventarul ${CONFIG.inventoryPath}.`);
  const inventory = JSON.parse(fs.readFileSync(INVENTORY_PATH, "utf8"));
  const rows = inventory.rows.filter((row) => CONFIG.forcedRoutes.includes(normalizeRoute(row.route)) || CONFIG.includedTypes.includes(row.type));
  const { programs } = loadProgramConfig();
  const programByRoute = new Map(programs.map((program) => [normalizeRoute(program.pageUrl), program]));
  const entries = [];
  const outOfSync = [];

  for (const row of rows) {
    const file = path.join(ROOT, row.sourceFile);
    if (!fs.existsSync(file)) throw new Error(`${row.route}: lipsește ${row.sourceFile}.`);
    const before = fs.readFileSync(file, "utf8");
    const result = synchronizePage(before, row, programByRoute);
    if (result.report) entries.push(result.report);
    if (result.html !== before) {
      if (CHECK_ONLY) outOfSync.push(row.sourceFile);
      else fs.writeFileSync(file, result.html, "utf8");
    }
  }

  entries.sort((left, right) => left.route.localeCompare(right.route, "ro"));
  const reportText = `${JSON.stringify(buildReport(entries), null, 2)}\n`;
  const currentReport = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
  if (reportText !== currentReport) {
    if (CHECK_ONLY) outOfSync.push(CONFIG.reportPath);
    else fs.writeFileSync(REPORT_PATH, reportText, "utf8");
  }

  if (CHECK_ONLY && outOfSync.length) throw new Error(`Layout lung nesincronizat: ${outOfSync.join(", ")}`);
  console.log(`Long-form layout ${CHECK_ONLY ? "PASS" : "sincronizat"}: ${entries.length} pagini peste prag, ${entries.reduce((sum, entry) => sum + entry.tocItemCount, 0)} ancore.`);
}

if (require.main === module) main();

module.exports = { CONFIG, countWords, removeInjected, synchronizePage };
