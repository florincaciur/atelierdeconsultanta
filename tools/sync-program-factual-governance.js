#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ROOT,
  archivedRobotsDecision,
  carouselPrograms,
  cofinancingSummaryText,
  fundingSummary,
  isPublicProgram,
  loadProgramConfig,
  programForRoute,
  programIndexes,
  programSummary,
  renderProgramFactualStatus,
  statusStatement
} = require("./program-factual-governance");

const REGISTRY_REF = "config/seo-programs.json#programs";
const FILES = Object.freeze({
  config: path.join(ROOT, "config", "seo-programs.json"),
  approvals: path.join(ROOT, "config", "program-status-approvals.json"),
  guides: path.join(ROOT, "official-guides.json"),
  banners: path.join(ROOT, "banners.json"),
  priority: path.join(ROOT, "config", "priority-pages.json"),
  snippets: path.join(ROOT, "config", "seo-snippets.json"),
  header: path.join(ROOT, "partials", "global-header.html"),
  homepage: path.join(ROOT, "index.html"),
  llms: path.join(ROOT, "llms.txt")
});

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function updateJsonFile(file, transform) {
  if (!fs.existsSync(file)) return null;
  const before = fs.readFileSync(file, "utf8");
  const value = JSON.parse(before);
  const after = jsonText(transform(value));
  return { file, before, after };
}

function syncSeoConfig(config, programs) {
  const byRoute = programIndexes(programs).byRoute;
  for (const page of config.pages || []) {
    if (page.redirectTo) continue;
    const program = byRoute.get(`/${page.slug}`);
    if (!program) continue;
    page.programId = program.id;
    page.factualGovernanceRef = `#/programs/${program.id}`;
    for (const key of ["programName", "title", "description", "funding", "programStatus", "applicationWindow", "quickAnswer", "cofinancingRows"]) {
      delete page[key];
    }
    page.sourceKeys = isPublicProgram(program) ? [...(program.officialGuideKeys || [])] : [];
  }
  return config;
}

function syncGuides(guides, programs) {
  for (const program of programs) {
    for (const key of program.officialGuideKeys || []) {
      if (!isPublicProgram(program)) delete guides[key];
    }
  }
  const programsByKey = new Map();
  for (const program of programs.filter(isPublicProgram)) {
    for (const key of program.officialGuideKeys || []) {
      if (!programsByKey.has(key)) programsByKey.set(key, []);
      programsByKey.get(key).push(program);
    }
  }
  for (const [key, linkedPrograms] of programsByKey) {
    const primary = linkedPrograms.find((program) => program.officialGuideKeys?.[0] === key) || linkedPrograms[0];
    guides[key] = {
      ...(typeof guides[key] === "object" ? guides[key] : {}),
      programIds: [...new Set(linkedPrograms.map((program) => program.id))],
      name: primary.sourceVersion,
      title: primary.sourceVersion,
      institution: primary.sourceName,
      url: primary.sourceUrl,
      accessedAt: primary.verifiedAt,
      programStatus: primary.status,
      statusLabel: primary.statusLabel,
      verifiedAt: primary.verifiedAt,
      isPrimaryFor: primary.id,
      sourceOfTruth: REGISTRY_REF
    };
    delete guides[key].sourceStatus;
    delete guides[key].reviewedAt;
  }
  return guides;
}

function syncBanners(banners, programs) {
  const existing = new Map((banners || []).filter((banner) => banner.programId).map((banner) => [banner.programId, banner]));
  return carouselPrograms(programs)
    .map((program) => {
      const previous = existing.get(program.id) || {};
      return {
        id: previous.id || `slide-${program.id}`,
        programId: program.id,
        title: program.name,
        tag: program.statusLabel,
        description: program.metaDescription,
        ctaText: previous.ctaText || "Detalii program",
        ctaLink: program.pageUrl,
        icon: program.presentation?.icon || previous.icon || "ph-file-text",
        image: program.presentation?.image || previous.image || null,
        pageTitle: program.presentation?.pageTitle || null,
        order: program.presentation.carouselOrder,
        estimate: program.presentation?.estimate || null,
        active: true,
        programStatus: program.status,
        statusLabel: program.statusLabel,
        verifiedAt: program.verifiedAt,
        sourceName: program.sourceName,
        sourceUrl: program.sourceUrl,
        sourceVersion: program.sourceVersion,
        applicationStart: program.applicationStart,
        applicationEnd: program.applicationEnd,
        grantSummary: program.grantSummary,
        cofinancingSummary: program.cofinancingSummary,
        fundingSummary: fundingSummary(program) || null,
        officialGuideKey: program.officialGuideKeys?.[0] || null,
        sourceOfTruth: REGISTRY_REF
      };
    });
}

function syncPriority(priority, programs) {
  for (const [key, page] of Object.entries(priority.pages || {})) {
    const program = programForRoute(page.route, programs);
    if (!program) continue;
    if (!isPublicProgram(program)) {
      delete priority.pages[key];
      continue;
    }
    page.programId = program.id;
    page.sourceOfTruth = REGISTRY_REF;
    page.publicationState = "public";
    page.directAnswer = programSummary(program);
    for (const fact of page.facts || []) {
      if (/finanț/iu.test(fact.term)) fact.description = fundingSummary(program) || "Registrul nu publică o valoare până când sursa oficială nu susține exact grantul.";
      if (/contribuț/iu.test(fact.term)) fact.description = cofinancingSummaryText(program) || "Registrul nu publică o cofinanțare până când sursa oficială nu susține exact valoarea.";
      if (/când se depune/iu.test(fact.term)) fact.description = program.applicationStart || program.applicationEnd
        ? `Perioada confirmată este ${program.applicationStart || "—"}–${program.applicationEnd || "—"}.`
        : program.statusLabel;
      if (/statut/iu.test(fact.term)) fact.description = statusStatement(program);
    }
    page.lastReviewed = program.verifiedAt;
    page.source = {
      document: program.sourceVersion,
      institution: program.sourceName,
      status: `${statusStatement(program)} ${program.editorialDisclaimer || ""}`.trim(),
      url: program.sourceUrl
    };
  }
  return priority;
}

function syncSnippets(snippets, programs) {
  const sourceRecords = Array.isArray(snippets) ? snippets : snippets.pages || snippets.routes || [];
  const records = sourceRecords.filter((item) => {
    const program = programForRoute(item.route, programs);
    return !program || isPublicProgram(program);
  });
  if (Array.isArray(snippets)) {
    snippets.splice(0, snippets.length, ...records);
  } else if (Array.isArray(snippets.pages)) {
    snippets.pages = records;
  } else if (Array.isArray(snippets.routes)) {
    snippets.routes = records;
  }
  for (const item of records) {
    const program = programForRoute(item.route, programs);
    if (!program) continue;
    item.title = program.metaTitle;
    item.description = program.metaDescription;
    item.ogTitle = program.metaTitle;
    item.ogDescription = program.metaDescription;
    item.sourceOfTruth = isPublicProgram(program) ? [REGISTRY_REF, program.sourceUrl] : [REGISTRY_REF];
    item.publicationState = program.publicationState;
    if (isPublicProgram(program)) {
      item.programStatus = program.status;
      item.statusLabel = program.statusLabel;
      item.lastReviewed = program.verifiedAt;
    } else {
      delete item.factualStatus;
      delete item.programStatus;
      delete item.statusLabel;
      delete item.lastReviewed;
    }
  }
  return snippets;
}

function syncHeaderText(source, programs) {
  const $ = cheerio.load(source, { decodeEntities: false }, false);
  $("#navbar").attr("data-program-registry", REGISTRY_REF).removeAttr("data-factual-governance");
  for (const program of programs) {
    const anchors = $(`a[href="${program.pageUrl}"]`);
    anchors.each((_, element) => {
      const anchor = $(element);
      const inProgramMenu = anchor.hasClass("dropdown-item") || anchor.closest("#mobileMenu").length;
      if (!inProgramMenu) return;
      if (!isPublicProgram(program)) {
        anchor.remove();
        return;
      }
      anchor
        .attr("data-program-id", program.id)
        .attr("data-program-status", program.status)
        .attr("data-status-label", program.statusLabel)
        .attr("data-verified-at", program.verifiedAt)
        .attr("data-source-url", program.sourceUrl)
        .removeAttr("data-source-status")
        .removeAttr("data-reviewed-at");
      if (anchor.hasClass("dropdown-item")) {
        const text = anchor.find(".d-text").first();
        const firstText = text.contents().filter((__, node) => node.type === "text").first();
        if (firstText.length) firstText[0].data = program.shortName;
        else text.prepend(program.shortName);
        text.find(".d-label").first().text(program.statusLabel);
      } else {
        anchor.text(program.shortName);
      }
    });
  }
  return $.root().html();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function homepageHeroList(programs) {
  return programs
    .filter((program) => isPublicProgram(program) && program.presentation?.hero)
    .sort((left, right) => (left.presentation?.order || 999) - (right.presentation?.order || 999))
    .map((program, index) => `              <li><a href="${escapeHtml(program.pageUrl)}" data-hero-program-item data-program-id="${escapeHtml(program.id)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" data-status="${escapeHtml(program.statusLabel)}" data-title="${escapeHtml(program.shortName)}" data-desc="${escapeHtml(program.cardSummary)}"${index === 0 ? " aria-current=\"true\"" : ""}><span class="hp-name">${escapeHtml(program.shortName)}</span><span class="hp-tag">${escapeHtml(program.statusLabel)}</span></a></li>`)
    .join("\n");
}

function renderHomepageSlide(program) {
  const image = program.presentation?.image || (/afir|agricultur/i.test(program.family) ? "/assets/hero/hero-agriculture.webp" : "/assets/hero/hero-business.webp");
  const funding = fundingSummary(program);
  return `<article class="program-slide hero hero--image is-active" style="--hero-image:url('${escapeHtml(image)}')" data-slide-id="slide-${escapeHtml(program.id)}" data-program-id="${escapeHtml(program.id)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" aria-hidden="false">
              <span class="hero-icon" aria-hidden="true"><i class="ph-duotone ${escapeHtml(program.presentation?.icon || "ph-file-text")}"></i></span>
              <span class="eyebrow">${escapeHtml(program.statusLabel)}</span>
              <h3>${escapeHtml(program.name)}</h3>
              <p>${escapeHtml(program.cardSummary)}</p>
              ${funding ? `<p data-program-funding>${escapeHtml(funding)}</p>` : "<!-- grantSummary=null; nicio valoare publicată -->"}
              <p class="program-source-meta">Verificat la <time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(program.verifiedAt)}</time>.</p>
              <div class="hero-actions">
                <a class="btn btn-primary" href="${escapeHtml(program.pageUrl)}">Detalii program →</a>
                <a class="btn btn-secondary" href="${escapeHtml(program.sourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="official_source" data-analytics-cta-id="source_document" data-analytics-target="${escapeHtml(program.sourceUrl)}">${escapeHtml(program.sourceVersion)}</a>
              </div>
            </article>`;
}

function syncHomepageCard(fragment, programs) {
  const $ = cheerio.load(fragment, { decodeEntities: false }, false);
  const card = $("article.finantare-card").first();
  const route = card.find(".finantare-actions a[href^='/']").first().attr("href");
  const program = programForRoute(route, programs);
  if (!program || !isPublicProgram(program)) return "";
  card
    .attr("data-program-id", program.id)
    .attr("data-program-status", program.status)
    .attr("data-status-label", program.statusLabel)
    .attr("data-verified-at", program.verifiedAt)
    .attr("data-source-url", program.sourceUrl);
  card.find(".finantare-badge").text(program.statusLabel).removeClass("badge-active badge-planning").addClass(program.status === "apel_deschis" ? "badge-active" : "badge-planning");
  card.find(".finantare-title").text(program.shortName);
  const funding = fundingSummary(program);
  if (funding) card.find(".finantare-amount").text(funding).attr("data-program-funding", "");
  else card.find(".finantare-amount").remove();
  const description = card.children("p").filter((_, element) => !$(element).hasClass("finantare-amount")).first();
  description.text(program.cardSummary);
  const actions = card.find(".finantare-actions");
  actions.find("a").first().attr("href", program.pageUrl).text("Detalii program");
  const source = actions.find("a").eq(1);
  source
    .attr("href", program.sourceUrl)
    .attr("target", "_blank")
    .attr("rel", "noopener noreferrer")
    .attr("data-analytics-event", "source_document_click")
    .attr("data-analytics-component", "official_source")
    .attr("data-analytics-cta-id", "source_document")
    .attr("data-analytics-target", program.sourceUrl)
    .text(program.sourceVersion);
  return $.html(card);
}

function syncHomepageText(source, programs) {
  const heroPrograms = programs
    .filter((program) => isPublicProgram(program) && program.presentation?.hero)
    .sort((left, right) => (left.presentation?.order || 999) - (right.presentation?.order || 999));
  const carouselPrograms = programs
    .filter((program) => isPublicProgram(program) && program.presentation?.carousel)
    .sort((left, right) => (left.presentation?.order || 999) - (right.presentation?.order || 999));
  let output = source.replace(
    /<ul\b[^>]*class="[^"]*\bhero-programs-list\b[^"]*"[^>]*>[\s\S]*?<\/ul>/,
    `<ul class="hero-programs-list" aria-label="Alege o măsură de finanțare" data-program-registry="${REGISTRY_REF}">\n${homepageHeroList(programs)}\n            </ul>`
  );
  if (heroPrograms.length) {
    const first = heroPrograms[0];
    output = output
      .replace(/(<span class="hero-program-eyebrow"[^>]*>)[\s\S]*?(<\/span>)/, `$1${escapeHtml(first.statusLabel)}$2`)
      .replace(/(<h3 data-hero-program-title[^>]*>)[\s\S]*?(<\/h3>)/, `$1${escapeHtml(first.shortName)}$2`)
      .replace(/(<p data-hero-program-desc[^>]*>)[\s\S]*?(<\/p>)/, `$1${escapeHtml(first.cardSummary)}$2`)
      .replace(/(<a class="hero-program-link"[^>]*href=")[^"]*("[^>]*>)/, `$1${escapeHtml(first.pageUrl)}$2`)
      .replace(/(<span class="hero-program-count"[^>]*>)[\s\S]*?(<\/span>)/, `$11 / ${heroPrograms.length}$2`);
  }
  output = output.replace(/<article class="finantare-card[\s\S]*?<\/article>/g, (fragment) => syncHomepageCard(fragment, programs));
  if (carouselPrograms.length) {
    output = output.replace(
      /(<div class="program-carousel-track"[^>]*>)[\s\S]*?(<\/article>\s*<\/div>)/,
      `$1\n            ${renderHomepageSlide(carouselPrograms[0])}\n          </div>`
    );
  }
  output = output.replace(
    /function getProgramFallbackBanners\(\) \{[\s\S]*?\n    function getHeroImageForBanner/,
    "function getProgramFallbackBanners() { return []; }\n\n    function getHeroImageForBanner"
  );
  output = output.replace("if (!activeBanners.length) activeBanners = getProgramFallbackBanners();", "if (!activeBanners.length) return;");
  output = output.replace("renderProgramCarousel(getProgramFallbackBanners(), {});", "track.setAttribute('data-registry-load-error', 'true');");
  return output;
}

function syncLlmsText(source, programs) {
  const markerStart = "<!-- PROGRAM_FACTUAL_GOVERNANCE_START -->";
  const markerEnd = "<!-- PROGRAM_FACTUAL_GOVERNANCE_END -->";
  const markerPattern = new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}`);
  let output = source.replace(markerPattern, "").replace(/\s+$/g, "");
  for (const program of programs) {
    const escaped = `https://atelierdeconsultanta.ro${program.pageUrl}`.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    output = output.replace(new RegExp(`^[-*] [^\\r\\n]*${escaped}(?=[)\\s]|$)[^\\r\\n]*(?:\\r?\\n  [^\\r\\n]*)?\\r?\\n?`, "gm"), "");
  }
    const entries = programs
      .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget)
    .map((program) => `- [${program.shortName}](https://atelierdeconsultanta.ro${program.pageUrl})\n  ${program.shortName} — ${program.statusLabel}. ${program.editorialDisclaimer || ""}`)
    .join("\n\n");
    const latest = programs
      .filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget)
      .reduce((value, program) => program.verifiedAt > value ? program.verifiedAt : value, "0000-00-00");
  const block = `${markerStart}\n## Guvernanță factuală a programelor\n\n- Sursa unică de adevăr: ${REGISTRY_REF}.\n- Statusurile și valorile nu sunt deduse din URL-uri sau din texte editoriale locale.\n- Înregistrările pending_validation sunt excluse din suprafețele publice.\n- Ultima verificare din registrul public: ${latest}\n\n${entries}\n${markerEnd}`;
  return `${output}\n\n${block}\n`;
}

function replaceTagAttribute(tag, attribute, value) {
  const escaped = escapeHtml(value);
  const pattern = new RegExp(`\\s${attribute}=(?:"[^"]*"|'[^']*')`, "i");
  if (pattern.test(tag)) return tag.replace(pattern, ` ${attribute}="${escaped}"`);
  return tag.replace(/\s*\/?>(?=$)/, (ending) => ` ${attribute}="${escaped}"${ending}`);
}

function removeTagAttribute(tag, attribute) {
  return tag.replace(new RegExp(`\\s${attribute}=(?:"[^"]*"|'[^']*')`, "gi"), "");
}

function replaceMeta(html, selectorPattern, value) {
  return html.replace(selectorPattern, (tag) => replaceTagAttribute(tag, "content", value));
}

function pendingMain(program) {
  return `<main class="container program-validation-hold" id="main-content" tabindex="-1" data-program-id="${escapeHtml(program.id)}" data-publication-state="pending_validation">
  <article class="panel">
    ${renderProgramFactualStatus(program)}
    <h1>${escapeHtml(program.shortName)}</h1>
    <p>${escapeHtml(program.cardSummary)}</p>
    <p>Responsabilul editorial trebuie să confirme statutul, documentul oficial și data verificării înainte de republicare.</p>
    <p><a href="/contact" data-analytics-event="cta_click" data-analytics-component="contact_cta" data-analytics-cta-id="contact_page" data-analytics-target="/contact">Contact FABER</a></p>
  </article>
</main>`;
}

function restoredPublicMain(program) {
  return `<main class="container program-page" id="main-content" tabindex="-1" data-program-id="${escapeHtml(program.id)}" data-publication-state="public">
  <article class="panel">
    ${renderProgramFactualStatus(program)}
    <h1>${escapeHtml(program.name)}</h1>
    <p>${escapeHtml(program.cardSummary)}</p>
    <p>${escapeHtml(program.editorialDisclaimer)}</p>
    <p><a href="${escapeHtml(program.sourceUrl)}" target="_blank" rel="noopener noreferrer">Consultă documentul oficial</a></p>
    <p><a href="/contact#program=${escapeHtml(program.slug)}" data-analytics-event="cta_click" data-analytics-component="program_page" data-analytics-cta-id="program_project_check" data-analytics-program-category="${escapeHtml(program.slug)}">Verifică încadrarea proiectului</a></p>
  </article>
</main>`;
}

function syncProgramHtml(source, program) {
  let output = source;
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const templateMode = /data-program-template-version=(?:"[^"]+"|'[^']+')/i.test(source);
  output = output.replace(/<title>[^<]*<\/title>/i, `<title>${escapeHtml(program.metaTitle)}</title>`);
  output = replaceMeta(output, /<meta\b[^>]*\bname=["']description["'][^>]*>/i, program.metaDescription);
  output = replaceMeta(output, /<meta\b[^>]*\bproperty=["']og:title["'][^>]*>/i, program.metaTitle);
  output = replaceMeta(output, /<meta\b[^>]*\bproperty=["']og:description["'][^>]*>/i, program.metaDescription);
  output = output.replace(/<body\b[^>]*>/i, (tag) => {
    let next = tag;
    if (!templateMode) {
      for (const attribute of ["data-source-status", "data-reviewed-at", "data-factual-governance", "data-program-registry", "data-program-status", "data-status-label", "data-verified-at", "data-source-url", "data-publication-state"]) {
        next = removeTagAttribute(next, attribute);
      }
    }
    next = replaceTagAttribute(next, "data-program-id", program.id);
    next = replaceTagAttribute(next, "data-publication-state", program.publicationState);
    next = replaceTagAttribute(next, "data-program-registry", REGISTRY_REF);
    if (isPublicProgram(program)) {
      next = replaceTagAttribute(next, "data-program-status", program.status);
      next = replaceTagAttribute(next, "data-status-label", program.statusLabel);
      next = replaceTagAttribute(next, "data-verified-at", program.verifiedAt);
      next = replaceTagAttribute(next, "data-source-url", program.sourceUrl);
    }
    return next;
  });
  if (!isPublicProgram(program)) {
    output = replaceMeta(output, /<meta\b[^>]*\bname=["']robots["'][^>]*>/i, "noindex, follow");
    output = output.replace(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/gi, "");
    output = output.replace(/<!-- PROGRAM_HERO_START -->[\s\S]*?<!-- PROGRAM_HERO_END -->/i, "");
    output = output.replace(/<header\b[^>]*class=["'][^"']*\bhero\b[^"']*["'][^>]*>[\s\S]*?<\/header>/i, "");
    output = output.replace(/<div\b[^>]*class=["'][^"']*\bbreadcrumb\b[^"']*["'][^>]*>[\s\S]*?<\/div>/i, "");
    const main = pendingMain(program).replace(/\r?\n/g, eol);
    if (/<main\b[^>]*>[\s\S]*?<\/main>/i.test(output)) output = output.replace(/<main\b[^>]*>[\s\S]*?<\/main>/i, main);
    else output = output.replace(/<body\b[^>]*>/i, (tag) => `${tag}${eol}${main}`);
    return output;
  }
  if (/<main\b[^>]*\bprogram-validation-hold\b[^>]*>[\s\S]*?<\/main>/i.test(output)) {
    output = output.replace(/<main\b[^>]*\bprogram-validation-hold\b[^>]*>[\s\S]*?<\/main>/i, restoredPublicMain(program).replace(/\r?\n/g, eol));
  }
  const archivedRobots = archivedRobotsDecision(program);
  output = replaceMeta(output, /<meta\b[^>]*\bname=["']robots["'][^>]*>/i, archivedRobots || "index, follow");
  if (!/<script\b[^>]*type=["']application\/ld\+json["']/i.test(output) && /<\/head>/i.test(output)) {
    output = output.replace(/<\/head>/i, '  <script type="application/ld+json">{"@context":"https://schema.org","@graph":[]}</script>\n</head>');
  }
  if (/<!-- PROGRAM_HERO_START -->[\s\S]*?<h1\b/iu.test(output)) {
    output = output.replace(/(<article\b[^>]*>[\s\S]*?)<h1(\b[^>]*)>([\s\S]*?)<\/h1>/iu, "$1<h2$2>$3</h2>");
  }
  const factualMode = templateMode ? "template-header" : "default";
  const block = renderProgramFactualStatus(program, { mode: factualMode }).replace(/\r?\n/g, eol);
  const marked = /<!-- PROGRAM_FACTUAL_STATUS_START -->[\s\S]*?<!-- PROGRAM_FACTUAL_STATUS_END -->/;
  if (marked.test(output)) return output.replace(marked, block);
  if (/<article\b[^>]*>/i.test(output)) return output.replace(/<article\b[^>]*>/i, (tag) => `${tag}${eol}${block}`);
  if (/<main\b[^>]*>/i.test(output)) return output.replace(/<main\b[^>]*>/i, (tag) => `${tag}${eol}${block}`);
  return output;
}

function filesForRoute(route) {
  const slug = String(route || "").replace(/^\/+|\/+$/g, "");
  if (!slug) return [path.join(ROOT, "index.html")];
  return [path.join(ROOT, slug, "index.html"), path.join(ROOT, `${slug}.html`)];
}

function programHtmlUpdates(programs, approvalConfig = { programs: [] }) {
  const updates = [];
  const seen = new Set();
  const holdsByProgram = new Map((approvalConfig.programs || []).map((row) => [row.programId, row]));
  for (const program of programs) {
    const approval = holdsByProgram.get(program.id);
    const routes = new Set([program.pageUrl]);
    if (!isPublicProgram(program) && approval?.approvalState === "pending") {
      for (const route of approval.publicationHoldUrls || []) routes.add(route);
    }
    for (const file of [...routes].flatMap(filesForRoute)) {
      if (seen.has(file) || !fs.existsSync(file)) continue;
      seen.add(file);
      const before = fs.readFileSync(file, "utf8");
      const withoutPendingSurfaces = syncPendingProgramSurfaces(before, programs);
      updates.push({ file, before, after: syncProgramHtml(withoutPendingSurfaces, program) });
    }
  }
  return updates;
}

function allHtmlFiles(directory = ROOT) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "dist", "node_modules"].includes(entry.name)) continue;
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...allHtmlFiles(file));
    else if (entry.isFile() && entry.name.endsWith(".html")) files.push(file);
  }
  return files;
}

function syncPendingProgramSurfaces(source, programs) {
  const pending = programs.filter((program) => !isPublicProgram(program));
  if (!pending.length) return source;
  const $ = cheerio.load(source, { decodeEntities: false });
  let changed = false;
  for (const program of pending) {
    const idSelector = `[data-program-id="${program.id}"]`;
    $(idSelector).each((_, element) => {
      const item = $(element);
      if (item.is("body, main.program-validation-hold") || item.closest("main.program-validation-hold").length) return;
      const removable = item.is("article, li, tr, a") ? item : item.closest("article, li, tr");
      if (removable.length) {
        removable.first().remove();
        changed = true;
      }
    });
    const route = program.pageUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const hrefPattern = new RegExp(`^(?:https://atelierdeconsultanta\\.ro)?${route}/?$`, "i");
    $("a[href]").each((_, element) => {
      const anchor = $(element);
      if (!hrefPattern.test(anchor.attr("href") || "")) return;
      if (anchor.closest("main.program-validation-hold").length) return;
      if (anchor.closest("nav, footer").length) {
        anchor.remove();
        changed = true;
        return;
      }
      const component = anchor.closest("article.finantare-card, article.program-slide, article.core-card, article.content-card, .hero-programs-list li");
      if (component.length) component.first().remove();
      else if (anchor.closest(".related-links").length) anchor.remove();
      else return;
      changed = true;
    });
  }
  return changed ? $.html() : source;
}

function programHandledFiles(programs, approvalConfig = { programs: [] }) {
  const files = new Set();
  const approvalById = new Map((approvalConfig.programs || []).map((row) => [row.programId, row]));
  for (const program of programs) {
    const routes = new Set([program.pageUrl]);
    const approval = approvalById.get(program.id);
    if (!isPublicProgram(program) && approval?.approvalState === "pending") {
      for (const route of approval.publicationHoldUrls || []) routes.add(route);
    }
    for (const file of [...routes].flatMap(filesForRoute)) files.add(file);
  }
  return files;
}

function pendingSurfaceUpdates(programs, approvalConfig = { programs: [] }) {
  const excluded = programHandledFiles(programs, approvalConfig);
  excluded.add(FILES.header);
  excluded.add(FILES.homepage);
  return allHtmlFiles().filter((file) => !excluded.has(file)).map((file) => {
    const before = fs.readFileSync(file, "utf8");
    return { file, before, after: syncPendingProgramSurfaces(before, programs) };
  });
}

function textUpdate(file, transform) {
  if (!fs.existsSync(file)) return null;
  const before = fs.readFileSync(file, "utf8");
  return { file, before, after: transform(before) };
}

function main() {
  const check = process.argv.includes("--check");
  const { config, programs } = loadProgramConfig();
  const approvalConfig = fs.existsSync(FILES.approvals) ? JSON.parse(fs.readFileSync(FILES.approvals, "utf8")) : { programs: [] };
  const updates = [
    { file: FILES.config, before: fs.readFileSync(FILES.config, "utf8"), after: jsonText(syncSeoConfig(config, programs)) },
    updateJsonFile(FILES.guides, (value) => syncGuides(value, programs)),
    updateJsonFile(FILES.banners, (value) => syncBanners(value, programs)),
    updateJsonFile(FILES.priority, (value) => syncPriority(value, programs)),
    updateJsonFile(FILES.snippets, (value) => syncSnippets(value, programs)),
    // Headerul și homepage-ul au generatoare dedicate care consumă același
    // registry. Nu le reserializăm aici, deoarece cele două ownership-uri ar
    // produce outputs concurente pentru aceleași componente.
    textUpdate(FILES.llms, (value) => syncLlmsText(value, programs)),
    ...pendingSurfaceUpdates(programs, approvalConfig),
    ...programHtmlUpdates(programs, approvalConfig)
  ].filter(Boolean);
  const changed = updates.filter((update) => update.before !== update.after);
  for (const update of changed) {
    const relative = path.relative(ROOT, update.file).split(path.sep).join("/");
    console.log(`${check ? "OUTDATED" : "SYNC"} ${relative}`);
    if (!check) fs.writeFileSync(update.file, update.after, "utf8");
  }
  const publicCount = programs.filter(isPublicProgram).length;
  console.log(`${programs.length} programe validate (${publicCount} publice); ${changed.length} consumatori ${check ? "nesincronizați" : "actualizați"}.`);
  if (check && changed.length) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = {
  FILES,
  renderHomepageSlide,
  syncBanners,
  syncGuides,
  syncHeaderText,
  syncHomepageText,
  syncLlmsText,
  syncPendingProgramSurfaces,
  syncPriority,
  syncProgramHtml,
  syncSeoConfig,
  syncSnippets
};
