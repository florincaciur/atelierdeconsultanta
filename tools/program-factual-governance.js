"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const HUMAN_REVIEW = "DE_VALIDAT_UMAN";
const PROGRAM_STATUSES = Object.freeze([
  "apel_deschis",
  "ghid_aprobat_nedeschis",
  "consultare_publica",
  "calendar_estimativ",
  "apel_inchis",
  "arhivat"
]);
const SOURCE_STATUSES = PROGRAM_STATUSES;
const ACTIVE_STATUSES = new Set(["apel_deschis"]);
const PUBLICATION_STATES = Object.freeze(["public", "pending_validation"]);
const REQUIRED_FIELDS = Object.freeze([
  "slug",
  "name",
  "shortName",
  "family",
  "status",
  "statusLabel",
  "publicationState",
  "verifiedAt",
  "sourceName",
  "sourceUrl",
  "sourceVersion",
  "applicationStart",
  "applicationEnd",
  "grantSummary",
  "cofinancingSummary",
  "pageUrl",
  "lastMeaningfulUpdate",
  "evergreenValue",
  "archivedNoindexDecision"
]);
const LEGACY_FIELDS = Object.freeze([
  "id",
  "route",
  "officialName",
  "authority",
  "officialSourceUrl",
  "sourceDocumentName",
  "sourceStatus",
  "reviewedAt",
  "maximumGrant",
  "minimumGrant",
  "intensity",
  "ownContribution",
  "budget",
  "menuLabel",
  "menuSecondaryLabel",
  "factualDisclaimer"
]);
const DEFAULT_STATUS_LABELS = Object.freeze({
  apel_deschis: "Apel deschis",
  ghid_aprobat_nedeschis: "Ghid aprobat – depunerea nu este deschisă",
  consultare_publica: "Consultare publică – depunerea nu este deschisă",
  calendar_estimativ: "Calendar estimativ – depunerea nu este confirmată",
  apel_inchis: "Apel închis",
  arhivat: "Arhivat"
});

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function normalizeRoute(value) {
  const raw = String(value || "/").trim();
  const route = raw.startsWith("http") ? new URL(raw).pathname : raw;
  if (route === "/") return route;
  return `/${route.replace(/^\/+|\/+$/g, "")}`;
}

function isIsoDate(value, { nullable = true } = {}) {
  if (value === null) return nullable;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) return false;
  return !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function isPending(value) {
  return String(value || "").trim() === HUMAN_REVIEW;
}

function isOfficialUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function isPublicProgram(program) {
  return program?.publicationState === "public";
}

function hasOfficialSource(program) {
  return program?.sourceType === "official"
    && isOfficialUrl(program?.sourceUrl)
    && !isPending(program?.sourceUrl)
    && Boolean(String(program?.sourceName || "").trim())
    && !isPending(program?.sourceName)
    && Boolean(String(program?.sourceVersion || "").trim())
    && !isPending(program?.sourceVersion)
    && isIsoDate(program?.verifiedAt, { nullable: false });
}

function summaryHasValues(summary) {
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) return false;
  return Object.values(summary).some((value) => {
    if (value === null || value === undefined || value === "") return false;
    if (Array.isArray(value)) return value.length > 0;
    return true;
  });
}

function validateProgram(program, index = -1) {
  const errors = [];
  const location = index >= 0 ? `programs[${index}]` : `program ${program?.slug || "necunoscut"}`;
  if (!program || typeof program !== "object" || Array.isArray(program)) return [`${location}: înregistrare invalidă`];
  for (const field of REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(program, field)) errors.push(`${location}: lipsește câmpul ${field}`);
  }
  for (const field of LEGACY_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(program, field)) errors.push(`${location}: câmpul legacy ${field} este interzis; folosește schema registrului unic`);
  }
  for (const field of ["slug", "name", "shortName", "family", "statusLabel", "sourceName", "sourceUrl", "sourceVersion", "pageUrl"]) {
    if (!String(program[field] ?? "").trim()) errors.push(`${location}: ${field} nu poate fi gol`);
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(program.slug || ""))) errors.push(`${location}: slug invalid (${program.slug})`);
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(program.family || ""))) errors.push(`${location}: family invalid (${program.family})`);
  if (!PROGRAM_STATUSES.includes(program.status)) errors.push(`${location}: status invalid (${program.status})`);
  if (!PUBLICATION_STATES.includes(program.publicationState)) errors.push(`${location}: publicationState invalid (${program.publicationState})`);
  if (normalizeRoute(program.pageUrl) !== program.pageUrl) errors.push(`${location}: pageUrl nu este canonic (${program.pageUrl})`);
  for (const field of ["applicationStart", "applicationEnd"]) {
    if (!isIsoDate(program[field]) && !isPending(program[field])) errors.push(`${location}: ${field} trebuie să fie dată ISO, null sau ${HUMAN_REVIEW}`);
  }
  if (!isIsoDate(program.lastMeaningfulUpdate) && !isPending(program.lastMeaningfulUpdate)) {
    errors.push(`${location}: lastMeaningfulUpdate trebuie să fie dată ISO, null sau ${HUMAN_REVIEW}`);
  }
  if (program.applicationStart && program.applicationEnd && isIsoDate(program.applicationStart) && isIsoDate(program.applicationEnd) && program.applicationStart > program.applicationEnd) {
    errors.push(`${location}: applicationStart nu poate fi după applicationEnd`);
  }
  if (program.status === "apel_deschis" && (!isIsoDate(program.applicationStart, { nullable: false }) || !isIsoDate(program.applicationEnd, { nullable: false }))) {
    errors.push(`${location}: un apel_deschis trebuie să aibă applicationStart și applicationEnd confirmate`);
  }
  if (program.grantSummary !== null && (typeof program.grantSummary !== "object" || Array.isArray(program.grantSummary))) {
    errors.push(`${location}: grantSummary trebuie să fie obiect sau null`);
  }
  if (program.cofinancingSummary !== null && (typeof program.cofinancingSummary !== "object" || Array.isArray(program.cofinancingSummary))) {
    errors.push(`${location}: cofinancingSummary trebuie să fie obiect sau null`);
  }
  if (isPublicProgram(program)) {
    if (!hasOfficialSource(program)) errors.push(`${location}: un program public trebuie să aibă verifiedAt, sourceUrl, sourceName și sourceVersion oficiale`);
    if ([program.verifiedAt, program.sourceName, program.sourceUrl, program.sourceVersion].some(isPending)) {
      errors.push(`${location}: un program public nu poate conține ${HUMAN_REVIEW} în metadatele sursei`);
    }
    if ((summaryHasValues(program.grantSummary) || summaryHasValues(program.cofinancingSummary)) && !hasOfficialSource(program)) {
      errors.push(`${location}: valorile numerice nu au o sursă oficială completă`);
    }
  } else {
    if (program.grantSummary !== null || program.cofinancingSummary !== null || program.applicationStart !== null || program.applicationEnd !== null) {
      errors.push(`${location}: o înregistrare pending_validation nu poate furniza public date sau valori factuale`);
    }
    if (!program.pendingValidation || !Array.isArray(program.pendingValidation.requestedFields)) {
      errors.push(`${location}: pending_validation necesită o listă explicită pendingValidation.requestedFields`);
    }
  }
  if (typeof program.evergreenValue !== "boolean") errors.push(`${location}: evergreenValue trebuie să fie boolean`);
  if (![null, "index", "noindex"].includes(program.archivedNoindexDecision)) errors.push(`${location}: archivedNoindexDecision invalid`);
  if (program.status !== "arhivat" && program.archivedNoindexDecision === "noindex") {
    errors.push(`${location}: noindex editorial este permis prin acest câmp numai pentru status=arhivat`);
  }
  if (program.status === "arhivat" && program.archivedNoindexDecision === "noindex" && program.evergreenValue !== false) {
    errors.push(`${location}: un program arhivat cu valoare evergreen nu poate primi automat noindex`);
  }
  if (!Array.isArray(program.eligibleApplicants)) errors.push(`${location}: eligibleApplicants trebuie să fie listă`);
  if (!Array.isArray(program.keyConditions)) errors.push(`${location}: keyConditions trebuie să fie listă`);
  if (!Array.isArray(program.officialGuideKeys)) errors.push(`${location}: officialGuideKeys trebuie să fie listă`);
  return errors;
}

function defineAlias(program, name, getter) {
  if (Object.prototype.hasOwnProperty.call(program, name)) return;
  Object.defineProperty(program, name, { configurable: true, enumerable: false, get: getter });
}

function decorateProgram(program) {
  defineAlias(program, "id", () => program.slug);
  defineAlias(program, "route", () => program.pageUrl);
  defineAlias(program, "officialName", () => program.name);
  defineAlias(program, "authority", () => program.sourceName);
  defineAlias(program, "officialSourceUrl", () => program.sourceUrl);
  defineAlias(program, "sourceDocumentName", () => program.sourceVersion);
  defineAlias(program, "sourceStatus", () => program.status);
  defineAlias(program, "reviewedAt", () => program.verifiedAt);
  defineAlias(program, "maximumGrant", () => program.grantSummary?.maximum ?? null);
  defineAlias(program, "minimumGrant", () => program.grantSummary?.minimum ?? null);
  defineAlias(program, "budget", () => program.grantSummary?.budget ?? null);
  defineAlias(program, "intensity", () => program.cofinancingSummary?.intensity ?? null);
  defineAlias(program, "ownContribution", () => program.cofinancingSummary?.ownContribution ?? null);
  defineAlias(program, "menuLabel", () => program.shortName);
  defineAlias(program, "menuSecondaryLabel", () => program.statusLabel);
  defineAlias(program, "factualDisclaimer", () => program.editorialDisclaimer || "");
  return program;
}

function loadProgramConfig(file = CONFIG_PATH) {
  const config = readJson(file);
  const rawPrograms = Array.isArray(config.programs) ? config.programs : [];
  const errors = rawPrograms.flatMap(validateProgram);
  const slugs = new Set();
  const routes = new Set();
  for (const program of rawPrograms) {
    if (slugs.has(program.slug)) errors.push(`slug duplicat: ${program.slug}`);
    if (routes.has(program.pageUrl)) errors.push(`pageUrl duplicat: ${program.pageUrl}`);
    slugs.add(program.slug);
    routes.add(program.pageUrl);
  }
  if (errors.length) throw new Error(`Registrul factual este invalid:\n- ${errors.join("\n- ")}`);
  const programs = rawPrograms.map(decorateProgram);
  return { config, programs, publicPrograms: programs.filter(isPublicProgram) };
}

function programIndexes(programs = loadProgramConfig().programs) {
  return {
    byId: new Map(programs.map((program) => [program.slug, program])),
    byRoute: new Map(programs.map((program) => [normalizeRoute(program.pageUrl), program]))
  };
}

function programForRoute(route, programs) {
  return programIndexes(programs).byRoute.get(normalizeRoute(route)) || null;
}

function programForPage(page, programs) {
  const indexes = programIndexes(programs);
  if (page?.programId && indexes.byId.has(page.programId)) return indexes.byId.get(page.programId);
  return indexes.byRoute.get(normalizeRoute(`/${page?.slug || ""}`)) || null;
}

function formatNumber(value) {
  if (!Number.isFinite(Number(value))) return "";
  return new Intl.NumberFormat("ro-RO", { maximumFractionDigits: 2 }).format(Number(value));
}

function formatMoneyValue(value) {
  if (!value || typeof value !== "object") return "";
  const currency = String(value.currency || "EUR");
  if (Array.isArray(value.variants) && value.variants.length) {
    return value.variants
      .map((variant) => `${formatNumber(variant.amount)} ${currency}${variant.scope ? ` (${variant.scope})` : ""}`)
      .join(" / ");
  }
  if (!Number.isFinite(Number(value.amount))) return "";
  return `${formatNumber(value.amount)} ${currency}${value.unit ? `/${value.unit}` : ""}`;
}

function formatIntensity(value) {
  if (!Array.isArray(value) || !value.length) return "";
  return value.map((item) => `${formatNumber(item.rate)}%${item.scope ? ` (${item.scope})` : ""}`).join(" / ");
}

function grantSummaryText(program) {
  if (!isPublicProgram(program) || !summaryHasValues(program.grantSummary)) return "";
  const minimum = formatMoneyValue(program.grantSummary.minimum);
  const maximum = formatMoneyValue(program.grantSummary.maximum);
  const budget = formatMoneyValue(program.grantSummary.budget);
  const range = minimum && maximum && !maximum.includes(" / ") ? `${minimum}–${maximum}` : (maximum || minimum);
  return [range, budget ? `buget ${budget}` : ""].filter(Boolean).join("; ");
}

function cofinancingSummaryText(program) {
  if (!isPublicProgram(program) || !summaryHasValues(program.cofinancingSummary)) return "";
  const intensity = formatIntensity(program.cofinancingSummary.intensity);
  const ownContribution = String(program.cofinancingSummary.ownContribution || "").trim();
  return [intensity ? `intensitate ${intensity}` : "", ownContribution].filter(Boolean).join("; ");
}

function fundingSummary(program) {
  if (!isPublicProgram(program)) return "";
  const facts = [grantSummaryText(program), cofinancingSummaryText(program)].filter(Boolean).join("; ");
  if (!facts) return "";
  const prefix = program.status === "consultare_publica"
    ? "Finanțare conform documentului aflat în consultare"
    : program.status === "apel_inchis" || program.status === "arhivat"
      ? "Valori istorice conform sursei oficiale"
      : "Finanțare conform sursei oficiale";
  return `${prefix}: ${facts}`;
}

function statusLabel(statusOrProgram) {
  if (statusOrProgram && typeof statusOrProgram === "object") return statusOrProgram.statusLabel;
  return DEFAULT_STATUS_LABELS[statusOrProgram] || "Statut în validare editorială";
}

function statusStatement(program) {
  if (!program || !isPublicProgram(program)) return "Informații în validare editorială.";
  if (program.status === "apel_deschis") return `${program.statusLabel}: ${program.applicationStart}–${program.applicationEnd}.`;
  return `${program.statusLabel}.`;
}

function programSummary(program) {
  if (!program) return "";
  if (!isPublicProgram(program)) return program.cardSummary;
  if (String(program.quickAnswer || "").trim()) return String(program.quickAnswer).trim();
  let summary = [program.cardSummary, statusStatement(program), fundingSummary(program)].filter(Boolean).join(" ");
  const wordCount = summary.trim().split(/\s+/u).filter(Boolean).length;
  if (wordCount < 45) {
    summary += ` Informația a fost verificată la ${program.verifiedAt} în ${program.sourceVersion}, publicat de ${program.sourceName}; înainte de pregătirea dosarului, consultă sursa oficială pentru eligibilitate, documente și condițiile aplicabile.`;
  }
  return summary;
}

function factualFaq(program) {
  if (!isPublicProgram(program)) return [];
  const items = [
    [`Care este statutul ${program.shortName}?`, `${statusStatement(program)} ${program.editorialDisclaimer || ""}`.trim()]
  ];
  const funding = fundingSummary(program);
  if (funding) items.push([`Ce finanțare și cofinanțare are ${program.shortName}?`, funding]);
  if (program.applicationStart || program.applicationEnd) {
    items.push([`Care este perioada de depunere pentru ${program.shortName}?`, `Perioada confirmată în registru este ${program.applicationStart || "—"}–${program.applicationEnd || "—"}.`]);
  }
  return items;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderProgramFactualStatus(program, options = {}) {
  if (!program) return "";
  if (!isPublicProgram(program)) {
    return `<!-- PROGRAM_FACTUAL_STATUS_START -->
<section class="program-factual-status program-factual-status--pending" aria-label="Informații în validare editorială" data-program-id="${escapeHtml(program.slug)}" data-publication-state="pending_validation">
  <p><strong>Publicare suspendată:</strong> statutul, documentul oficial, datele și valorile sunt în validare editorială și nu sunt publicate.</p>
</section>
<!-- PROGRAM_FACTUAL_STATUS_END -->`;
  }
  if (options.mode === "template-header") {
    return `<!-- PROGRAM_FACTUAL_STATUS_START -->
<section class="program-factual-status program-factual-status--template-header" aria-label="Statut și proveniență" data-program-id="${escapeHtml(program.slug)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" data-publication-state="public">
  <p><strong>${escapeHtml(statusStatement(program))}</strong></p>
  <p>Verificat la <time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(program.verifiedAt)}</time>. Sursa: <a href="${escapeHtml(program.sourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="program_template_header" data-analytics-cta-id="official_source" data-analytics-program-category="${escapeHtml(program.slug)}">${escapeHtml(program.sourceName)} — ${escapeHtml(program.sourceVersion)}</a>.</p>
</section>
<!-- PROGRAM_FACTUAL_STATUS_END -->`;
  }
  const funding = fundingSummary(program);
  const application = program.applicationStart || program.applicationEnd
    ? `<p><strong>Perioadă de depunere:</strong> ${escapeHtml(program.applicationStart || "—")}–${escapeHtml(program.applicationEnd || "—")}.</p>`
    : "<!-- applicationStart/applicationEnd=null -->";
  const meaningful = isIsoDate(program.lastMeaningfulUpdate, { nullable: false })
    ? ` Ultima actualizare relevantă: <time datetime="${escapeHtml(program.lastMeaningfulUpdate)}">${escapeHtml(program.lastMeaningfulUpdate)}</time>.`
    : "";
  return `<!-- PROGRAM_FACTUAL_STATUS_START -->
<section class="program-factual-status" aria-label="Statut factual al programului" data-program-id="${escapeHtml(program.slug)}" data-program-status="${escapeHtml(program.status)}" data-status-label="${escapeHtml(program.statusLabel)}" data-verified-at="${escapeHtml(program.verifiedAt)}" data-source-url="${escapeHtml(program.sourceUrl)}" data-publication-state="public">
  <p><strong>Statut:</strong> ${escapeHtml(statusStatement(program))} ${escapeHtml(program.editorialDisclaimer || "")}</p>
  ${application}
  ${funding ? `<p data-program-funding>${escapeHtml(funding)}</p>` : "<!-- grantSummary/cofinancingSummary=null; nicio valoare publicată -->"}
  <p><strong>Sursă oficială:</strong> <a href="${escapeHtml(program.sourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="program_factual_status" data-analytics-cta-id="official_source" data-analytics-program-category="${escapeHtml(program.slug)}">${escapeHtml(program.sourceVersion)}</a>, ${escapeHtml(program.sourceName)}. Verificat la <time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(program.verifiedAt)}</time>.${meaningful}</p>
</section>
<!-- PROGRAM_FACTUAL_STATUS_END -->`;
}

function archivedRobotsDecision(program) {
  if (program?.status !== "arhivat") return null;
  if (program.archivedNoindexDecision === "noindex" && program.evergreenValue === false) return "noindex, follow";
  if (program.archivedNoindexDecision === "index") return "index, follow";
  return null;
}

function hydrateProgramPage(page, programs) {
  const program = programForPage(page, programs);
  if (!program) return { ...page };
  const pending = !isPublicProgram(program);
  const robots = pending ? "noindex, follow" : (archivedRobotsDecision(program) || page.robots);
  return {
    ...page,
    programId: program.slug,
    programName: program.shortName,
    title: program.metaTitle,
    description: program.metaDescription,
    quickAnswer: programSummary(program),
    funding: fundingSummary(program),
    cofinancingRows: [],
    faq: [...factualFaq(program), ...(pending ? [] : (page.faq || []))],
    sourceKeys: program.officialGuideKeys?.length ? [...program.officialGuideKeys] : page.sourceKeys,
    factualGovernance: program,
    publicationHold: pending,
    robots
  };
}

function daysSince(date, now = new Date()) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date || ""))) return Number.POSITIVE_INFINITY;
  return Math.floor((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - Date.parse(`${date}T00:00:00Z`)) / 86400000);
}

module.exports = {
  ACTIVE_STATUSES,
  CONFIG_PATH,
  DEFAULT_STATUS_LABELS,
  HUMAN_REVIEW,
  PROGRAM_STATUSES,
  PUBLICATION_STATES,
  REQUIRED_FIELDS,
  ROOT,
  SOURCE_STATUSES,
  archivedRobotsDecision,
  cofinancingSummaryText,
  daysSince,
  factualFaq,
  formatIntensity,
  formatMoneyValue,
  fundingSummary,
  grantSummaryText,
  hasOfficialSource,
  hydrateProgramPage,
  isOfficialUrl,
  isPublicProgram,
  loadProgramConfig,
  normalizeRoute,
  programForPage,
  programForRoute,
  programIndexes,
  programSummary,
  renderProgramFactualStatus,
  statusLabel,
  statusStatement,
  summaryHasValues,
  validateProgram
};
