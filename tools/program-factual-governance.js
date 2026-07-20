"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const SOURCE_STATUSES = Object.freeze(["draft", "consultation", "final", "announced", "open", "closed", "unknown"]);
const ACTIVE_STATUSES = new Set(["announced", "open"]);
const REQUIRED_FIELDS = Object.freeze([
  "id",
  "route",
  "officialName",
  "shortName",
  "authority",
  "officialSourceUrl",
  "sourceDocumentName",
  "sourceStatus",
  "reviewedAt",
  "applicationStart",
  "applicationEnd",
  "eligibleApplicants",
  "maximumGrant",
  "minimumGrant",
  "intensity",
  "ownContribution",
  "budget",
  "keyConditions",
  "menuLabel",
  "menuSecondaryLabel",
  "metaTitle",
  "metaDescription",
  "factualDisclaimer"
]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function normalizeRoute(value) {
  const raw = String(value || "/").trim();
  const route = raw.startsWith("http") ? new URL(raw).pathname : raw;
  if (route === "/") return route;
  return `/${route.replace(/^\/+|\/+$/g, "")}`;
}

function isIsoDate(value) {
  return value === null || /^\d{4}-\d{2}-\d{2}$/.test(String(value || ""));
}

function hasOfficialSource(program) {
  return /^https?:\/\//i.test(String(program?.officialSourceUrl || ""))
    && Boolean(String(program?.sourceDocumentName || "").trim())
    && Boolean(String(program?.authority || "").trim())
    && /^\d{4}-\d{2}-\d{2}$/.test(String(program?.reviewedAt || ""));
}

function validateProgram(program, index = -1) {
  const errors = [];
  const location = index >= 0 ? `programs[${index}]` : `program ${program?.id || "necunoscut"}`;
  if (!program || typeof program !== "object" || Array.isArray(program)) return [`${location}: înregistrare invalidă`];
  for (const field of REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(program, field)) errors.push(`${location}: lipsește câmpul ${field}`);
  }
  if (!SOURCE_STATUSES.includes(program.sourceStatus)) errors.push(`${location}: sourceStatus invalid (${program.sourceStatus})`);
  if (normalizeRoute(program.route) !== program.route) errors.push(`${location}: ruta nu este canonică (${program.route})`);
  for (const field of ["reviewedAt", "applicationStart", "applicationEnd"]) {
    if (!isIsoDate(program[field])) errors.push(`${location}: ${field} trebuie să fie dată ISO sau null`);
  }
  if (!Array.isArray(program.eligibleApplicants)) errors.push(`${location}: eligibleApplicants trebuie să fie listă`);
  if (!Array.isArray(program.keyConditions)) errors.push(`${location}: keyConditions trebuie să fie listă`);
  if (!Array.isArray(program.officialGuideKeys) || !program.officialGuideKeys.length) errors.push(`${location}: lipsește officialGuideKeys pentru corelarea cu official-guides.json`);
  if (program.sourceStatus === "open" && (!program.applicationStart || !program.applicationEnd)) {
    errors.push(`${location}: un apel open trebuie să aibă applicationStart și applicationEnd confirmate`);
  }
  if (program.sourceStatus === "unknown") {
    for (const field of ["maximumGrant", "minimumGrant", "intensity", "budget"]) {
      if (program[field] !== null) errors.push(`${location}: ${field} trebuie să fie null când sourceStatus este unknown`);
    }
  }
  if (!hasOfficialSource(program)) errors.push(`${location}: sursa oficială sau reviewedAt este incompletă`);
  return errors;
}

function loadProgramConfig(file = CONFIG_PATH) {
  const config = readJson(file);
  const programs = Array.isArray(config.programs) ? config.programs : [];
  const errors = programs.flatMap(validateProgram);
  const ids = new Set();
  const routes = new Set();
  for (const program of programs) {
    if (ids.has(program.id)) errors.push(`id duplicat: ${program.id}`);
    if (routes.has(program.route)) errors.push(`rută duplicată: ${program.route}`);
    ids.add(program.id);
    routes.add(program.route);
  }
  if (errors.length) throw new Error(`Registrul factual este invalid:\n- ${errors.join("\n- ")}`);
  return { config, programs };
}

function programIndexes(programs = loadProgramConfig().programs) {
  return {
    byId: new Map(programs.map((program) => [program.id, program])),
    byRoute: new Map(programs.map((program) => [normalizeRoute(program.route), program]))
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

function fundingSummary(program) {
  if (!program) return "Finanțare: se confirmă în documentul oficial al apelului";
  if (program.sourceStatus === "closed") return "Finanțare: apel închis; valorile au rol editorial istoric";
  if (program.sourceStatus === "unknown") return "Finanțare: se confirmă în documentul oficial al ediției active";

  const minimum = formatMoneyValue(program.minimumGrant);
  const maximum = formatMoneyValue(program.maximumGrant);
  const intensity = formatIntensity(program.intensity);
  let range = maximum;
  if (minimum && maximum && !maximum.includes(" / ")) range = `${minimum}–${maximum}`;
  const facts = [range, intensity ? `intensitate ${intensity}` : ""].filter(Boolean).join("; ");
  const prefix = program.sourceStatus === "consultation" ? "Finanțare conform variantei consultative" : "Finanțare conform sursei oficiale";
  return facts ? `${prefix}: ${facts}` : `${prefix}: valorile se verifică în documentul programului`;
}

function statusLabel(status) {
  return ({
    draft: "Proiect de document",
    consultation: "Variantă consultativă",
    final: "Document final",
    announced: "Apel anunțat",
    open: "Apel deschis",
    closed: "Apel închis",
    unknown: "Statut de confirmat"
  })[status] || "Statut de confirmat";
}

function statusStatement(program) {
  const label = statusLabel(program?.sourceStatus);
  if (program?.sourceStatus === "open") return `${label}: ${program.applicationStart}–${program.applicationEnd}.`;
  if (program?.sourceStatus === "consultation") return `${label}; informațiile sunt conform variantei consultative.`;
  if (program?.sourceStatus === "closed") return `${label}; pagina rămâne disponibilă cu rol editorial.`;
  return `${label}.`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderProgramFactualStatus(program) {
  if (!program) return "";
  return `<!-- PROGRAM_FACTUAL_STATUS_START -->
<section class="program-factual-status" aria-label="Statut factual al programului" data-program-id="${escapeHtml(program.id)}" data-source-status="${escapeHtml(program.sourceStatus)}" data-reviewed-at="${escapeHtml(program.reviewedAt)}">
  <p><strong>Statutul informației:</strong> ${escapeHtml(statusStatement(program))} ${escapeHtml(program.factualDisclaimer)}</p>
  <p>${escapeHtml(fundingSummary(program))}</p>
  <p><strong>Sursă oficială:</strong> <a href="${escapeHtml(program.officialSourceUrl)}" target="_blank" rel="noopener noreferrer" data-analytics-event="source_document_click" data-analytics-component="program_factual_status" data-analytics-cta-id="official_source" data-analytics-program-category="${escapeHtml(program.id)}">${escapeHtml(program.sourceDocumentName)}</a>, ${escapeHtml(program.authority)}. Verificat la <time datetime="${escapeHtml(program.reviewedAt)}">${escapeHtml(program.reviewedAt)}</time>.</p>
</section>
<!-- PROGRAM_FACTUAL_STATUS_END -->`;
}

function hydrateProgramPage(page, programs) {
  const program = programForPage(page, programs);
  if (!program) return { ...page };
  return {
    ...page,
    programId: program.id,
    programName: program.shortName,
    title: program.metaTitle,
    description: program.metaDescription,
    funding: fundingSummary(program),
    sourceKeys: program.officialGuideKeys?.length ? [...program.officialGuideKeys] : page.sourceKeys,
    factualGovernance: program
  };
}

function daysSince(date, now = new Date()) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date || ""))) return Number.POSITIVE_INFINITY;
  return Math.floor((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - Date.parse(`${date}T00:00:00Z`)) / 86400000);
}

module.exports = {
  ACTIVE_STATUSES,
  CONFIG_PATH,
  REQUIRED_FIELDS,
  ROOT,
  SOURCE_STATUSES,
  daysSince,
  formatIntensity,
  formatMoneyValue,
  fundingSummary,
  hasOfficialSource,
  hydrateProgramPage,
  loadProgramConfig,
  normalizeRoute,
  programForPage,
  programForRoute,
  programIndexes,
  renderProgramFactualStatus,
  statusLabel,
  statusStatement,
  validateProgram
};
