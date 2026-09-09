#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { isOfficialUrl, loadData, resolveSourceReference } = require("./generate-status-governance-docs");

const ROOT = path.resolve(__dirname, "..");
const POLICY_PATH = "config/editorial-governance.json";
const REPORT_STEM = path.join(ROOT, "reports", "funding-status-audit");
const DAY_MS = 86400000;

function isDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString().slice(0, 10) === value;
}

function hasValue(value) {
  const text = String(value ?? "").trim();
  return text !== "" && text !== "DE_VALIDAT_UMAN";
}

function referenceId(reference) {
  return typeof reference === "string" ? reference.trim() : String(reference?.ref || "").trim();
}

function officialEvidence(reference, program, data) {
  try {
    const source = resolveSourceReference(reference, program, data);
    return isOfficialUrl(source.url) && hasValue(source.label) ? source : null;
  } catch {
    // An unresolved reference is missing evidence, not a reason to skip the program.
    return null;
  }
}

function auditFundingStatus(data, { today = new Date().toISOString().slice(0, 10), policy } = {}) {
  if (!isDate(today)) throw new Error("today trebuie să fie o dată calendaristică YYYY-MM-DD validă.");
  if (!Array.isArray(data?.programs) || !data.programs.length) throw new Error("Registrul trebuie să conțină o listă nevidă programs.");
  if (!Array.isArray(data.taxonomy?.statuses) || !data.taxonomy.statuses.length) throw new Error("Taxonomia canonică lipsește.");
  for (const field of ["openCallReviewDays", "programReviewDays"]) {
    if (!Number.isInteger(policy?.[field]) || policy[field] <= 0) throw new Error(`Politică invalidă: ${field}.`);
  }
  const statuses = new Set(data.taxonomy.statuses.map((entry) => entry.id));
  const findings = [];

  for (const program of data.programs) {
    if (!program || typeof program !== "object" || Array.isArray(program)) throw new Error("Înregistrare program invalidă.");
    const firstFinding = findings.length;
    const status = program.canonicalStatus;
    const open = status === "OPEN" || program.status === "apel_deschis";
    const severity = open ? "high" : "warning";
    const start = program.applicationStart;
    const end = program.applicationEnd;
    const verified = isDate(program.verifiedAt) && program.verifiedAt <= today;
    let effectiveEnd = end;
    let extensionSource = null;
    const add = (code, level, problem, recommendedAction) => findings.push({
      program: program.id || program.slug || "(identificator lipsă)",
      name: program.name || program.shortName || null,
      status: status || null,
      legacyStatus: program.status || null,
      sessionStart: start ?? null,
      sessionEnd: end ?? null,
      effectiveSessionEnd: effectiveEnd ?? null,
      consultationStart: program.consultationStart ?? null,
      consultationEnd: program.consultationEnd ?? null,
      verifiedAt: program.verifiedAt ?? null,
      source: program.sourceUrl ?? null,
      extensionSource,
      code,
      problem,
      severity: level,
      recommendedAction,
    });

    if (!statuses.has(status)) add("UNKNOWN_STATUS", "high", "canonicalStatus lipsește sau nu aparține taxonomiei.", "Corectează atribuirea după verificarea dovezii oficiale; nu deduce statusul din eticheta legacy.");
    if (program.status === "apel_deschis" && status !== "OPEN") add("STATUS_CONTRADICTION", "high", "Suprafața legacy afirmă OPEN, dar statusul canonic diferă.", "Reverifică și aliniază manual statusul canonic și cel public.");
    if (!verified) add("VERIFICATION_INVALID", severity, "verifiedAt lipsește, este invalid sau este în viitor.", "Înregistrează data reală a reverificării oficiale; nu folosi data rulării auditului.");
    else {
      const age = (Date.parse(`${today}T00:00:00Z`) - Date.parse(`${program.verifiedAt}T00:00:00Z`)) / DAY_MS;
      const limit = open ? policy.openCallReviewDays : policy.programReviewDays;
      if (age > limit) add("VERIFICATION_STALE", "warning", `Reverificare veche de ${age} zile; prag intern ${limit} zile depășit.`, "Reverifică sursa oficială și eventualele corrigenda; vechimea nu dovedește schimbarea statusului.");
    }

    for (const field of ["applicationStart", "applicationEnd", "consultationStart", "consultationEnd"]) {
      if (hasValue(program[field]) && !isDate(program[field])) add("INVALID_DATE", severity, `${field} nu este o dată calendaristică validă.`, "Corectează data numai pe baza documentului oficial; nu interpreta automat text liber.");
    }
    if (isDate(start) && isDate(end) && start > end) add("SESSION_ORDER_INVALID", severity, "Începutul sesiunii este după sfârșit.", "Reverifică intervalul și transcrierea datelor în registry.");

    if (program.extensionData !== undefined && program.extensionData !== null) {
      const extension = program.extensionData;
      const source = officialEvidence(extension?.sourceRef, program, data);
      const assignedRefs = ["corrigenda", "sessionAnnouncement"].flatMap((role) => {
        const references = program.officialSources?.roles?.[role];
        return Array.isArray(references) ? references.map(referenceId) : [];
      });
      const documented = source && assignedRefs.includes(referenceId(extension?.sourceRef));
      extensionSource = source?.url || null;
      const datesValid = isDate(extension?.originalEnd) && isDate(extension?.extendedEnd)
        && extension.originalEnd < extension.extendedEnd
        && [extension.originalEnd, extension.extendedEnd].includes(end)
        && isDate(extension?.verifiedAt) && extension.verifiedAt <= today
        && verified && extension.verifiedAt <= program.verifiedAt;
      if (!documented) add("EXTENSION_SOURCE_MISSING", "high", "Prelungirea nu are o referință oficială rezolvabilă, atribuită sesiunii sau unei corrigende.", "Leagă extensionData.sourceRef de documentul oficial înregistrat și atribuie-l acestui program; nu accepta un URL generic ca dovadă de prelungire.");
      if (!datesValid) add("EXTENSION_INVALID", "high", "Datele prelungirii sunt incomplete, necorelate cu sesiunea sau fără reverificare validă.", "Confirmă originalEnd, extendedEnd și verifiedAt ale prelungirii și reverifică înregistrarea programului.");
      if (documented && datesValid) {
        effectiveEnd = extension.extendedEnd;
        if (end !== effectiveEnd) add("EXTENSION_NOT_APPLIED", "warning", "Prelungire documentată, dar applicationEnd încă păstrează termenul anterior.", "După review editorial, sincronizează manual termenul și suprafețele publice cu prelungirea oficială.");
      }
    }

    if (open) {
      if (program.sourceType !== "official" || !isOfficialUrl(program.sourceUrl) || !hasValue(program.sourceName) || !hasValue(program.sourceVersion)) {
        add("OPEN_SOURCE_MISSING", "high", "OPEN fără sursă oficială principală completă și permisă de politica repo-ului.", "Reverifică și înregistrează instituția, documentul/versiunea și URL-ul oficial.");
      }
      const sessionRefs = program.officialSources?.roles?.sessionAnnouncement;
      if (!Array.isArray(sessionRefs) || !sessionRefs.some((reference) => officialEvidence(reference, program, data))) {
        add("OPEN_SESSION_EVIDENCE_MISSING", "high", "OPEN fără dovadă oficială rezolvabilă de sesiune.", "Înregistrează anunțul de sesiune sau dovada platformei oficiale, asociată acestui program.");
      }
      if (!isDate(start) || !isDate(end)) add("OPEN_SESSION_DATES_MISSING", "high", "OPEN fără început și sfârșit de sesiune confirmate.", "Verifică fereastra oficială; nu deduce sesiunea din publicarea ghidului sau aprobarea schemei.");
      if (isDate(start) && start > today) add("OPEN_NOT_STARTED", "high", "OPEN are o dată de început în viitor.", "Reverifică data și statusul înainte de a prezenta depunerea drept deschisă.");
      if (isDate(effectiveEnd) && effectiveEnd < today) add("OPEN_EXPIRED", "high", "OPEN are termenul depășit, fără prelungire documentată care să acopere data auditului.", "Reverifică urgent sursa oficială, prelungirile și eventualele suspendări. Nu schimba automat OPEN în CLOSED.");
    }

    if (status === "SCHEDULED") {
      if (!isDate(start)) add("SCHEDULED_START_MISSING", "warning", "SCHEDULED fără dată de început confirmată.", "Completează data din anunțul oficial; nu transforma un calendar estimativ în sesiune confirmată.");
      else if (start < today && (!verified || program.verifiedAt < start)) add("SCHEDULED_REVIEW_REQUIRED", "warning", "Data programată a trecut fără reverificare la sau după începutul sesiunii.", "Verifică dacă sesiunea a început, a fost amânată ori suspendată; actualizarea statusului necesită review.");
    }
    if (status === "PUBLIC_CONSULTATION") {
      const consultationEnd = program.consultationEnd;
      if (!isDate(consultationEnd)) add("CONSULTATION_END_MISSING", "warning", "Consultare activă fără termen explicit pentru observații.", "Înregistrează consultationEnd din sursa oficială, separat de applicationEnd.");
      else if (consultationEnd < today && (!verified || program.verifiedAt <= consultationEnd)) add("CONSULTATION_REVIEW_REQUIRED", "warning", "Termenul consultării a trecut fără reverificare ulterioară.", "Reverifică documentul și stadiul consultării; un ghid consultativ rămas public nu înseamnă consultare activă.");
    }
    for (const finding of findings.slice(firstFinding)) {
      finding.effectiveSessionEnd = effectiveEnd ?? null;
      finding.extensionSource = extensionSource;
    }
  }

  return {
    schemaVersion: 1,
    asOf: today,
    readOnly: true,
    policy: { source: POLICY_PATH, openCallReviewDays: policy.openCallReviewDays, programReviewDays: policy.programReviewDays },
    programsChecked: data.programs.length,
    summary: { high: findings.filter((item) => item.severity === "high").length, warning: findings.filter((item) => item.severity === "warning").length },
    findings,
  };
}

function exitCode(report) {
  return report.summary.high > 0 ? 1 : 0;
}

function markdownReport(report) {
  const cell = (value) => String(value ?? "—").replace(/\r?\n/gu, " ").replace(/\|/gu, "\\|").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
  const lines = [
    "# Audit statusuri finanțare",
    "",
    `Data auditului (UTC): ${report.asOf}. Programe: ${report.programsChecked}. HIGH: ${report.summary.high}; WARNING: ${report.summary.warning}.`,
    "",
    `Praguri interne: OPEN ${report.policy.openCallReviewDays} zile; alte programe ${report.policy.programReviewDays} zile (${report.policy.source}).`,
    "Audit offline/read-only: nu reverifică documentele online și nu schimbă facts, statusuri, verifiedAt, dateModified sau lastmod.",
    "",
    "| Program | Status | Session start/end | Termen efectiv | Consultation start/end | verifiedAt | Source / extension source | Problem | Severity | Recommended action |",
    "|---|---|---|---|---|---|---|---|---|---|",
  ];
  for (const row of report.findings) {
    lines.push(`| ${[row.program, row.status, `${row.sessionStart ?? "—"} / ${row.sessionEnd ?? "—"}`, row.effectiveSessionEnd, `${row.consultationStart ?? "—"} / ${row.consultationEnd ?? "—"}`, row.verifiedAt, [row.source, row.extensionSource].filter(Boolean).join(" / "), `${row.code}: ${row.problem}`, row.severity.toUpperCase(), row.recommendedAction].map(cell).join(" | ")} |`);
  }
  if (!report.findings.length) lines.push("", "Nicio combinație suspectă detectată în datele înregistrate. Acest rezultat nu confirmă starea actuală a surselor online.");
  return lines.join("\n") + "\n";
}

function main(args = process.argv.slice(2)) {
  try {
    const options = { format: "markdown", report: false };
    const seen = new Set();
    for (const arg of args) {
      const [key, ...parts] = arg.split("=");
      if (seen.has(key)) throw new Error(`Argument duplicat: ${key}`);
      seen.add(key);
      const value = parts.join("=");
      if (key === "--today" && value) options.today = value;
      else if (key === "--format" && ["json", "markdown"].includes(value)) options.format = value;
      else if (arg === "--report") options.report = true;
      else throw new Error(`Argument invalid: ${arg}. Folosește --today=YYYY-MM-DD, --format=json|markdown, --report.`);
    }
    const { policy } = JSON.parse(fs.readFileSync(path.join(ROOT, POLICY_PATH), "utf8"));
    const report = auditFundingStatus(loadData(), { today: options.today, policy });
    const json = JSON.stringify(report, null, 2) + "\n";
    const markdown = markdownReport(report);
    if (options.report) {
      fs.mkdirSync(path.dirname(REPORT_STEM), { recursive: true });
      fs.writeFileSync(`${REPORT_STEM}.json`, json, "utf8");
      fs.writeFileSync(`${REPORT_STEM}.md`, markdown, "utf8");
    }
    process.stdout.write(options.format === "json" ? json : markdown);
    process.exitCode = exitCode(report);
  } catch (error) {
    console.error(`Audit statusuri indisponibil: ${error.message}`);
    process.exitCode = 2;
  }
}

if (require.main === module) main();

module.exports = { auditFundingStatus, exitCode, isDate, markdownReport };
