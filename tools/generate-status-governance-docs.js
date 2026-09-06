#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const TAXONOMY_PATH = path.join(ROOT, "config", "program-status-taxonomy.json");
const SOURCE_REGISTRY_PATH = path.join(ROOT, "config", "program-source-registry.json");
const PROGRAMS_PATH = path.join(ROOT, "config", "seo-programs.json");
const GUIDES_PATH = path.join(ROOT, "official-guides.json");
const APPROVALS_PATH = path.join(ROOT, "config", "program-status-approvals.json");
const STATUS_DOC_PATH = path.join(ROOT, "docs", "faber-remediation", "STATUS_TAXONOMY.md");
const SOURCE_DOC_PATH = path.join(ROOT, "docs", "faber-remediation", "OFFICIAL_SOURCE_REGISTRY.md");

const EXPECTED_STATUS_IDS = Object.freeze([
  "ANNOUNCED",
  "PREPARATION",
  "PUBLIC_CONSULTATION",
  "CONSULTATIVE_GUIDE",
  "FINAL_GUIDE",
  "APPROVED_SCHEME",
  "SCHEDULED",
  "OPEN",
  "CLOSED",
  "SUSPENDED",
  "CANCELLED",
  "COMPLETED",
  "UNCONFIRMED"
]);
const LEGACY_STATUS_IDS = Object.freeze([
  "calendar_estimativ",
  "consultare_publica",
  "ghid_aprobat_nedeschis",
  "apel_deschis",
  "apel_inchis",
  "arhivat"
]);
const SOURCE_ROLES = Object.freeze([
  "programPage",
  "guide",
  "annexes",
  "schemeOrder",
  "sessionAnnouncement",
  "corrigenda",
  "clarifications"
]);
const SOURCE_ROLE_LABELS = Object.freeze({
  programPage: "Pagină oficială program/apel",
  guide: "Ghid",
  annexes: "Anexe",
  schemeOrder: "Schemă / ordin",
  sessionAnnouncement: "Anunț sesiune",
  corrigenda: "Corrigenda / erate",
  clarifications: "Clarificări"
});
const FACTUAL_FIELD_LABELS = Object.freeze([
  "Denumire oficială",
  "Acronim",
  "Autoritate",
  "Fond / program",
  "Temei / document",
  "Stadiu",
  "Sesiune",
  "Data deschiderii",
  "Deadline",
  "Prelungiri",
  "Buget",
  "Grant minim",
  "Grant maxim",
  "Intensitate",
  "Cofinanțare",
  "Beneficiari",
  "Regiune",
  "CAEN",
  "Prag SO",
  "Investiții",
  "Cheltuieli eligibile",
  "Cheltuieli neeligibile",
  "Condiții critice",
  "Documente",
  "Indicatori",
  "Selecție / punctaj",
  "Ajutor de stat / de minimis",
  "Implementare",
  "Monitorizare",
  "Surse oficiale",
  "Latest official update",
  "verifiedAt"
]);
const OFFICIAL_HOST_SUFFIXES = Object.freeze([
  "gov.ro",
  "bidromania.eu",
  "afir.ro",
  "regionordest.ro",
  "legislatie.just.ro",
  "fonduri-ue.ro"
]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function loadData() {
  const taxonomy = readJson(TAXONOMY_PATH);
  const sourceRegistry = readJson(SOURCE_REGISTRY_PATH);
  const programConfig = readJson(PROGRAMS_PATH);
  const guides = readJson(GUIDES_PATH);
  const approvalConfig = readJson(APPROVALS_PATH);
  return {
    taxonomy,
    sourceRegistry,
    programs: programConfig.programs || [],
    factualChanges: programConfig.factualChanges || [],
    guides,
    approvals: approvalConfig.programs || []
  };
}

function isIsoDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))
    && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function isOfficialUrl(value) {
  try {
    const url = new URL(String(value || ""));
    const hostname = url.hostname.toLowerCase();
    return url.protocol === "https:"
      && OFFICIAL_HOST_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`));
  } catch {
    return false;
  }
}

function sameMembers(actual, expected) {
  return actual.length === expected.length
    && actual.every((item) => expected.includes(item));
}

function resolveSourceReference(reference, program, data) {
  const descriptor = typeof reference === "string" ? { ref: reference } : reference;
  const ref = String(descriptor?.ref || "").trim();
  let source;

  if (ref === "program") {
    source = {
      title: program.sourceVersion,
      url: program.sourceUrl,
      authority: program.sourceName,
      verifiedAt: program.verifiedAt,
      updatedAt: program.officialSourceUpdatedAt || program.lastMeaningfulUpdate
    };
  } else if (ref.startsWith("guide:")) {
    const key = ref.slice("guide:".length);
    const guide = data.guides[key];
    if (!guide) throw new Error(`${program.slug}: referință inexistentă ${ref}`);
    if (Array.isArray(guide.programIds) && guide.programIds.length && !guide.programIds.includes(program.id)) {
      throw new Error(`${program.slug}: ${ref} aparține altui program`);
    }
    source = {
      title: guide.title || guide.name,
      url: guide.url,
      authority: guide.institution || guide.authority,
      verifiedAt: guide.verifiedAt || guide.accessedAt || guide.lastVerifiedAt,
      updatedAt: guide.publishedAt || null
    };
  } else if (ref.startsWith("registry:")) {
    const key = ref.slice("registry:".length);
    const registrySource = data.sourceRegistry.supplementalSources?.[key];
    if (!registrySource) throw new Error(`${program.slug}: referință inexistentă ${ref}`);
    source = {
      title: registrySource.title,
      url: registrySource.url,
      authority: registrySource.authority,
      verifiedAt: registrySource.verifiedAt,
      updatedAt: registrySource.publishedAt || null
    };
  } else if (ref === "approval:official" || ref.startsWith("approval:evidence:")) {
    const approval = data.approvals.find((item) => item.programId === program.id);
    if (!approval) throw new Error(`${program.slug}: ${ref} nu are înregistrare de aprobare`);
    if (ref === "approval:official") {
      source = {
        title: approval.officialDocumentVersion || approval.officialDocument,
        url: approval.officialUrl,
        authority: approval.officialInstitution,
        verifiedAt: approval.verifiedAt,
        updatedAt: approval.officialDocumentDate || null
      };
    } else {
      const index = Number(ref.slice("approval:evidence:".length));
      const url = approval.additionalOfficialEvidence?.[index];
      if (!Number.isInteger(index) || !url) throw new Error(`${program.slug}: index invalid în ${ref}`);
      source = {
        title: `Dovadă oficială suplimentară pentru ${approval.officialDocument}`,
        url,
        authority: approval.officialInstitution,
        verifiedAt: approval.verifiedAt,
        updatedAt: approval.officialDocumentDate || null
      };
    }
  } else {
    throw new Error(`${program.slug}: tip de referință necunoscut ${ref || "(gol)"}`);
  }

  return {
    ref,
    label: String(descriptor.label || source.title || ref).trim(),
    ...source
  };
}

function validateData(data) {
  const errors = [];
  const statusIds = data.taxonomy.statuses.map((status) => status.id);
  const statusSet = new Set(statusIds);
  const programIds = data.programs.map((program) => program.id);

  if (data.taxonomy.schemaVersion !== 2) errors.push("Taxonomia trebuie să aibă schemaVersion=2.");
  if (data.sourceRegistry.schemaVersion !== 2) errors.push("Catalogul suplimentar de surse trebuie să aibă schemaVersion=2.");
  if (!isIsoDate(data.taxonomy.reviewedAt)) errors.push("Taxonomia trebuie să aibă reviewedAt ISO.");
  if (!isIsoDate(data.sourceRegistry.factualSnapshotDate)) errors.push("Snapshot-ul factual trebuie să fie dată ISO.");
  if (!sameMembers(statusIds, EXPECTED_STATUS_IDS) || statusSet.size !== EXPECTED_STATUS_IDS.length) {
    errors.push(`Taxonomia trebuie să conțină exact: ${EXPECTED_STATUS_IDS.join(", ")}.`);
  }

  for (const status of data.taxonomy.statuses) {
    const location = `status ${status.id || "necunoscut"}`;
    for (const field of ["definition", "publicLabel"]) {
      if (!String(status[field] || "").trim()) errors.push(`${location}: ${field} lipsește.`);
    }
    for (const field of ["evidenceRequired", "forbiddenWording", "validTransitions"]) {
      if (!Array.isArray(status[field]) || !status[field].length) errors.push(`${location}: ${field} trebuie să fie listă nevidă.`);
    }
    if (typeof status.acceptsApplications !== "boolean") errors.push(`${location}: acceptsApplications trebuie să fie boolean.`);
    if (status.id === "OPEN" ? status.acceptsApplications !== true : status.acceptsApplications !== false) {
      errors.push(`${location}: numai OPEN poate avea acceptsApplications=true.`);
    }
    for (const target of status.validTransitions || []) {
      if (!statusSet.has(target)) errors.push(`${location}: tranziție invalidă spre ${target}.`);
    }
  }

  const finalGuide = data.taxonomy.statuses.find((status) => status.id === "FINAL_GUIDE");
  const approvedScheme = data.taxonomy.statuses.find((status) => status.id === "APPROVED_SCHEME");
  const scheduled = data.taxonomy.statuses.find((status) => status.id === "SCHEDULED");
  if (finalGuide?.acceptsApplications || approvedScheme?.acceptsApplications) {
    errors.push("FINAL_GUIDE și APPROVED_SCHEME nu pot permite depunerea.");
  }
  if (!scheduled?.publicLabel.includes("{startDate}") || !scheduled.publicLabel.includes("{endDate}")) {
    errors.push("Label-ul SCHEDULED trebuie să includă startDate și endDate.");
  }

  const legacyIds = Object.keys(data.taxonomy.legacyCompatibility);
  if (!sameMembers(legacyIds, LEGACY_STATUS_IDS)) errors.push("Maparea legacy nu acoperă exact cele șase statusuri curente.");
  for (const [legacyId, mapping] of Object.entries(data.taxonomy.legacyCompatibility)) {
    if (!Array.isArray(mapping.possibleCanonicalStatuses) || !mapping.possibleCanonicalStatuses.length) {
      errors.push(`${legacyId}: possibleCanonicalStatuses lipsește.`);
    }
    for (const target of mapping.possibleCanonicalStatuses || []) {
      if (!statusSet.has(target)) errors.push(`${legacyId}: status canonic invalid ${target}.`);
    }
    if (!String(mapping.rule || "").trim()) errors.push(`${legacyId}: regula de compatibilitate lipsește.`);
  }

  if (new Set(programIds).size !== programIds.length) errors.push("ID-urile programelor trebuie să fie unice.");

  for (const [key, source] of Object.entries(data.sourceRegistry.supplementalSources || {})) {
    if (!String(source.title || "").trim()) errors.push(`supplementalSources.${key}: title lipsește.`);
    if (!String(source.authority || "").trim()) errors.push(`supplementalSources.${key}: authority lipsește.`);
    if (!String(source.documentType || "").trim()) errors.push(`supplementalSources.${key}: documentType lipsește.`);
    if (!isOfficialUrl(source.url)) errors.push(`supplementalSources.${key}: URL oficial HTTPS invalid.`);
    if (!isIsoDate(source.verifiedAt)) errors.push(`supplementalSources.${key}: verifiedAt invalid.`);
    if (source.publishedAt !== null && !isIsoDate(source.publishedAt)) errors.push(`supplementalSources.${key}: publishedAt invalid.`);
  }

  for (const program of data.programs) {
    const assignment = program;
    const sourceEntry = program.officialSources;
    if (!assignment || !statusSet.has(assignment.canonicalStatus)) errors.push(`${program.slug}: atribuire canonică invalidă.`);
    if (!assignment?.statusScope || !assignment?.statusRationale) errors.push(`${program.slug}: statusScope/statusRationale lipsă.`);
    if (program.sourceType !== "official" || !isOfficialUrl(program.sourceUrl)) errors.push(`${program.slug}: sursa principală nu este URL oficial HTTPS permis.`);
    if (!isIsoDate(program.verifiedAt)) errors.push(`${program.slug}: verifiedAt invalid.`);
    if (program.verifiedAt < data.sourceRegistry.factualSnapshotDate) {
      errors.push(`${program.slug}: verifiedAt nu poate fi anterior snapshot-ului factual de bază.`);
    }
    if (!sourceEntry || !sourceEntry.roles) continue;
    if (!String(sourceEntry.notes || "").trim()) errors.push(`${program.slug}: notes lipsește din registrul de surse.`);
    for (const role of SOURCE_ROLES) {
      if (!Array.isArray(sourceEntry.roles[role])) {
        errors.push(`${program.slug}: rolul ${role} trebuie să fie listă.`);
        continue;
      }
      for (const reference of sourceEntry.roles[role]) {
        try {
          const resolved = resolveSourceReference(reference, program, data);
          if (!isOfficialUrl(resolved.url)) errors.push(`${program.slug}: ${resolved.ref} nu este URL oficial HTTPS permis.`);
          if (!String(resolved.label || "").trim()) errors.push(`${program.slug}: ${resolved.ref} nu are label.`);
          if (!isIsoDate(resolved.verifiedAt)) errors.push(`${program.slug}: ${resolved.ref} nu are dată de verificare validă.`);
        } catch (error) {
          errors.push(error.message);
        }
      }
    }
    if (!sourceEntry.roles.programPage.length) errors.push(`${program.slug}: programPage nu poate fi gol.`);
    if (sourceEntry.latestOfficialUpdateRef) {
      try {
        const latest = resolveSourceReference(sourceEntry.latestOfficialUpdateRef, program, data);
        if (!isOfficialUrl(latest.url)) errors.push(`${program.slug}: latestOfficialUpdateRef nu este URL oficial HTTPS permis.`);
      } catch (error) {
        errors.push(error.message);
      }
    }
    if (["OPEN", "SCHEDULED"].includes(assignment?.canonicalStatus)) {
      if (!isIsoDate(program.applicationStart) || !isIsoDate(program.applicationEnd)) {
        errors.push(`${program.slug}: ${assignment.canonicalStatus} cere applicationStart/applicationEnd.`);
      }
      if (!sourceEntry.roles.sessionAnnouncement.length) {
        errors.push(`${program.slug}: ${assignment.canonicalStatus} cere dovadă de sesiune.`);
      }
    }
    if (assignment?.canonicalStatus === "SCHEDULED" && program.applicationStart <= data.taxonomy.reviewedAt) {
      errors.push(`${program.slug}: SCHEDULED cere o dată de început viitoare față de reviewedAt.`);
    }
    if (assignment?.canonicalStatus === "OPEN"
      && !(program.applicationStart <= data.taxonomy.reviewedAt && data.taxonomy.reviewedAt <= program.applicationEnd)) {
      errors.push(`${program.slug}: OPEN cere ca reviewedAt să fie în fereastra oficială.`);
    }
  }

  for (const program of data.programs) {
    for (const key of program.officialGuideKeys || []) {
      if (!data.guides[key]) errors.push(`${program.slug}: cheia officialGuideKeys ${key} lipsește din official-guides.json.`);
    }
  }
  for (const [index, change] of data.factualChanges.entries()) {
    const location = `factualChanges[${index}]`;
    if (!programIds.includes(change.programId)) errors.push(`${location}: programId inexistent.`);
    for (const field of ["field", "before", "after", "sourceLabel", "reason"]) {
      if (!String(change[field] || "").trim()) errors.push(`${location}: ${field} lipsește.`);
    }
    if (!isOfficialUrl(change.sourceUrl)) errors.push(`${location}: sourceUrl nu este URL oficial permis.`);
    if (!isIsoDate(change.verifiedAt)) errors.push(`${location}: verifiedAt invalid.`);
  }
  return errors;
}

function markdown(value) {
  return String(value ?? "—")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .trim() || "—";
}

function missingOfficialInformation(program) {
  return `Documentația oficială publicată și verificată la ${formatDate(program.verifiedAt)} nu stabilește încă această informație.`;
}

function formatScalar(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(formatScalar).filter(Boolean).join("; ");
  if (typeof value === "object") {
    if (Number.isFinite(value.amount)) {
      const amount = new Intl.NumberFormat("ro-RO").format(value.amount);
      return [amount, value.currency, value.unit ? `/ ${value.unit}` : ""].filter(Boolean).join(" ");
    }
    return Object.entries(value)
      .map(([key, item]) => `${key}: ${formatScalar(item)}`)
      .filter((item) => !item.endsWith(": "))
      .join("; ");
  }
  return String(value);
}

function factualValue(program, value) {
  const formatted = formatScalar(value).trim();
  return markdown(formatted || missingOfficialInformation(program));
}

function allOfficialReferences(program, data) {
  const references = SOURCE_ROLES.flatMap((role) => program.officialSources.roles[role]);
  const seen = new Set();
  return references
    .map((reference) => resolveSourceReference(reference, program, data))
    .filter((source) => !seen.has(source.url) && seen.add(source.url));
}

function factualFieldRows(program, data) {
  const sources = allOfficialReferences(program, data);
  const documents = sources.map((source) => link(source.label, source.url)).join("<br>");
  const sessions = (program.officialSources.roles.sessionAnnouncement || []);
  const session = sessions.length ? renderReferences(sessions, program, data) : "";
  const latest = resolveSourceReference(program.officialSources.latestOfficialUpdateRef || { ref: "program" }, program, data);
  const regionLabels = { national: "Național", nord_est: "Regiunea Nord-Est", local: "Local, la nivelul GAL selectat" };
  const regions = (program.discovery?.regions || []).map((region) => regionLabels[region] || region.replaceAll("_", " "));
  const review = program.factualReview || {};
  const values = [
    program.name,
    program.acronym,
    program.sourceName,
    program.fund,
    `${program.sourceVersion} — ${link("document oficial", program.sourceUrl)}`,
    `${program.canonicalStatus} — ${program.statusLabel}`,
    session || review.session,
    program.applicationStart ? formatDate(program.applicationStart) : null,
    program.applicationEnd ? formatDate(program.applicationEnd) : null,
    program.extensionData || review.extensions,
    program.grantSummary?.budget,
    program.grantSummary?.minimum,
    program.grantSummary?.maximum,
    program.cofinancingSummary?.intensity,
    program.cofinancingSummary?.ownContribution,
    program.eligibleApplicantSummary || program.eligibleApplicants,
    regions,
    program.caenApplicability,
    program.soRequirement,
    review.investments,
    review.eligibleExpenses,
    review.ineligibleExpenses,
    program.keyConditions,
    documents,
    review.indicators,
    review.selection,
    review.stateAid,
    review.implementation,
    review.monitoring,
    documents,
    `${latest.updatedAt || program.lastMeaningfulUpdate || "—"} — ${link(latest.label, latest.url)}`,
    program.verifiedAt
  ];
  return FACTUAL_FIELD_LABELS.map((label, index) => `| ${label} | ${factualValue(program, values[index])} |`);
}

function link(label, url) {
  return `[${markdown(label).replace(/\[/g, "\\[").replace(/\]/g, "\\]")}](${url})`;
}

function formatDate(value) {
  if (!isIsoDate(value)) return markdown(value);
  const [year, month, day] = value.split("-");
  return `${day}.${month}.${year}`;
}

function statusById(data) {
  return new Map(data.taxonomy.statuses.map((status) => [status.id, status]));
}

function publicLabelForProgram(program, assignment, statuses) {
  return statuses.get(assignment.canonicalStatus).publicLabel
    .replace("{startDate}", formatDate(program.applicationStart))
    .replace("{endDate}", formatDate(program.applicationEnd));
}

function renderStatusTaxonomy(data) {
  const statuses = statusById(data);
  const programRows = data.programs.map((program) => {
    const assignment = program;
    return `| \`${program.id}\` | \`${program.status}\` | \`${assignment.canonicalStatus}\` | ${markdown(publicLabelForProgram(program, assignment, statuses))} | ${markdown(assignment.statusScope)} | ${markdown(assignment.statusRationale)} |`;
  });
  const lines = [
    "# Taxonomia unică de status FABER",
    "",
    `Revizie semantică: **${data.taxonomy.reviewedAt}**. Definiții canonice: \`config/program-status-taxonomy.json\`; atribuiri per program: \`config/seo-programs.json#programs[*].canonicalStatus\`. Acest document este generat de \`tools/generate-status-governance-docs.js\` și nu este o pagină publică.`,
    "",
    "## Contractul mecanismului",
    "",
    "Starea canonică descrie un program, apel, ediție sau sesiune la granularitatea declarată. Ea este separată de publicare/indexare: o pagină `CLOSED` sau `COMPLETED` poate rămâne indexabilă dacă are valoare evergreen, iar o pagină `UNCONFIRMED` nu capătă certitudine doar pentru că este publicată.",
    "",
    "Reguli invariabile:",
    "",
    "1. `acceptsApplications=true` există exclusiv pentru `OPEN`.",
    "2. `APPROVED_SCHEME` și `FINAL_GUIDE` nu sunt sinonime cu `OPEN`.",
    "3. `SCHEDULED` cere o fereastră oficială viitoare; data de început nu promovează automat starea la `OPEN` fără reverificarea sesiunii.",
    "4. `OPEN` cere dovadă oficială de sesiune, interval curent și verificarea unei eventuale suspendări, închideri anticipate, prelungiri ori corrigenda.",
    "5. După deadline, `OPEN` este interzis. Se folosește `CLOSED` când închiderea este dovedită sau `UNCONFIRMED` când nu pot fi excluse actualizări oficiale.",
    "6. Starea unui apel punctual nu se propagă asupra unei pagini-umbrelă cu apeluri multiple.",
    "7. O tranziție este acceptată numai cu o dovadă nouă, versionată în registrul oficial; trecerea timpului este un semnal de reverificare, nu singura dovadă.",
    "",
    "Fluxul de evaluare este: identificarea granularității → verificarea emitentului și documentului → clasificarea tipului de dovadă → evaluarea ferestrei calendaristice → controlul corrigenda/clarificărilor → emiterea statusului și label-ului public. În caz de conflict sau lipsă, rezultatul este `UNCONFIRMED`.",
    "",
    "## Mapare status tehnic → label public",
    "",
    "| Status tehnic | Depunere | Label public recomandat | Definiție scurtă |",
    "|---|---|---|---|",
    ...data.taxonomy.statuses.map((status) => `| \`${status.id}\` | ${status.acceptsApplications ? "da" : "nu"} | ${markdown(status.publicLabel)} | ${markdown(status.definition)} |`),
    "",
    "Placeholder-ele `{startDate}` și `{endDate}` se înlocuiesc numai cu date absolute confirmate; formatul recomandat public este `ZZ.LL.AAAA`. Label-ul poate adăuga identificatorul apelului, dar nu poate schimba sensul stării.",
    "",
    "## Definiții, dovezi și tranziții"
  ];

  for (const status of data.taxonomy.statuses) {
    lines.push(
      "",
      `### \`${status.id}\``,
      "",
      `**Definiție:** ${status.definition}`,
      "",
      "**Dovadă minimă necesară:**",
      "",
      ...status.evidenceRequired.map((item) => `- ${item}`),
      "",
      `**Depunere posibilă:** ${status.acceptsApplications ? "Da, numai în fereastra oficială curentă." : "Nu."}`,
      "",
      `**Label public recomandat:** „${status.publicLabel}”`,
      "",
      `**Wording public interzis:** ${status.forbiddenWording.map((item) => `„${item}”`).join("; ")}.`,
      "",
      `**Exemple de tranziții valide:** ${status.validTransitions.map((target) => `\`${status.id} → ${target}\``).join(", ")}. Fiecare cere dovada specifică stării-destinație.`
    );
  }

  lines.push(
    "",
    "## Compatibilitatea cu taxonomia legacy",
    "",
    "Valorile de mai jos sunt citite încă de suprafețele publice existente. Ele nu sunt stări canonice și nu au mapare optimistă implicită. Normalizarea folosește atribuirea explicită din fiecare înregistrare de program până la migrarea controlată a consumatorilor.",
    "",
    "| Status legacy | Stări canonice posibile | Regulă de normalizare |",
    "|---|---|---|",
    ...Object.entries(data.taxonomy.legacyCompatibility).map(([legacy, mapping]) => `| \`${legacy}\` | ${mapping.possibleCanonicalStatuses.map((status) => `\`${status}\``).join(", ")} | ${markdown(mapping.rule)} |`),
    "",
    "## Maparea snapshot-ului curent",
    "",
    `Maparea de mai jos folosește snapshot-ul factual de bază verificat în registry la **${data.sourceRegistry.factualSnapshotDate}**. Înregistrările pot avea o reverificare ulterioară, indicată individual prin \`verifiedAt\`.`,
    "",
    "| Stable program ID | Status legacy | Status canonic | Label public recomandat | Scope | Motiv |",
    "|---|---|---|---|---|---|",
    ...programRows,
    "",
    "## Păstrarea paginilor închise/finalizate",
    "",
    "`CLOSED`, `CANCELLED` și `COMPLETED` nu produc automat `noindex`, redirect sau ștergere. Decizia SEO rămâne separată și se bazează pe valoarea evergreen, unicitatea conținutului, intenția de căutare și existența unei destinații canonice mai bune. Pagina păstrată trebuie să arate clar că depunerea nu este deschisă și să indice sursa oficială verificată.",
    "",
    "## Limita Task 02",
    "",
    "Contractul canonic și rolurile surselor sunt păstrate în înregistrarea unică a programului. HTML-ul, bannerele și celelalte suprafețe continuă să consume temporar codul operațional legacy `status`, dar nu îi mai păstrează atribuirea într-un config concurent.",
  );
  return `${lines.join("\n")}\n`;
}

function renderReferences(references, program, data) {
  if (!references.length) {
    return `— Neidentificat separat în sursele oficiale înregistrate la ${program.verifiedAt}; nu se presupune inexistența documentului.`;
  }
  return references
    .map((reference) => {
      const source = resolveSourceReference(reference, program, data);
      return `${link(source.label, source.url)} (\`${source.ref}\`, verificat ${source.verifiedAt})`;
    })
    .join("<br>");
}

function renderSourceRegistry(data) {
  const lines = [
    "# Registrul surselor oficiale FABER",
    "",
    `Snapshot factual de bază al programelor: **${data.sourceRegistry.factualSnapshotDate}**. Fiecare înregistrare poate avea o reverificare mai nouă, publicată în câmpul \`verifiedAt\`. Revizia structurii registrului: **${data.sourceRegistry.registryReviewDate}**. Rolurile per program: \`config/seo-programs.json#programs[*].officialSources\`; surse suplimentare: \`config/program-source-registry.json#supplementalSources\`; catalog documente: \`official-guides.json\`. Document generat de \`tools/generate-status-governance-docs.js\`.`,
    "",
    "## Reguli de audit",
    "",
    "- Sunt acceptate numai surse primare ale autorității competente, Portalului Legislativ/Monitorului Oficial ori platformelor publice oficiale.",
    "- `Pagină oficială` este punctul stabil de pornire; `ghid`, `anexe`, `schemă/ordin`, `anunț sesiune`, `corrigenda` și `clarificări` sunt roluri distincte și nu se substituie reciproc.",
    "- Un câmp neidentificat este un gol explicit al registry-ului, nu afirmația că documentul nu există. Golul nu poate susține o stare mai optimistă.",
    "- `Latest official update` înseamnă ultima actualizare consemnată pentru program la data lui `verifiedAt`, nu o garanție că instituția nu a publicat ulterior alt document.",
    "- URL-ul accesibil nu este singur dovadă de `OPEN`; sunt obligatorii identificarea sesiunii, fereastra curentă și controlul actualizărilor ulterioare.",
    `- Cele ${FACTUAL_FIELD_LABELS.length} de categorii solicitate sunt documentate pentru fiecare program. Când sursa oficială verificată nu stabilește un câmp, fișa publică exact golul factual, fără completări speculative.`,
    "",
    "## Acoperire",
    "",
    "| Stable program ID | Autoritate | Status canonic | Ultima actualizare oficială înregistrată | Verificat |",
    "|---|---|---|---|---|",
    ...data.programs.map((program) => `| \`${program.id}\` | ${markdown(program.sourceName)} | \`${program.canonicalStatus}\` | ${markdown(program.lastMeaningfulUpdate || "—")} | ${program.verifiedAt} |`),
    ""
  ];

  for (const program of data.programs) {
    const entry = program.officialSources;
    lines.push(
      `## \`${program.id}\` — ${program.name}`,
      "",
      "| Câmp | Valoare auditabilă |",
      "|---|---|",
      `| Stable program ID | \`${program.id}\` |`,
      ...factualFieldRows(program, data),
      ...SOURCE_ROLES.map((role) => `| ${SOURCE_ROLE_LABELS[role]} | ${renderReferences(entry.roles[role], program, data)} |`),
      `| Sursă primară în registry-ul operațional | ${link(program.sourceVersion, program.sourceUrl)} (verificat ${program.verifiedAt}) |`,
      `| Chei surse repo | ${(program.officialGuideKeys || []).map((key) => `\`${key}\``).join(", ") || "—"} |`,
      `| Notes | ${markdown(entry.notes)} |`,
      ""
    );
  }

  lines.push(
    "## Jurnalul schimbărilor factuale din reverificare",
    "",
    "| Program | Câmp | Before | After | Sursă | Verificat | Motiv |",
    "|---|---|---|---|---|---|---|",
    ...data.factualChanges.map((change) => `| \`${change.programId}\` | ${markdown(change.field)} | ${markdown(change.before)} | ${markdown(change.after)} | ${link(change.sourceLabel, change.sourceUrl)} | ${change.verifiedAt} | ${markdown(change.reason)} |`),
    ""
  );

  lines.push(
    "## Goluri cunoscute și regulă de completare",
    "",
    "Multe pagini-umbrelă și câteva ediții istorice au în prezent doar un catalog oficial sau o pagină de stare, fără URL-uri distincte pentru toate rolurile documentare. Aceste goluri sunt vizibile în fiecare fișă. Completarea lor cere un document oficial verificat, adăugat mai întâi în `official-guides.json`, în catalogul suplimentar sau în registrul de aprobări și apoi referit din `config/seo-programs.json`; nu se folosesc agregatoare ori alte firme de consultanță drept source-of-truth.",
  );
  return `${lines.join("\n")}\n`;
}

function buildDocuments(data = loadData()) {
  const errors = validateData(data);
  if (errors.length) throw new Error(`Status governance invalid:\n- ${errors.join("\n- ")}`);
  return {
    status: renderStatusTaxonomy(data),
    sources: renderSourceRegistry(data)
  };
}

function sameDocumentContent(actual, expected) {
  const normalizeLineEndings = (value) => String(value).replace(/\r\n?/gu, "\n");
  return normalizeLineEndings(actual) === normalizeLineEndings(expected);
}

function checkDocuments(documents) {
  const expected = [
    [STATUS_DOC_PATH, documents.status],
    [SOURCE_DOC_PATH, documents.sources]
  ];
  const errors = [];
  for (const [file, content] of expected) {
    if (!fs.existsSync(file)) {
      errors.push(`${path.relative(ROOT, file)} lipsește.`);
    } else if (!sameDocumentContent(fs.readFileSync(file, "utf8"), content)) {
      errors.push(`${path.relative(ROOT, file)} este nesincronizat.`);
    }
  }
  return errors;
}

function main() {
  try {
    const data = loadData();
    const documents = buildDocuments(data);
    if (process.argv.includes("--check")) {
      const errors = checkDocuments(documents);
      if (errors.length) throw new Error(errors.join("\n"));
      console.log(`Status governance PASS: ${data.taxonomy.statuses.length} statuses, ${data.programs.length} programs, official source roles synchronized.`);
      return;
    }
    fs.mkdirSync(path.dirname(STATUS_DOC_PATH), { recursive: true });
    fs.writeFileSync(STATUS_DOC_PATH, documents.status, "utf8");
    fs.writeFileSync(SOURCE_DOC_PATH, documents.sources, "utf8");
    console.log(`Generated ${path.relative(ROOT, STATUS_DOC_PATH)} and ${path.relative(ROOT, SOURCE_DOC_PATH)}.`);
  } catch (error) {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  EXPECTED_STATUS_IDS,
  FACTUAL_FIELD_LABELS,
  LEGACY_STATUS_IDS,
  SOURCE_ROLES,
  buildDocuments,
  checkDocuments,
  isOfficialUrl,
  loadData,
  resolveSourceReference,
  sameDocumentContent,
  validateData
};
