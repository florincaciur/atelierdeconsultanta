#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const { HUMAN_REVIEW, loadProgramConfig } = require("../tools/program-factual-governance");
const {
  APPROVALS_PATH,
  REQUIRED_PROGRAMS,
  validateApprovalRegistry
} = require("../tools/validate-program-status-approvals");

const approvalConfig = JSON.parse(fs.readFileSync(APPROVALS_PATH, "utf8"));
const intentionalNoindex = new Set(
  JSON.parse(fs.readFileSync(path.join(ROOT, "config", "content-intent-taxonomy.json"), "utf8"))
    .blockedNonIndexableRoutes
    .map((item) => item.route)
);
const { programs } = loadProgramConfig();
const programById = new Map(programs.map((program) => [program.slug, program]));
const approvalById = new Map(approvalConfig.programs.map((row) => [row.programId, row]));
const banners = JSON.parse(fs.readFileSync(path.join(ROOT, "banners.json"), "utf8"));
const header = cheerio.load(fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8"), { decodeEntities: false });
const homepage = cheerio.load(fs.readFileSync(path.join(ROOT, "index.html"), "utf8"), { decodeEntities: false });

function filesForRoute(route) {
  const slug = route.replace(/^\/+|\/+$/g, "");
  return slug
    ? [path.join(ROOT, slug, "index.html"), path.join(ROOT, `${slug}.html`)].filter(fs.existsSync)
    : [path.join(ROOT, "index.html")];
}

function htmlFiles(directory = ROOT) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "dist", "node_modules"].includes(entry.name)) continue;
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...htmlFiles(file));
    else if (entry.isFile() && entry.name.endsWith(".html")) files.push(file);
  }
  return files;
}

assert.deepEqual(validateApprovalRegistry(approvalConfig, programs), [], "Configurația P0.02 trebuie să treacă poarta editorială");

for (const id of REQUIRED_PROGRAMS) {
  const row = approvalById.get(id);
  const program = programById.get(id);
  assert(row, `${id}: lipsește din tabelul de aprobare`);
  if (row.numericClaimsApproved !== true) {
    assert.equal(program.grantSummary, null, `${id}: grantSummary nu este aprobat numeric`);
    assert.equal(program.cofinancingSummary, null, `${id}: cofinancingSummary nu este aprobat numeric`);
  }
  if (row.approvalState === "approved") {
    assert.notEqual(row.validatorName, HUMAN_REVIEW, `${id}: aprobarea trebuie să fie nominală`);
    assert.equal(program.publicationState, "public", `${id}: rândul aprobat trebuie publicat din registru`);
    assert.equal(program.verifiedAt, row.verifiedAt || approvalConfig.researchDate, `${id}: data publică diferă de aprobare`);
    assert.equal(program.sourceUrl, row.officialUrl, `${id}: sursa publică diferă de aprobare`);
    const homepageSurfaces = homepage(`[data-program-id="${id}"][data-program-status]`);
    homepageSurfaces.each((_, surface) => {
      assert.equal(homepage(surface).attr("data-program-status"), program.status, `${id}: status homepage contradictoriu`);
      assert.equal(homepage(surface).attr("data-verified-at"), program.verifiedAt, `${id}: data homepage contradictorie`);
    });
    for (const route of row.publicationHoldUrls) {
      if (intentionalNoindex.has(route)) continue;
      const routeFiles = filesForRoute(route);
      const indexFiles = routeFiles.filter((file) => file.endsWith(`${path.sep}index.html`));
      const files = indexFiles.length ? indexFiles : routeFiles;
      assert(files.length, `${id}: lipsește ruta aprobată ${route}`);
      for (const file of files) {
        const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
        assert.doesNotMatch($("meta[name='robots']").attr("content") || "", /noindex/iu, `${route}: aprobarea a lăsat pagina noindex`);
        assert.notEqual($("body").attr("data-publication-state"), "pending_validation", `${route}: aprobarea a lăsat body pending_validation`);
        assert.equal($("main.program-validation-hold").length, 0, `${route}: aprobarea a lăsat mesajul de suspendare`);
      }
    }
  } else {
    assert.equal(row.validatorName, HUMAN_REVIEW, `${id}: un rând pending păstrează placeholderul controlat`);
    assert.equal(program.publicationState, "pending_validation", `${id}: registrul publică un rând neaprobat`);
    assert.equal(header(`[data-program-id="${id}"]`).length, 0, `${id}: apare în meniul global`);
    assert.equal(homepage(`[data-program-id="${id}"]`).length, 0, `${id}: apare pe homepage`);
    assert(!banners.some((banner) => banner.programId === id), `${id}: apare în carusel`);

    for (const route of row.publicationHoldUrls) {
      const files = filesForRoute(route);
      assert(files.length, `${id}: lipsește ruta suspendată ${route}`);
      for (const file of files) {
        const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
        assert.match($("meta[name='robots']").attr("content") || "", /noindex/iu, `${route}: nu are noindex`);
        assert.equal($("body").attr("data-publication-state"), "pending_validation", `${route}: body nu este marcat pending_validation`);
        assert.equal($("main.program-validation-hold").length, 1, `${route}: lipsește mesajul neutru de suspendare`);
        assert.equal($(`[data-program-id="${id}"][data-program-status]`).length, 0, `${route}: publică un status candidat`);
        assert.equal($("script[type='application/ld+json']").length, 0, `${route}: publică JSON-LD factual`);
        assert(!$.html().includes(row.proposedCopy), `${route}: copy-ul candidat este publicat înainte de aprobare`);
      }
    }
  }
}

for (const file of htmlFiles()) {
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  for (const id of REQUIRED_PROGRAMS.filter((programId) => approvalById.get(programId).approvalState === "pending")) {
    const program = programById.get(id);
    const route = program.pageUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const hrefPattern = new RegExp(`^(?:https://atelierdeconsultanta\\.ro)?${route}/?$`, "i");
    assert.equal($(`[data-program-id="${id}"][data-program-status]`).length, 0, `${path.relative(ROOT, file)}: componentă factuală publică pentru ${id}`);
    $("a[href]").each((_, anchor) => {
      if (!hrefPattern.test($(anchor).attr("href") || "")) return;
      const inFactSurface = $(anchor).closest("nav, footer, article.finantare-card, article.program-slide, article.core-card, article.content-card, .related-links").length;
      assert.equal(inFactSurface, 0, `${path.relative(ROOT, file)}: card/meniu/tabel neaprobat pentru ${id}`);
    });
  }
}

const missingValidator = structuredClone(approvalConfig);
missingValidator.programs[0].validatorName = HUMAN_REVIEW;
assert(validateApprovalRegistry(missingValidator, programs).some((error) => /numele consultantului|DE_VALIDAT_UMAN/iu.test(error)), "Aprobarea fără validator nominal trebuie respinsă");

const pendingApprovalConfig = structuredClone(approvalConfig);
const pendingProInfra = pendingApprovalConfig.programs.find((program) => program.programId === "pro-infra");
pendingProInfra.approvalState = "pending";
pendingProInfra.validatorName = HUMAN_REVIEW;
pendingProInfra.approvedAt = null;
assert(validateApprovalRegistry(pendingApprovalConfig, programs).some((error) => /public înainte/iu.test(error)), "Publicarea înainte de aprobarea FABER trebuie respinsă");

console.log("Poarta P0.02: rândurile aprobate sunt publice, cele disputate rămân blocate și validarea nominală este obligatorie.");
