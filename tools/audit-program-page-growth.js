#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

const ROOT = path.resolve(__dirname, "..");
const REGISTRY = path.join(ROOT, "config", "seo-programs.json");
const REPORT_MD = path.join(ROOT, "reports", "audit-integritate-programe-2026-08-15.md");
const REPORT_CSV = path.join(ROOT, "reports", "audit-integritate-programe-2026-08-15.csv");
const CHECK = process.argv.includes("--check");
const PRIORITY = new Set(["/dr14", "/dr12-afir", "/investitii-modernizarea-microintreprinderilor-apel-2"]);

function fileForRoute(route) {
  if (route === "/") return path.join(ROOT, "index.html");
  const clean = String(route).replace(/^\/+|\/+$/g, "");
  const indexFile = path.join(ROOT, clean, "index.html");
  if (fs.existsSync(indexFile)) return indexFile;
  const flatFile = path.join(ROOT, `${clean}.html`);
  return fs.existsSync(flatFile) ? flatFile : indexFile;
}

function words(value) {
  return String(value || "").match(/[\p{L}\p{N}]+(?:[’'-][\p{L}\p{N}]+)*/gu)?.length || 0;
}

function parseSchemas($, route, integrityErrors) {
  const schemas = [];
  $("script[type='application/ld+json']").each((_, node) => {
    try { schemas.push(JSON.parse($(node).text())); }
    catch (error) { integrityErrors.push(`${route}: JSON-LD invalid (${error.message})`); }
  });
  return schemas;
}

function schemaText(schemas) {
  return JSON.stringify(schemas);
}

function cap(value) { return Math.max(0, Math.min(100, Math.round(value))); }

function audit(program, sitemap) {
  const file = fileForRoute(program.pageUrl);
  const integrityErrors = [];
  if (!fs.existsSync(file)) return { program, file, integrityErrors: [`${program.pageUrl}: fișier lipsă`], issues: ["fișier lipsă"], scores: {} };
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  const title = $("title").first().text().trim();
  const meta = $("meta[name='description']").attr("content")?.trim() || "";
  const canonical = $("link[rel='canonical']").attr("href") || "";
  const expectedCanonical = `https://atelierdeconsultanta.ro${program.pageUrl}`;
  const h1Count = $("h1").length;
  const h2Count = $("main h2").length;
  const mainText = $("main").text().replace(/\s+/gu, " ").trim();
  const wordCount = words(mainText);
  const robots = $("meta[name='robots']").attr("content") || "";
  const schemas = parseSchemas($, program.pageUrl, integrityErrors);
  const structured = schemaText(schemas);
  const officialVisible = $(`a[href='${program.sourceUrl}']`).length > 0;
  const officialStructured = structured.includes(program.sourceUrl);
  const statusNode = $(`[data-program-id='${program.id}'][data-program-status]`).first();
  const statusMatches = statusNode.length > 0
    && statusNode.attr("data-program-status") === program.status
    && statusNode.attr("data-verified-at") === program.verifiedAt;
  const contactLinks = $("main a[href*='/contact']");
  const attributedCta = contactLinks.filter((_, node) => ($(node).attr("href") || "").includes(`program_slug=${program.slug}`));
  const trackedCta = contactLinks.filter((_, node) => $(node).attr("data-analytics-event") === "cta_click");
  const faqSchema = structured.includes('"FAQPage"');
  const directAnswers = $("[data-aeo-direct-answer], .aeo-question__direct, [data-expert-direct-answer]").length;
  const breadcrumb = $("[data-breadcrumb], .breadcrumb").length > 0;
  const ogComplete = Boolean($("meta[property='og:title']").attr("content") && $("meta[property='og:description']").attr("content"));
  const sourceTime = $(`time[datetime='${program.verifiedAt}']`).length > 0;
  const imagesWithoutAlt = $("main img").filter((_, node) => $(node).attr("alt") == null).length;
  const emptyButtons = $("main button").filter((_, node) => !$(node).text().trim() && !$(node).attr("aria-label")).length;
  const ambiguousLinks = $("main a").filter((_, node) => /^(click aici|aici|mai mult)$/iu.test($(node).text().trim())).length;
  const noGuarantee = /nu (?:garantează|garantăm|promite)|nu poate fi garantat|nu reprezintă o garanție/iu.test(mainText);
  const sitemapIncluded = sitemap.includes(`<loc>${expectedCanonical}</loc>`);
  const redirectTarget = program.discovery?.redirectTarget || "";
  const discoverable = sitemapIncluded || Boolean(redirectTarget);
  const titleIntent = program.shortName.split(/\s+/u).some((term) => term.length > 2 && title.toLocaleLowerCase("ro").includes(term.toLocaleLowerCase("ro")));
  const metaFact = /\d|consultativ|deschis|lansat|programat/iu.test(meta);

  if (h1Count !== 1) integrityErrors.push(`${program.pageUrl}: ${h1Count} H1`);
  if (!redirectTarget && canonical !== expectedCanonical) integrityErrors.push(`${program.pageUrl}: canonical diferit (${canonical || "lipsește"})`);
  if (!redirectTarget && /noindex/iu.test(robots)) integrityErrors.push(`${program.pageUrl}: program public marcat noindex`);
  if (!statusMatches) integrityErrors.push(`${program.pageUrl}: statusul sau data nu coincid cu registrul`);
  if (!schemas.length) integrityErrors.push(`${program.pageUrl}: JSON-LD lipsește`);

  const seo = cap((title.length >= 35 && title.length <= 68 ? 20 : 8) + (meta.length >= 105 && meta.length <= 180 ? 20 : 8) + (h1Count === 1 ? 20 : 0) + (canonical === expectedCanonical ? 20 : 0) + (!/noindex/iu.test(robots) ? 10 : 0) + (wordCount >= 500 ? 10 : 4));
  const aeo = cap((directAnswers ? 30 : 0) + (faqSchema ? 30 : 10) + (h2Count >= 4 ? 20 : 8) + (structured.includes('"FinancialIncentive"') ? 20 : 0));
  const geo = cap((officialVisible ? 30 : 0) + (officialStructured ? 30 : 0) + (sourceTime ? 20 : 0) + (structured.includes('"citation"') ? 20 : 0));
  const traditional = cap((canonical === expectedCanonical ? 25 : 0) + (h1Count === 1 ? 25 : 0) + (!/noindex/iu.test(robots) ? 20 : 0) + (discoverable ? 20 : 0) + (wordCount >= 500 ? 10 : 4));
  const visibility = cap((discoverable ? 30 : 0) + (breadcrumb ? 20 : 0) + (ogComplete ? 20 : 0) + (statusMatches ? 30 : 0));
  const accessibility = cap((h1Count === 1 ? 30 : 0) + (imagesWithoutAlt === 0 ? 25 : 0) + (emptyButtons === 0 ? 25 : 0) + (ambiguousLinks === 0 ? 20 : 0));
  const cta = cap((contactLinks.length ? 20 : 0) + (attributedCta.length ? 35 : 0) + (trackedCta.length ? 25 : 0) + (noGuarantee ? 20 : 8));
  const ctr = cap((titleIntent ? 25 : 8) + (title.length >= 35 && title.length <= 68 ? 20 : 8) + (metaFact ? 20 : 8) + (ogComplete ? 15 : 0) + (attributedCta.length ? 20 : 5));

  const issues = [];
  if (!directAnswers) issues.push("lipsește răspunsul AEO direct");
  if (!faqSchema) issues.push("FAQ schema absentă");
  if (!officialVisible) issues.push("sursa oficială nu este vizibilă");
  if (!sourceTime) issues.push("data verificării nu este vizibilă semantic");
  if (!attributedCta.length) issues.push("CTA fără program_slug");
  if (!trackedCta.length) issues.push("CTA fără tracking");
  if (!noGuarantee) issues.push("disclaimerul de rezultat poate fi întărit");
  if (imagesWithoutAlt) issues.push(`${imagesWithoutAlt} imagini fără alt`);
  if (emptyButtons) issues.push(`${emptyButtons} butoane fără nume accesibil`);
  if (!sitemapIncluded && !redirectTarget) issues.push("URL absent din sitemap");
  if (redirectTarget) issues.push(`rută consolidată prin redirect către ${redirectTarget}`);
  if (wordCount < 500) issues.push(`conținut subțire (${wordCount} cuvinte)`);

  return {
    program,
    file,
    integrityErrors,
    issues,
    metrics: { wordCount, h1Count, h2Count, contactLinks: contactLinks.length, attributedCta: attributedCta.length },
    scores: { seo, aeo, geo, traditional, visibility, accessibility, cta, ctr }
  };
}

function csvCell(value) { return `"${String(value ?? "").replace(/"/g, '""')}"`; }

function reports(results, integrityErrors) {
  const generated = "2026-08-15";
  const avg = (key) => Math.round(results.reduce((sum, row) => sum + (row.scores[key] || 0), 0) / results.length);
  const headers = ["Program", "URL", "SEO", "AEO", "GEO", "Căutare tradițională", "Vizibilitate", "Accesibilitate", "CTA", "CTR", "Cuvinte", "Probleme/oportunități"];
  const csv = [headers.map(csvCell).join(","), ...results.map((row) => [
    row.program.shortName, row.program.pageUrl, row.scores.seo, row.scores.aeo, row.scores.geo, row.scores.traditional,
    row.scores.visibility, row.scores.accessibility, row.scores.cta, row.scores.ctr, row.metrics?.wordCount || 0,
    row.issues.join("; ") || "fără problemă detectată automat"
  ].map(csvCell).join(","))].join("\n") + "\n";

  const priorityDetails = results.filter((row) => PRIORITY.has(row.program.pageUrl)).map((row) => {
    const scores = Object.entries(row.scores).map(([key, value]) => `${key.toUpperCase()} ${value}`).join(" · ");
    return `### ${row.program.shortName} — ${row.program.pageUrl}\n\n- Scoruri: ${scores}.\n- CTA atribuite: ${row.metrics.attributedCta}; cuvinte: ${row.metrics.wordCount}; H2: ${row.metrics.h2Count}.\n- Oportunități rămase: ${row.issues.join("; ") || "nicio problemă automată de nivel ridicat"}.`;
  }).join("\n\n");

  const table = results.map((row) => `| ${row.program.shortName} | ${row.program.pageUrl} | ${row.scores.seo} | ${row.scores.aeo} | ${row.scores.geo} | ${row.scores.traditional} | ${row.scores.visibility} | ${row.scores.accessibility} | ${row.scores.cta} | ${row.scores.ctr} | ${row.issues.join("; ") || "—"} |`).join("\n");
  const md = `# Audit de integritate și creștere — pagini de programe\n\nData auditului: **${generated}**. Registru auditat: toate programele publice din \`config/seo-programs.json\`. Scorurile sunt semnale tehnice 0–100, nu estimări de trafic, clasare sau conversie.\n\n## Rezultat executiv\n\n- Pagini publice auditate: **${results.length}**.\n- Erori de integritate blocante: **${integrityErrors.length}**.\n- Medii: SEO **${avg("seo")}**, AEO **${avg("aeo")}**, GEO **${avg("geo")}**, căutare tradițională **${avg("traditional")}**, vizibilitate **${avg("visibility")}**, accesibilitate **${avg("accessibility")}**, CTA **${avg("cta")}**, CTR **${avg("ctr")}**.\n- CSV pentru filtrare: \`reports/audit-integritate-programe-2026-08-15.csv\`.\n\n${integrityErrors.length ? `## Erori blocante\n\n${integrityErrors.map((error) => `- ${error}`).join("\n")}\n\n` : "## Integritate\n\nNu au fost detectate pagini lipsă, canonicale corupte, H1 duplicat, JSON-LD invalid, programe publice noindex sau statusuri divergente față de registru.\n\n"}## Cele trei pagini prioritare\n\n${priorityDetails}\n\n## Matrice completă\n\n| Program | URL | SEO | AEO | GEO | Tradițional | Vizibilitate | Accesibilitate | CTA | CTR | Oportunități |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|\n${table}\n\n## Ordinea recomandată a îmbunătățirilor\n\n1. Adaugă răspunsuri directe și FAQ schema paginilor marcate cu deficit AEO, numai pe întrebări susținute de surse oficiale.\n2. Adaugă CTA atribuit cu \`program_slug\` paginilor care trimit generic către contact; aceasta permite calculul cost/contract pe program.\n3. Publică data verificării în elemente \`time\` și păstrează sursa oficială atât vizibil, cât și în JSON-LD pentru GEO.\n4. Întărește disclaimerul de rezultat pe paginile unde lipsește, fără a slăbi CTA-ul.\n5. Testează titlul, meta description și textul CTA în experimente izolate; decide pe CTR calificat și contracte, nu doar pe clickuri.\n\n## Metodă\n\nAuditul verifică HTML-ul local, registrul unic, sitemapul și datele structurate. Categoriile includ title/meta/H1/canonical/indexare, răspunsuri directe și FAQ, citarea sursei oficiale, includerea în sitemap și breadcrumb, nume accesibile, atribuirea și trackingul CTA, plus semnale de claritate pentru snippet și CTR. Verificarea umană și testele cu trafic real rămân necesare.\n`;
  return { md, csv };
}

function main() {
  const config = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const sitemap = fs.readdirSync(ROOT)
    .filter((name) => /^sitemap(?:-[a-z0-9-]+)?\.xml$/iu.test(name))
    .map((name) => fs.readFileSync(path.join(ROOT, name), "utf8"))
    .join("\n");
  const programs = config.programs.filter((program) => program.publicationState === "public");
  const results = programs.map((program) => audit(program, sitemap));
  const integrityErrors = results.flatMap((row) => row.integrityErrors);
  const output = reports(results, integrityErrors);
  if (CHECK) {
    if (!fs.existsSync(REPORT_MD) || fs.readFileSync(REPORT_MD, "utf8") !== output.md) throw new Error("Raportul Markdown de audit nu este sincronizat");
    if (!fs.existsSync(REPORT_CSV) || fs.readFileSync(REPORT_CSV, "utf8") !== output.csv) throw new Error("Raportul CSV de audit nu este sincronizat");
  } else {
    fs.writeFileSync(REPORT_MD, output.md, "utf8");
    fs.writeFileSync(REPORT_CSV, output.csv, "utf8");
  }
  if (integrityErrors.length) throw new Error(`Auditul a găsit ${integrityErrors.length} erori blocante:\n- ${integrityErrors.join("\n- ")}`);
  console.log(`Audit programe PASS: ${results.length} pagini, 0 erori blocante.`);
}

if (require.main === module) main();
module.exports = { audit, fileForRoute, reports };
