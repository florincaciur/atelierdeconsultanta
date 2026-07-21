#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { collectSiteState } = require("./generate-sitemap");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const TAXONOMY_PATH = path.join(ROOT, "config", "content-intent-taxonomy.json");
const GOVERNANCE_PATH = path.join(ROOT, "config", "editorial-governance.json");
const PROGRAMS_PATH = path.join(ROOT, "config", "seo-programs.json");
const CONSOLIDATION_PATH = path.join(ROOT, "config", "url-consolidation-candidates.json");
const REPORT_JSON_PATH = path.join(ROOT, "reports", "content-intent-inventory-2026-07-21.json");
const REPORT_CSV_PATH = path.join(ROOT, "reports", "content-intent-inventory-2026-07-21.csv");
const REPORT_HTML_PATH = path.join(ROOT, "reports", "content-intent-inventory-2026-07-21.html");
const REPORT_MD_PATH = path.join(ROOT, "reports", "content-intent-architecture-2026-07-21.md");

const SERVICE_ROUTE_RE = /(?:consultant|consultanta|management-proiecte|plan-de-afaceri|proiectare|studiu-fezabilitate|verificare-eligibilitate)/u;
const QUESTION_PREFIX = "/intrebari/";
const CAEN_PREFIX = "/fonduri-europene-caen/";

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function clip(value, max = 240) {
  const text = cleanText(value);
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1).replace(/\s+\S*$/u, "")}…`;
}

function isoAddDays(iso, days) {
  const date = new Date(`${iso}T12:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function routeMatches(route, patterns) {
  return patterns.some((pattern) => new RegExp(pattern, "u").test(route));
}

function loadContext() {
  const taxonomy = loadJson(TAXONOMY_PATH);
  const governance = loadJson(GOVERNANCE_PATH);
  const programs = loadJson(PROGRAMS_PATH);
  const consolidation = loadJson(CONSOLIDATION_PATH);
  return {
    taxonomy,
    governanceByRoute: new Map(governance.records.map((record) => [record.route, record])),
    programsByRoute: new Map(programs.programs.map((program) => [program.pageUrl, program])),
    consolidationByRoute: new Map(consolidation.rows.map((row) => [row.url, row])),
  };
}

function inspectPage(entry) {
  const absolute = path.join(ROOT, entry.sourceFile);
  const html = fs.readFileSync(absolute, "utf8");
  const $ = cheerio.load(html);
  const h1 = cleanText($("h1").first().text());
  const title = cleanText($("title").first().text());
  const description = cleanText($('meta[name="description"]').attr("content"));
  const main = $("main").length ? $("main") : $("body");
  const headings = main.find("h2, h3").filter((_, element) => cleanText($(element).text()).length > 2).length;
  const faqQuestions = Math.max(
    main.find('[itemprop="name"]').filter((_, element) => $(element).closest('[itemtype*="Question"]').length > 0).length,
    main.find("details > summary").length,
    main.find(".faq-item, .faq-question").length,
  );
  const externalLinks = new Set();
  main.find('a[href^="http"]').each((_, element) => {
    try {
      const url = new URL($(element).attr("href"));
      if (url.origin !== SITE) externalLinks.add(url.href);
    } catch {
      // Invalid links are handled by the technical crawler, not this inventory.
    }
  });
  const controls = main.find("input, select, textarea, button").length;
  const preferredCta = main.find("[data-content-primary-cta]").first();
  const ctaCandidates = preferredCta.length
    ? preferredCta
    : main.find('a[href^="/contact"], a[href^="tel:"], a[href^="mailto:"], a[href*="wa.me"], [data-analytics-event="cta_click"]');
  let cta = null;
  ctaCandidates.each((_, element) => {
    if (cta) return;
    const text = cleanText($(element).text()) || cleanText($(element).attr("aria-label"));
    if (!text) return;
    cta = {
      text: clip(text, 90),
      href: $(element).attr("href") || "",
      id: $(element).attr("data-analytics-cta-id") || $(element).attr("data-cta-id") || "",
    };
  });
  return { html, h1, title, description, headings, faqQuestions, externalLinks: externalLinks.size, controls, cta };
}

function classifyType(entry, route, taxonomy) {
  const override = taxonomy.routeOverrides[route];
  if (override?.type) return override.type;
  if (entry.family === "programs") return "program";
  if (route.startsWith(QUESTION_PREFIX)) return "întrebare";
  if (taxonomy.serviceRoutes.includes(route) || SERVICE_ROUTE_RE.test(route.slice(1))) return "serviciu";
  if (taxonomy.hubRoutes.includes(route)) return "hub";
  if (route === "/politica-de-confidentialitate" || route === "/termeni-si-conditii") return "legal";
  if (route.includes("studii-de-caz")) return "studiu_de_caz";
  if (route.includes("calculator") || route.includes("calendar-")) return "instrument";
  return "ghid";
}

function classifyIntent(type, route, taxonomy) {
  const override = taxonomy.routeOverrides[route];
  if (override?.intent) return override.intent;
  if (routeMatches(route, taxonomy.scaledPatterns) && /bucuresti|nord-est/u.test(route)) return "locală";
  if (type === "serviciu" || route === "/") return "comercială";
  if (["legal", "hub", "core"].includes(type)) return "navigațională";
  return "informațională";
}

function audienceFor(route, type) {
  if (type === "legal") return "Vizitatori, lead-uri și persoane vizate";
  if (route === "/despre-faber") return "Decidenți care evaluează furnizorul";
  if (route === "/contact") return "Solicitanți pregătiți pentru triere";
  if (/institutii-publice|public/u.test(route)) return "Instituții publice și UAT-uri";
  if (/afir|agric|ferm|gal|dr12|dr14|soc/u.test(route)) return "Fermieri și antreprenori agroalimentari";
  if (/digital|pocidif|erp|crm|cloud/u.test(route)) return "IMM-uri care planifică digitalizarea";
  if (/start-up|femeia-antreprenor|idei-afaceri/u.test(route)) return "Antreprenori și viitori antreprenori";
  if (/fotovolta|energie|e-move|modernizare/u.test(route)) return "Companii și entități cu investiții energetice";
  if (/bucuresti|nord-est|regional|por-/u.test(route)) return "Solicitanți din regiunea vizată";
  if (route.startsWith(CAEN_PREFIX)) return "IMM-uri din activitatea CAEN vizată";
  if (type === "serviciu") return "Decidenți care caută sprijin pentru proiect";
  return "Solicitanți și beneficiari potențiali";
}

function mainQuestionFor(type, route, h1) {
  const subject = h1 || route.replace(/^\//u, "").replace(/[/-]+/gu, " ");
  if (route === "/") return "Cum poate FABER verifica și pregăti prudent un proiect înainte de dosar?";
  if (route === "/despre-faber") return "Cine este FABER și cum verifică informația și proiectele?";
  if (route === "/contact") return "Cum poate un solicitant transmite datele minime pentru trierea proiectului?";
  if (type === "program") return `Care este statutul verificat și ce trebuie analizat pentru „${subject}”?`;
  if (type === "serviciu") return `Ce include și când este potrivit serviciul „${subject}”?`;
  if (type === "hub") return `Unde găsește utilizatorul traseele și resursele relevante pentru „${subject}”?`;
  if (type === "instrument") return `Cum poate utilizatorul calcula sau verifica „${subject}”?`;
  if (type === "întrebare") return /\?$/u.test(subject) ? subject : `${subject}?`;
  if (type === "legal") return `Ce reguli și drepturi explică „${subject}”?`;
  if (type === "studiu_de_caz") return `Ce dovezi și lecții verificabile oferă „${subject}”?`;
  return `Ce trebuie să știe solicitantul despre „${subject}”?`;
}

function derivedCluster(route, h1) {
  const routeTerms = route.replace(/^\//u, "").replace(/[/-]+/gu, " ");
  const h1Terms = cleanText(h1).replace(/[|–—:]/gu, " ").split(/\s+/u).slice(0, 9).join(" ");
  return clip(`${routeTerms}; ${h1Terms}`, 180);
}

function parentFor(type, route, taxonomy) {
  const override = taxonomy.routeOverrides[route];
  if (override?.parent) return override.parent;
  if (route.startsWith(QUESTION_PREFIX)) return "/intrebari-frecvente";
  if (route.startsWith(CAEN_PREFIX)) return "/fonduri-europene-imm";
  if (type === "serviciu") return "/consultanta-fonduri-europene";
  if (type === "program") {
    if (/afir|gal|agro/u.test(route)) return "/afir";
    if (/fotovolta|energie|e-move|modernizare|autoconsum/u.test(route)) return "/finantari-panouri-fotovoltaice";
    if (/femeia|start-up/u.test(route)) return "/fonduri-europene-imm";
    if (/regional|por-/u.test(route)) return "/fonduri-europene";
    return "/fonduri-europene";
  }
  if (type === "hub") return "/fonduri-europene";
  if (type === "instrument") return "/instrumente";
  if (type === "legal" || type === "core") return "/";
  if (type === "studiu_de_caz") return "/resurse";
  if (/afir|agric|ferm|gal|dr12|dr14/u.test(route)) return "/fonduri-europene-agricultura";
  if (/digital|pocidif|erp|crm|cloud/u.test(route)) return "/fonduri-europene-digitalizare";
  if (/start-up|femeia-antreprenor|caen|idei-afaceri/u.test(route)) return "/fonduri-europene-imm";
  if (/fotovolta|energie|e-move|modernizare|autoconsum/u.test(route)) return "/finantari-panouri-fotovoltaice";
  return "/ghiduri";
}

function competitorsFor(route, taxonomy, consolidationByRoute) {
  const competitors = new Set();
  for (const group of taxonomy.competitorGroups) {
    if (!group.includes(route)) continue;
    for (const member of group) if (member !== route) competitors.add(member);
  }
  const p0 = consolidationByRoute.get(route);
  if (p0) {
    for (const row of consolidationByRoute.values()) {
      if (row.group === p0.group && row.url !== route) competitors.add(row.url);
    }
  }
  return [...competitors].sort();
}

function recommendationFor(type, route, page, taxonomy) {
  const override = taxonomy.routeOverrides[route];
  if (override?.recommendation) return override.recommendation;
  if (routeMatches(route, taxonomy.scaledPatterns)) return "rewrite";
  if (type === "legal") return "rewrite";
  if (type === "studiu_de_caz" && page.headings < 2) return "rewrite";
  return "keep";
}

function targetPromise(type, h1) {
  const subject = h1 || "subiectul paginii";
  const promises = {
    core: `Orientează utilizatorul clar către oferta și următorul pas relevant pentru „${subject}”.`,
    serviciu: `Explică livrabilul, limitele și traseul de lucru pentru „${subject}”.`,
    hub: `Ordonează într-un singur punct opțiunile și traseele pentru „${subject}”.`,
    program: `Centralizează statutul, sursa oficială și pașii de verificare pentru „${subject}”.`,
    ghid: `Răspunde complet la întrebarea principală despre „${subject}” înainte de CTA.`,
    instrument: `Produce un rezultat orientativ și explică limitele lui pentru „${subject}”.`,
    întrebare: `Oferă un răspuns direct, documentat și legătura către ghidul complet pentru „${subject}”.`,
    legal: `Prezintă versiunea aprobată și regulile aplicabile pentru „${subject}”.`,
    studiu_de_caz: `Arată dovezi verificabile, context și lecții transferabile pentru „${subject}”.`,
  };
  return promises[type];
}

function uniqueEvidence(route, type, recommendation, competitors, page, program) {
  if (recommendation === "merge") {
    return `Valoarea distinctă nu este demonstrată față de ${competitors.join(", ") || "URL-ul țintă"}; conținutul unic trebuie inventariat înainte de consolidare.`;
  }
  if (route.startsWith(CAEN_PREFIX)) {
    return "Pagina are un CAEN specific, dar experiența, oferta și dovezile unice pentru acel CAEN necesită validare umană.";
  }
  if (/bucuresti/u.test(route)) {
    return "Semnal local prezent în conținut; dovada unei oferte/experiențe locale distincte necesită validare umană.";
  }
  if (type === "program" && program) {
    const source = program.sourceName && program.sourceName !== "DE_VALIDAT_UMAN" ? program.sourceName : "sursă în validare";
    return `Înregistrare în registrul unic al programelor; ${page.headings} subtitluri, ${page.faqQuestions} FAQ și sursă: ${source}.`;
  }
  if (type === "instrument") return `${page.controls} controale interactive, ${page.headings} subtitluri explicative și ${page.externalLinks} linkuri externe.`;
  if (type === "întrebare") return `Răspuns focalizat pe o singură întrebare; ${page.headings} subtitluri și ${page.externalLinks} linkuri externe.`;
  return `${page.headings} subtitluri distincte, ${page.faqQuestions} FAQ și ${page.externalLinks} linkuri externe în sursa HTML.`;
}

function fallbackCta(type) {
  const values = {
    core: ["Alege următorul pas", "navigation_click", "/"],
    serviciu: ["Solicită verificarea inițială", "form_start", "/contact"],
    hub: ["Deschide resursa relevantă", "child_page_click", "/fonduri-europene"],
    program: ["Verifică proiectul", "service_or_form_click", "/contact"],
    ghid: ["Vezi următorul pas", "related_service_click", "/consultanta-fonduri-europene"],
    instrument: ["Folosește instrumentul", "tool_complete", "/instrumente"],
    întrebare: ["Citește ghidul complet", "guide_click", "/ghiduri"],
    legal: ["Contact pentru clarificări", "legal_contact", "/contact"],
    studiu_de_caz: ["Vezi metodologia", "methodology_click", "/metodologie-verificare-eligibilitate"],
  };
  return values[type];
}

function ctaFor(type, route, page, taxonomy) {
  const override = taxonomy.routeOverrides[route];
  const fallback = fallbackCta(type);
  return {
    cta: override?.cta || page.cta?.text || fallback[0],
    microConversion: override?.microConversion || (page.cta?.id ? `cta_click:${page.cta.id}` : fallback[1]),
    ctaTarget: override?.ctaTarget || page.cta?.href || fallback[2],
  };
}

function recommendationReason(route, type, recommendation, target, competitors, p0, scaled) {
  if (recommendation === "merge") return `Intenția se suprapune cu ${target || competitors[0]}; se păstrează doar conținutul unic după aprobarea SEO/business.`;
  if (recommendation === "noindex") return "Nu este demonstrată o valoare indexabilă unică; decizia editorială este obligatorie înainte de aplicare.";
  if (scaled) return "Pagina locală/CAEN poate rămâne numai cu experiență, ofertă și conținut unic demonstrabil; necesită rescriere și validare.";
  if (p0?.recommendation === "KEEP_UNIQUE_CONDITIONAL") return "Rol distinct condiționat în harta P0.09; trebuie eliminată suprapunerea și aprobat KPI-ul propriu.";
  if (recommendation === "rewrite") return `Rolul de ${type} este util, dar promisiunea, query clusterul sau diferențierea față de URL-urile apropiate trebuie clarificate.`;
  return `Rol distinct de ${type}, cu o singură intenție primară și conversie proprie.`;
}

function reviewFor(type, route, taxonomy, governanceRecord) {
  const owner = taxonomy.owners[type];
  if (governanceRecord?.nextReviewAt) return { owner, nextReviewAt: governanceRecord.nextReviewAt };
  const days = taxonomy.reviewCadenceDays[type];
  return { owner, nextReviewAt: days == null ? "DE_VALIDAT_UMAN" : isoAddDays(taxonomy.reportDate, days) };
}

function buildRows(context) {
  const { taxonomy, governanceByRoute, programsByRoute, consolidationByRoute } = context;
  const state = collectSiteState();
  return state.entries
    .slice()
    .sort((a, b) => a.route.localeCompare(b.route, "ro"))
    .map((entry) => {
      const route = entry.route;
      const override = taxonomy.routeOverrides[route] || {};
      const page = inspectPage(entry);
      const type = classifyType(entry, route, taxonomy);
      const primaryIntent = classifyIntent(type, route, taxonomy);
      const parent = parentFor(type, route, taxonomy);
      const competitors = competitorsFor(route, taxonomy, consolidationByRoute);
      const recommendation = recommendationFor(type, route, page, taxonomy);
      const target = override.target || null;
      const program = programsByRoute.get(route) || null;
      const governanceRecord = governanceByRoute.get(route) || null;
      const p0 = consolidationByRoute.get(route) || null;
      const scaled = routeMatches(route, taxonomy.scaledPatterns);
      const { owner, nextReviewAt } = reviewFor(type, route, taxonomy, governanceRecord);
      const { cta, microConversion, ctaTarget } = ctaFor(type, route, page, taxonomy);
      const decisionState = recommendation === "merge" || recommendation === "noindex" || scaled || Boolean(p0?.approvalBlockers?.length)
        ? "APROBARE_UMANĂ_NECESARĂ"
        : "APROBAT_PENTRU_ARHITECTURĂ";
      return {
        url: entry.url,
        route,
        sourceFile: entry.sourceFile.replace(/\\/gu, "/"),
        sitemapFamily: entry.family,
        type,
        primaryAudience: audienceFor(route, type),
        mainQuestion: mainQuestionFor(type, route, page.h1),
        queryCluster: override.queryCluster || p0?.queryCluster || derivedCluster(route, page.h1),
        primaryIntent,
        h1: page.h1 || "LIPSĂ_H1",
        uniquePromise: targetPromise(type, page.h1),
        cta,
        ctaTarget,
        microConversion,
        parent,
        competingUrls: competitors,
        demonstrableUniqueValue: uniqueEvidence(route, type, recommendation, competitors, page, program),
        recommendation,
        recommendationTarget: target,
        recommendationReason: recommendationReason(route, type, recommendation, target, competitors, p0, scaled),
        decisionState,
        owner,
        nextReviewAt,
        evidence: {
          title: page.title,
          metaDescription: page.description,
          headingCount: page.headings,
          faqCount: page.faqQuestions,
          externalLinkCount: page.externalLinks,
          interactiveControlCount: page.controls,
          governanceState: governanceRecord?.governanceState || "NEÎNREGISTRAT",
          programRegistryState: program?.publicationState || "NU_ESTE_PROGRAM_ÎN_REGISTRU",
        },
      };
    });
}

function blockedDecisions(rows, context) {
  const blocked = [];
  for (const row of rows) {
    if (row.decisionState !== "APROBARE_UMANĂ_NECESARĂ") continue;
    const p0 = context.consolidationByRoute.get(row.route);
    blocked.push({
      route: row.route,
      decision: row.recommendation,
      target: row.recommendationTarget,
      reason: row.recommendationReason,
      requiredApproval: p0?.approvalBlockers?.join("; ") || (row.route.startsWith(CAEN_PREFIX) || /bucuresti/u.test(row.route)
        ? "Owner business confirmă experiența/oferta unică; SEO lead validează query și KPI"
        : "SEO lead + owner de conținut aprobă decizia și migrarea"),
    });
  }
  for (const item of context.taxonomy.blockedNonIndexableRoutes) {
    blocked.push({
      route: item.route,
      decision: "în afara inventarului canonic",
      target: null,
      reason: item.reason,
      requiredApproval: "Aprobarea factuală/juridică/SEO indicată în poarta P0",
    });
  }
  return blocked;
}

function csvEscape(value) {
  const text = Array.isArray(value) ? value.join(" | ") : String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function makeCsv(rows) {
  const columns = [
    ["URL", "url"], ["Rută", "route"], ["Tip", "type"], ["Public principal", "primaryAudience"],
    ["Întrebare principală", "mainQuestion"], ["Query cluster", "queryCluster"], ["Intenție primară", "primaryIntent"],
    ["H1", "h1"], ["Promisiune unică țintă", "uniquePromise"], ["CTA", "cta"], ["Țintă CTA", "ctaTarget"], ["Micro-conversie", "microConversion"],
    ["Părinte", "parent"], ["URL-uri concurente", "competingUrls"], ["Valoare unică demonstrabilă", "demonstrableUniqueValue"],
    ["Recomandare", "recommendation"], ["Țintă recomandată", "recommendationTarget"], ["Motiv", "recommendationReason"],
    ["Stare decizie", "decisionState"], ["Owner", "owner"], ["Următoarea revizie", "nextReviewAt"],
    ["Fișier sursă", "sourceFile"], ["Familie sitemap", "sitemapFamily"],
  ];
  return `${columns.map(([label]) => csvEscape(label)).join(",")}\n${rows.map((row) => columns.map(([, key]) => csvEscape(row[key])).join(",")).join("\n")}\n`;
}

function makeHtml(report) {
  const safeJson = JSON.stringify(report.rows).replace(/</gu, "\\u003c");
  return `<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>P1.01 — Inventar URL → intenție</title>
  <style>
    :root{font-family:Inter,system-ui,sans-serif;color:#18221c;background:#f4f6f3}body{margin:0;padding:24px}h1{margin:.2rem 0}p{max-width:80ch}.filters{position:sticky;top:0;z-index:2;display:grid;grid-template-columns:2fr repeat(3,minmax(150px,1fr));gap:10px;padding:14px 0;background:#f4f6f3}label{font-weight:650;font-size:.85rem}input,select{display:block;width:100%;box-sizing:border-box;margin-top:5px;padding:10px;border:1px solid #9aa79e;border-radius:6px;background:white}.summary{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}.summary span{background:#e4ece6;padding:8px 12px;border-radius:999px}.table-wrap{overflow:auto;border:1px solid #c8d0ca;background:#fff}table{border-collapse:collapse;min-width:2300px;width:100%;font-size:13px}th,td{padding:9px;border-bottom:1px solid #e1e5e2;vertical-align:top;text-align:left}th{position:sticky;top:88px;background:#233d2d;color:#fff}tr:hover{background:#f3f8f4}.badge{white-space:nowrap;font-weight:700}.blocked{color:#9b2c2c}a{color:#0f6033}code{white-space:nowrap}@media(max-width:800px){body{padding:12px}.filters{grid-template-columns:1fr 1fr}th{top:150px}}
  </style>
</head>
<body>
  <h1>P1.01 — Inventar „un URL, o intenție”</h1>
  <p>Snapshot local al URL-urilor canonice/indexabile după P0. Recomandările <code>merge</code> și <code>noindex</code> sunt doar candidate și nu execută redirecturi sau schimbări de indexare.</p>
  <div class="summary"><span id="visible"></span><span>Total: ${report.rows.length}</span><span>Data: ${report.generatedAt}</span></div>
  <div class="filters" aria-label="Filtre inventar">
    <label>Caută<input id="q" type="search" placeholder="URL, H1, cluster, public…"></label>
    <label>Tip<select id="type"><option value="">Toate</option></select></label>
    <label>Intenție<select id="intent"><option value="">Toate</option></select></label>
    <label>Recomandare<select id="recommendation"><option value="">Toate</option></select></label>
  </div>
  <div class="table-wrap"><table><thead><tr><th>URL</th><th>Tip</th><th>Public</th><th>Întrebare principală</th><th>Cluster</th><th>Intenție</th><th>H1</th><th>Promisiune unică</th><th>CTA / țintă / micro-conversie</th><th>Părinte</th><th>Concurenți</th><th>Valoare demonstrabilă</th><th>Decizie</th><th>Owner / revizie</th></tr></thead><tbody id="rows"></tbody></table></div>
<script>
const data=${safeJson};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const unique=k=>[...new Set(data.map(r=>r[k]))].sort((a,b)=>a.localeCompare(b,'ro'));
for(const [id,key] of [['type','type'],['intent','primaryIntent'],['recommendation','recommendation']]){const select=document.getElementById(id);for(const value of unique(key))select.insertAdjacentHTML('beforeend',\`<option>\${esc(value)}</option>\`)}
function render(){const q=document.getElementById('q').value.toLocaleLowerCase('ro');const type=document.getElementById('type').value;const intent=document.getElementById('intent').value;const rec=document.getElementById('recommendation').value;const filtered=data.filter(r=>(!q||JSON.stringify(r).toLocaleLowerCase('ro').includes(q))&&(!type||r.type===type)&&(!intent||r.primaryIntent===intent)&&(!rec||r.recommendation===rec));document.getElementById('visible').textContent=\`Afișate: \${filtered.length}\`;document.getElementById('rows').innerHTML=filtered.map(r=>\`<tr><td><a href="\${esc(r.url)}">\${esc(r.route)}</a></td><td>\${esc(r.type)}</td><td>\${esc(r.primaryAudience)}</td><td>\${esc(r.mainQuestion)}</td><td>\${esc(r.queryCluster)}</td><td>\${esc(r.primaryIntent)}</td><td>\${esc(r.h1)}</td><td>\${esc(r.uniquePromise)}</td><td>\${esc(r.cta)}<br><code>\${esc(r.ctaTarget)}</code><br><code>\${esc(r.microConversion)}</code></td><td><code>\${esc(r.parent)}</code></td><td>\${esc(r.competingUrls.join(' · '))}</td><td>\${esc(r.demonstrableUniqueValue)}</td><td><span class="badge \${r.decisionState.includes('NECESAR')?'blocked':''}">\${esc(r.recommendation)}</span><br>\${esc(r.recommendationReason)}<br><small>\${esc(r.decisionState)}</small></td><td>\${esc(r.owner)}<br><code>\${esc(r.nextReviewAt)}</code></td></tr>\`).join('')}
for(const element of document.querySelectorAll('input,select'))element.addEventListener('input',render);render();
</script>
</body></html>\n`;
}

function makeMarkdown(report) {
  const counts = (key) => Object.entries(report.summary[key]).sort((a, b) => a[0].localeCompare(b[0], "ro")).map(([label, count]) => `- ${label}: **${count}**`).join("\n");
  const blockedRows = report.blockedDecisions.map((item) => `| \`${item.route}\` | ${item.decision} | ${item.target ? `\`${item.target}\`` : "—"} | ${item.reason.replace(/\|/gu, "\\|")} | ${item.requiredApproval.replace(/\|/gu, "\\|")} |`).join("\n");
  return `# P1.01 — Inventar de conținut și harta de intenții

Data snapshot-ului: **${report.generatedAt}**

Sursă: sitemap-ul local generat după consolidările P0
Acoperire: **${report.rows.length}/${report.summary.canonicalUrlCount} URL-uri canonice/indexabile**

## Rezumat

### Tipuri

${counts("byType")}

### Recomandări

${counts("byRecommendation")}

` + "```mermaid\ngraph TD\n  HOME[\"/ — core comercial\"] --> SERV[\"/consultanta-fonduri-europene — servicii\"]\n  HOME --> FUND[\"/fonduri-europene — hub finanțări\"]\n  HOME --> RES[\"/resurse — hub editorial\"]\n  HOME --> TRUST[\"Despre · Contact · Legal\"]\n  SERV --> SVCP[\"Servicii specializate\"]\n  FUND --> AFIR[\"AFIR / agricultură\"]\n  FUND --> IMM[\"IMM / antreprenoriat\"]\n  FUND --> DIGI[\"Digitalizare\"]\n  FUND --> ENERGY[\"Energie / fotovoltaice\"]\n  FUND --> REG[\"Regional\"]\n  AFIR --> PROG[\"Pagini de program\"]\n  IMM --> PROG\n  DIGI --> PROG\n  ENERGY --> PROG\n  REG --> PROG\n  RES --> GUIDES[\"Ghiduri\"]\n  RES --> QUESTIONS[\"Întrebări\"]\n  RES --> TOOLS[\"Instrumente\"]\n  RES --> CASES[\"Studii de caz / webinarii\"]\n```\n" + `
## Reguli aplicate

- Fiecare rând are exact o intenție primară controlată.
- Paginile de program au părinte tematic și conduc către un serviciu sau formular prin micro-conversie.
- Ghidurile au rol informațional și CTA ulterior către următorul pas.
- Paginile locale și CAEN sunt marcate pentru rescriere până la demonstrarea unei oferte și experiențe unice.
- \`merge\` și \`noindex\` sunt recomandări, nu acțiuni. Niciun redirect și nicio schimbare de indexare nu este produsă de acest task.

## Decizii blocate

| URL | Decizie propusă | Țintă | Motiv | Aprobare/dovadă necesară |
|---|---|---|---|---|
${blockedRows}

## Livrabile

- Tabel filtrabil: \`reports/content-intent-inventory-2026-07-21.html\`
- CSV: \`reports/content-intent-inventory-2026-07-21.csv\`
- Date complete și dovezi: \`reports/content-intent-inventory-2026-07-21.json\`
- Taxonomie și reguli: \`config/content-intent-taxonomy.json\`
`;
}

function countBy(rows, key) {
  return rows.reduce((result, row) => {
    result[row[key]] = (result[row[key]] || 0) + 1;
    return result;
  }, {});
}

function makeReport() {
  const context = loadContext();
  const rows = buildRows(context);
  const report = {
    schemaVersion: 1,
    generatedFor: "P1.01",
    generatedAt: context.taxonomy.reportDate,
    source: "sitemap.xml + HTML local + registrele P0",
    principle: context.taxonomy.principle,
    summary: {
      canonicalUrlCount: collectSiteState().entries.length,
      inventoriedUrlCount: rows.length,
      byType: countBy(rows, "type"),
      byIntent: countBy(rows, "primaryIntent"),
      byRecommendation: countBy(rows, "recommendation"),
      blockedDecisionCount: rows.filter((row) => row.decisionState === "APROBARE_UMANĂ_NECESARĂ").length,
    },
    rows,
    blockedDecisions: blockedDecisions(rows, context),
  };
  return report;
}

function outputsFor(report) {
  return new Map([
    [REPORT_JSON_PATH, `${JSON.stringify(report, null, 2)}\n`],
    [REPORT_CSV_PATH, makeCsv(report.rows)],
    [REPORT_HTML_PATH, makeHtml(report)],
    [REPORT_MD_PATH, makeMarkdown(report)],
  ]);
}

function run({ check = false } = {}) {
  const report = makeReport();
  const outputs = outputsFor(report);
  const stale = [];
  for (const [file, content] of outputs) {
    if (check) {
      if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== content) stale.push(path.relative(ROOT, file));
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, content, "utf8");
    }
  }
  if (stale.length) throw new Error(`Inventarul P1.01 este absent sau expirat: ${stale.join(", ")}. Rulează npm run generate:content-intent-inventory.`);
  console.log(`${check ? "PASS" : "GENERATED"}: ${report.rows.length} URL-uri; ${report.summary.blockedDecisionCount} decizii canonice necesită aprobare.`);
  return report;
}

if (require.main === module) {
  try {
    run({ check: process.argv.includes("--check") });
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { buildRows, makeReport, outputsFor, run };
