#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_CSV = path.join(ROOT, "reports", "generative-language-audit.csv");
const REPORT_MD = path.join(ROOT, "reports", "generative-language-audit.md");
const EXCEPTIONS_PATH = path.join(ROOT, "config", "generative-language-exceptions.json");
const ALLOWED_EXCEPTION_KINDS = new Set(["official_name", "verbatim_quote"]);
const HIGH_SEVERITY = "ridicată";

const PHRASE_RULES = [
  rule("Într-o lume în continuă schimbare", /(?<![\p{L}\p{N}_])într-o lume în continuă schimbare(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "introducere_generică", "Deschidere generică, fără legătură cu programul, documentele sau situația solicitantului.", "Începe cu situația concretă verificată: solicitant, investiție, document sau statutul apelului."),
  rule("Este important de menționat", /(?<![\p{L}\p{N}_])este important de menționat(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "formulă_metadiscursivă", "Anunță importanța în loc să explice direct criteriul și consecința lui.", "Formulează direct regula, documentul care o dovedește și efectul lipsei lui."),
  rule("Joacă un rol crucial", /(?<![\p{L}\p{N}_])joacă un rol crucial(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "afirmație_vagă", "Intensificatorul nu precizează ce se verifică sau ce consecință produce.", "Numește criteriul, documentul și decizia pe care o poate modifica."),
  rule("Nu doar..., ci și...", /(?<![\p{L}\p{N}_])nu doar(?![\p{L}\p{N}_])[\s\S]{0,240}?(?<![\p{L}\p{N}_])ci (?:și|si)(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "construcție_simetrică", "Construcție retorică previzibilă care comprimă criterii diferite fără a le delimita.", "Separă criteriile și explică pentru fiecare documentul sau riscul verificat."),
  rule("Descoperă", /(?<![\p{L}\p{N}_])descoperă(?![\p{L}\p{N}_])/iu, "medie", "imperativ_promotional", "Imperativ promoțional care nu adaugă informație practică.", "Înlocuiește cu acțiunea concretă disponibilă în pagină: verificare, calcul, comparație sau documentare."),
  rule("Ghid complet", /(?<![\p{L}\p{N}_])ghid complet(?![\p{L}\p{N}_])/iu, "medie", "promisiune_exhaustivă", "Promite exhaustivitate fără să poată acoperi toate versiunile și clarificările oficiale.", "Precizează versiunea documentului și subiectele efectiv acoperite."),
  rule("Tot ce trebuie să știi", /(?<![\p{L}\p{N}_])tot ce trebuie să știi(?![\p{L}\p{N}_])/iu, "medie", "promisiune_exhaustivă", "Promite exhaustivitate și ascunde limitele informației disponibile.", "Enumeră concret întrebările la care răspunde pagina și ce trebuie reconfirmat."),
  rule("Maximizează șansele", /(?<![\p{L}\p{N}_])maximizează șansele(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "promisiune_neverificabilă", "Sugerează o creștere a probabilității de aprobare fără bază măsurabilă.", "Descrie verificările care reduc erorile: eligibilitate, corelări, buget și documente."),
  rule("Navighează cu succes", /(?<![\p{L}\p{N}_])navighează cu succes(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "promisiune_neverificabilă", "Formulare generică despre succes, fără criterii sau pași controlabili.", "Numește etapa procedurală și documentele necesare pentru parcurgerea ei."),
  rule("Soluții personalizate", /(?<![\p{L}\p{N}_])soluții personalizate(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "clișeu_comercial", "Afirmație comercială generală care nu explică ce se adaptează și pe baza căror date.", "Precizează variabilele analizate: tip solicitant, CAEN, locație, buget, calendar și documente."),
  rule("Abordare holistică", /(?<![\p{L}\p{N}_])abordare holistică(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "clișeu_comercial", "Jargon abstract fără etapă de lucru sau rezultat verificabil.", "Descrie succesiunea verificărilor și livrabilul fiecărei etape."),
  rule("Proces complex", /(?<![\p{L}\p{N}_])proces complex(?![\p{L}\p{N}_])/iu, "medie", "generalizare_fără_exemplu", "Etichetează dificultatea fără să arate unde apar blocajele.", "Indică blocajul concret: drept asupra imobilului, CAEN, aviz, deviz, cofinanțare sau calendar."),
  rule("Oportunitate unică", /(?<![\p{L}\p{N}_])oportunitate unică(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "superlativ_neconfirmat", "Superlativ promoțional care nu poate fi susținut din ghidul programului.", "Descrie beneficiarii, cheltuielile și limitele confirmate ale apelului."),
  rule("Transformă-ți visul în realitate", /(?<![\p{L}\p{N}_])transformă-ți visul în realitate(?![\p{L}\p{N}_])/iu, HIGH_SEVERITY, "clișeu_promoțional", "Promisiune emoțională nepotrivită unei analize de finanțare bazate pe documente.", "Înlocuiește cu pașii verificabili pentru pregătirea investiției și a dosarului.")
];

const STOP_WORDS = new Set("a ai ale al anul ar au ca care ce cel cea cu de din este fi fost in la mai o pe pentru prin sa se si sau sunt un una unei unui iar însă după înainte între către".split(" "));
const SPECIFIC_SIGNALS = /\b(?:CAEN|SO|SOC|APIA|ANSVSA|ANZ|ONRC|AFIR|ADR|certificat|contract|extras|cadastr|document|ghid|ordin|buget|deviz|factur|aviz|autoriza|amplasament|cofinan|solicitant|proprietate|concesiune|închiriere)\w*/iu;
const ABSTRACT_SIGNALS = /\b(?:inovare|dezvoltare|eficiență|competitivitate|sustenabilitate|transformare|oportunități|soluții|strategie|optimizare|succes|impact|valoare adăugată|potențial)\b/giu;

function rule(label, regex, severity, category, reason, recommendation) {
  return { label, regex, severity, category, reason, recommendation };
}

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function comparable(value) {
  return cleanText(value).normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLowerCase();
}

function tokens(value) {
  return comparable(value)
    .replace(/[^a-z0-9]+/gu, " ")
    .split(/\s+/u)
    .filter((token) => token.length > 2 && !STOP_WORDS.has(token));
}

function jaccard(first, second) {
  const a = new Set(tokens(first));
  const b = new Set(tokens(second));
  if (!a.size || !b.size) return { score: 0, shared: 0 };
  const shared = [...a].filter((token) => b.has(token)).length;
  return { score: shared / new Set([...a, ...b]).size, shared };
}

function visibleBlocks($) {
  const blocks = [];
  $("body h1, body h2, body h3, body h4, body p, body li").each((index, element) => {
    const current = $(element);
    if (current.closest("header, nav, footer, dialog, form, template, [hidden], [aria-hidden='true']").length) return;
    if (current.is("li") && current.children("p, ul, ol").length) return;
    const text = cleanText(current.text());
    if (!text) return;
    blocks.push({
      index,
      kind: element.tagName.toLowerCase(),
      text,
      context: current.attr("id") || current.attr("class") || "body"
    });
  });
  return blocks;
}

function metadataBlocks($) {
  const values = [
    ["title", $("head > title").first().text()],
    ["meta-description", $("head meta[name='description']").first().attr("content")],
    ["og-title", $("head meta[property='og:title']").first().attr("content")],
    ["og-description", $("head meta[property='og:description']").first().attr("content")]
  ];
  return values.map(([kind, value], index) => ({ index: -10 + index, kind, text: cleanText(value), context: "head" })).filter((block) => block.text);
}

function loadExceptions() {
  const source = JSON.parse(fs.readFileSync(EXCEPTIONS_PATH, "utf8"));
  const errors = [];
  if (source.version !== 1) errors.push("Fișierul de excepții trebuie să aibă version 1.");
  if (!Array.isArray(source.allowedKinds)) errors.push("Fișierul de excepții trebuie să declare allowedKinds.");
  else {
    const configuredKinds = new Set(source.allowedKinds);
    for (const kind of configuredKinds) {
      if (!ALLOWED_EXCEPTION_KINDS.has(kind)) errors.push(`Tip de excepție declarat, dar nepermis: ${kind}.`);
    }
    for (const kind of ALLOWED_EXCEPTION_KINDS) {
      if (!configuredKinds.has(kind)) errors.push(`Tip de excepție obligatoriu lipsă din allowedKinds: ${kind}.`);
    }
  }
  const exceptions = source.exceptions || [];
  for (const [index, exception] of exceptions.entries()) {
    for (const field of ["route", "category", "fragment", "kind", "reason", "source"]) {
      if (!cleanText(exception[field])) errors.push(`Excepția ${index + 1} nu conține ${field}.`);
    }
    if (!ALLOWED_EXCEPTION_KINDS.has(exception.kind)) errors.push(`Excepția ${index + 1} are tip nepermis: ${exception.kind}.`);
  }
  if (errors.length) throw new Error(errors.join("\n"));
  return exceptions;
}

function isExcepted(finding, exceptions) {
  return exceptions.some((exception) => (
    exception.route === finding.route &&
    exception.category === finding.category &&
    comparable(exception.fragment) === comparable(finding.fragment)
  ));
}

function addFinding(findings, finding) {
  const key = [finding.route, finding.category, comparable(finding.fragment)].join("|");
  if (findings.some((item) => item.key === key)) return;
  findings.push({ ...finding, key });
}

function phraseFindings(route, file, blocks, findings) {
  for (const block of blocks) {
    for (const phraseRule of PHRASE_RULES) {
      if (!phraseRule.regex.test(block.text)) continue;
      addFinding(findings, {
        route,
        file,
        fragment: block.text,
        category: phraseRule.category,
        severity: phraseRule.severity,
        reason: `${phraseRule.reason} Expresie detectată: „${phraseRule.label}”.`,
        recommendation: phraseRule.recommendation
      });
    }
  }
}

function abstractEnumerationFindings(route, file, paragraphs, findings) {
  for (const block of paragraphs) {
    const separators = (block.text.match(/[,;]/gu) || []).length;
    const abstractCount = (block.text.match(ABSTRACT_SIGNALS) || []).length;
    const hasSpecifics = SPECIFIC_SIGNALS.test(block.text) || /\d/u.test(block.text) || /\b(?:de exemplu|cum ar fi|în cazul)\b/iu.test(block.text);
    if (block.text.length < 130 || separators < 3 || abstractCount < 2 || hasSpecifics) continue;
    addFinding(findings, {
      route,
      file,
      fragment: block.text,
      category: "enumerare_abstractă",
      severity: "medie",
      reason: "Paragraful acumulează concepte abstracte, dar nu indică un criteriu, un document, o limită sau un exemplu verificabil.",
      recommendation: "Păstrează numai ideile necesare și leagă fiecare afirmație de un criteriu, document sau exemplu de necorelare."
    });
  }
}

function dashAndSymmetryFindings(route, file, paragraphs, findings) {
  for (const block of paragraphs) {
    const dashCount = (block.text.match(/—/gu) || []).length;
    if (dashCount >= 2) {
      addFinding(findings, {
        route,
        file,
        fragment: block.text,
        category: "liniuțe_lungi_excesive",
        severity: "scăzută",
        reason: `Paragraful folosește ${dashCount} liniuțe lungi și comprimă explicații care ar trebui delimitate procedural.`,
        recommendation: "Împarte ideea în propoziții directe sau într-o listă de criterii, fără a schimba ierarhia vizuală."
      });
    }

    const sentences = block.text.split(/(?<=[.!?])\s+/u).filter((sentence) => tokens(sentence).length >= 3);
    if (sentences.length < 3) continue;
    const starts = sentences.map((sentence) => tokens(sentence).slice(0, 2).join(" "));
    const repeatedStart = starts.find((start) => start && starts.filter((value) => value === start).length >= 3);
    if (repeatedStart) {
      addFinding(findings, {
        route,
        file,
        fragment: block.text,
        category: "propoziții_simetrice",
        severity: "scăzută",
        reason: "Trei propoziții din același paragraf pornesc cu aceeași structură și creează un ritm mecanic.",
        recommendation: "Grupează informația după decizia practică, nu după o structură sintactică repetată."
      });
    }
  }
}

function repeatedParagraphStartFindings(route, file, paragraphs, findings) {
  for (let index = 0; index <= paragraphs.length - 3; index += 1) {
    const group = paragraphs.slice(index, index + 3);
    const starts = group.map((block) => tokens(block.text).slice(0, 3).join(" "));
    if (!starts[0] || !starts.every((start) => start === starts[0])) continue;
    addFinding(findings, {
      route,
      file,
      fragment: group.map((block) => block.text).join("\n\n"),
      category: "început_repetat_de_paragraf",
      severity: "medie",
      reason: "Trei paragrafe succesive încep cu aceeași structură, semn al unei redactări mecanice.",
      recommendation: "Reordonează paragrafele după criteriu, dovadă și consecință; variază începutul numai când logica o cere."
    });
  }
}

function repeatedEligibilityWarningFindings(route, file, paragraphs, findings) {
  const matches = paragraphs.filter((block) => /\beligibilitatea\s+(?:depinde|se stabilește|se verifică|nu poate fi confirmată)\b/iu.test(block.text));
  if (matches.length < 2) return;
  addFinding(findings, {
    route,
    file,
    fragment: matches.map((block) => block.text).join("\n\n"),
    category: "avertisment_eligibilitate_repetat",
    severity: "medie",
    reason: `Avertismentul despre dependența eligibilității apare în ${matches.length} paragrafe și diluează criteriile concrete.`,
    recommendation: "Păstrează avertismentul o singură dată și folosește restul spațiului pentru criterii, dovezi și consecințe."
  });
}

function repeatedConclusionFindings(route, file, paragraphs, findings) {
  const substantial = paragraphs.filter((block) => block.text.length >= 100);
  if (substantial.length < 6) return;
  const introductions = substantial.slice(0, 3);
  const conclusions = substantial.slice(-3);
  for (const conclusion of conclusions) {
    for (const introduction of introductions) {
      const overlap = jaccard(introduction.text, conclusion.text);
      if (overlap.score < 0.55 || overlap.shared < 9) continue;
      addFinding(findings, {
        route,
        file,
        fragment: conclusion.text,
        category: "concluzie_repetitivă",
        severity: "medie",
        reason: `Concluzia reia vocabularul introducerii (${Math.round(overlap.score * 100)}% suprapunere) fără o decizie sau un pas nou.`,
        recommendation: "Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural."
      });
      break;
    }
  }
}

function inspectPage(route, file, html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const visible = visibleBlocks($);
  const paragraphs = visible.filter((block) => block.kind === "p");
  const findings = [];
  phraseFindings(route, file, [...metadataBlocks($), ...visible], findings);
  abstractEnumerationFindings(route, file, paragraphs, findings);
  dashAndSymmetryFindings(route, file, paragraphs, findings);
  repeatedParagraphStartFindings(route, file, paragraphs, findings);
  repeatedEligibilityWarningFindings(route, file, paragraphs, findings);
  repeatedConclusionFindings(route, file, paragraphs, findings);
  return { visible, findings };
}

function csvCell(value) {
  return `"${String(value ?? "").replace(/"/gu, '""')}"`;
}

function mdText(value) {
  return cleanText(value).replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

function writeReports(findings, routeCount) {
  fs.mkdirSync(path.dirname(REPORT_CSV), { recursive: true });
  const header = ["route", "file", "fragment", "category", "severity", "reason", "recommendation"];
  const csv = [
    header.map(csvCell).join(","),
    ...findings.map((finding) => header.map((field) => csvCell(finding[field])).join(","))
  ].join("\n");
  fs.writeFileSync(REPORT_CSV, `${csv}\n`, "utf8");

  const severityCounts = new Map();
  const categoryCounts = new Map();
  for (const finding of findings) {
    severityCounts.set(finding.severity, (severityCounts.get(finding.severity) || 0) + 1);
    categoryCounts.set(finding.category, (categoryCounts.get(finding.category) || 0) + 1);
  }
  const byRoute = new Map();
  for (const finding of findings) {
    if (!byRoute.has(finding.route)) byRoute.set(finding.route, []);
    byRoute.get(finding.route).push(finding);
  }
  const details = [...byRoute.entries()].map(([route, routeFindings]) => {
    return `## ${route}\n\n${routeFindings.map((finding, index) => `### ${index + 1}. ${finding.category} — severitate ${finding.severity}\n\n- Fișier: \`${finding.file}\`\n- Fragment exact:\n\n> ${mdText(finding.fragment)}\n\n- Motiv: ${mdText(finding.reason)}\n- Recomandare: ${mdText(finding.recommendation)}`).join("\n\n")}`;
  }).join("\n\n");
  const md = `# Audit editorial al limbajului generativ\n\nGenerat: ${new Date().toISOString()}\n\nPagini indexabile analizate: ${routeCount}\n\nPagini cu observații: ${byRoute.size}\n\nObservații totale: ${findings.length}\n\nInstrumentul raportează formulările și tiparele; nu modifică HTML-ul. Fragmentele sunt păstrate integral în CSV și în secțiunile de mai jos.\n\n## Distribuție după severitate\n\n| Severitate | Număr |\n| --- | ---: |\n${[...severityCounts.entries()].map(([severity, count]) => `| ${severity} | ${count} |`).join("\n")}\n\n## Distribuție după categorie\n\n| Categorie | Număr |\n| --- | ---: |\n${[...categoryCounts.entries()].sort((a, b) => b[1] - a[1]).map(([category, count]) => `| ${category} | ${count} |`).join("\n")}\n\n${details || "Nu au fost identificate observații."}\n`;
  fs.writeFileSync(REPORT_MD, md, "utf8");
}

function parseArgs(argv) {
  const args = { checkHigh: false, noReport: false, inspect: "" };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--check-high") args.checkHigh = true;
    else if (argv[index] === "--no-report") args.noReport = true;
    else if (argv[index] === "--inspect") args.inspect = argv[++index] || "";
    else throw new Error(`Argument necunoscut: ${argv[index]}`);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const routes = sitemapRoutes(ROOT);
  const exceptions = loadExceptions();
  const findings = [];
  for (const route of routes) {
    if (args.inspect && route !== args.inspect) continue;
    const absoluteFile = fileForRoute(ROOT, route);
    if (!fs.existsSync(absoluteFile)) throw new Error(`${route}: fișier indexabil lipsă (${absoluteFile})`);
    const file = path.relative(ROOT, absoluteFile).split(path.sep).join("/");
    const result = inspectPage(route, file, fs.readFileSync(absoluteFile, "utf8"));
    if (args.inspect) {
      console.log(`# ${route} — ${file}`);
      for (const [index, block] of result.visible.entries()) console.log(`${String(index + 1).padStart(3, "0")}|${block.kind}|${block.context}| ${block.text}`);
    }
    for (const finding of result.findings) {
      if (isExcepted(finding, exceptions)) continue;
      findings.push(finding);
    }
  }
  findings.sort((a, b) => a.route.localeCompare(b.route, "ro") || a.severity.localeCompare(b.severity, "ro") || a.category.localeCompare(b.category, "ro"));
  if (!args.noReport && !args.inspect) writeReports(findings, routes.length);
  const highFindings = findings.filter((finding) => finding.severity === HIGH_SEVERITY);
  console.log(`Audit limbaj generativ: ${args.inspect ? 1 : routes.length} pagini, ${findings.length} observații, ${highFindings.length} cu severitate ridicată.`);
  if (args.checkHigh && highFindings.length) {
    console.error(highFindings.map((finding) => `- ${finding.route} [${finding.category}]: ${finding.fragment}`).join("\n"));
    process.exitCode = 1;
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || error);
    process.exitCode = 1;
  }
}

module.exports = {
  inspectPage,
  jaccard,
  loadExceptions,
  PHRASE_RULES
};
