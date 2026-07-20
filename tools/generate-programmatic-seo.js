#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const GLOBAL_HEADER = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8").trim();
const CONFIG = path.join(ROOT, "config", "seo-programmatic-pages.json");
const SITEMAP = path.join(ROOT, "sitemap.xml");
const PROGRAMMATIC_MIN_WORDS = 1100;
const PROGRAMMATIC_MIN_FAQ = 5;
const {
  SITE,
  PAGE_KINDS,
  articleSchema,
  buildPageMetadata,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  canonicalUrl,
  faqPageSchema,
  jsonLdGraph,
  normalizeCanonicalPath,
  organizationSchema,
  pageKindForPath,
  serviceSchema,
  standardInternalLinksForPath,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const {
  normalizeHtmlCopy,
  normalizeRomanianCopy
} = require("./normalize-copy-ro");
const { designFamilyForSlug } = require("./design-family-map");
const ANALYTICS_EVENTS_SCRIPT = `  <script src="/assets/analytics-events.js" defer></script>`;

function publicText(value, fallback = "") {
  const text = String(value ?? "").trim();
  if (!text || /^TODO_/i.test(text)) return fallback;
  return normalizeRomanianCopy(text
    .replace(/TODO_CLIENT_[A-Z0-9_ -]*/gi, fallback)
    .replace(/TODO_SURSA_OFICIALA[A-Z0-9_ -]*/gi, "Se confirma in ghidul activ")
    .replace(/TODO_DATA_ACCESARII/gi, "")
    .replace(/TODO_DATE_LOCALE/gi, ""));
}

function esc(value) {
  return publicText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cleanUrl(value) {
  return normalizeCanonicalPath(value);
}

function canonical(route) {
  return canonicalUrl(route);
}

function heroImageFor(route, category = "") {
  const text = `${route} ${category}`.toLowerCase();
  if (/agricultur|ferme|0111/.test(text)) return "/assets/hero/hero-agriculture.webp";
  if (/energie|fotovoltaic/.test(text)) return "/assets/hero/hero-solar.webp";
  if (/bacau|iasi|suceava|bucuresti|nord-est|local/.test(text)) return "/assets/hero/hero-local.webp";
  if (/caen|digital|software|pnrr/.test(text)) return "/assets/hero/hero-digital.webp";
  return "/assets/hero/hero-business.webp";
}

function heroAttrs(route, category) {
  const family = designFamilyForRoute(route, category);
  return `class="hero hero--image hero--${esc(family)}" data-design-family="${esc(family)}" style="--hero-image:url('${heroImageFor(route, category)}')"`;
}

function designFamilyForRoute(route, category = "") {
  const mappedFamily = designFamilyForSlug(route);
  if (mappedFamily) return mappedFamily;
  const text = `${route} ${category}`.toLowerCase();
  if (/caen/.test(text)) return "caen";
  if (/intrebari/.test(text)) return "editorial";
  if (/consultanta/.test(text)) return "service";
  if (/nord-est|regional|bacau|iasi|suceava|bucuresti|local/.test(text)) return "cluster";
  if (/digital|software|pnrr/.test(text)) return "digital";
  if (/agricultur|ferme|0111/.test(text)) return "afir";
  if (/energie|fotovoltaic/.test(text)) return "energy";
  return "cluster";
}

function heroIconForRoute(route, category = "") {
  const family = designFamilyForRoute(route, category);
  if (family === "caen") return "ph-duotone ph-file-text";
  if (family === "digital") return "ph-duotone ph-desktop";
  if (family === "afir") return "ph-duotone ph-plant";
  if (family === "energy") return "ph-duotone ph-sun";
  if (family === "service") return "ph-duotone ph-magnifying-glass";
  return "ph-duotone ph-info";
}

function heroBadgeForRoute(route, category = "") {
  const family = designFamilyForRoute(route, category);
  if (family === "caen") return "CAEN | eligibilitatea depinde de apel";
  if (family === "digital") return "PNRR/MIPE | digitalizare | ghid verificat";
  if (family === "afir") return "AFIR | status apel | verificare documente";
  if (family === "energy") return "Energie | autoconsum | avize";
  if (family === "service") return "Serviciu FABER | proces | livrabile";
  if (family === "editorial") return "Ghid editorial | actualizat | surse citate";
  return category || "FABER | resursa | actualizare";
}

function renderHeroSummary({ route, category, summary }) {
  const family = designFamilyForRoute(route, category);
  const items = family === "caen"
    ? [["Cod", route.split("/").filter(Boolean).pop().slice(0, 4)], ["Status", "depinde de apelul activ"], ["Documente", "CAEN, buget, spatiu"], ["Risc", "program incompatibil"]]
    : [["Beneficiar", category || "solicitant"], ["Status", "se confirma in ghid"], ["Documente", "buget si dovezi"], ["Risc", "eligibilitate neconfirmata"]];
  return `<div class="hero-summary" aria-label="Rezumat vizual">
      ${items.map(([label, value]) => `<span class="hero-summary__item"><strong>${esc(label)}</strong><em>${esc(value || summary)}</em></span>`).join("\n      ")}
    </div>`;
}

function renderCaenSheet(item) {
  const programs = (item.programs || []).slice(0, 4).join("; ");
  const investments = (item.investments || []).slice(0, 4).join("; ");
  return `<section class="caen-sheet" aria-label="Fisa eligibilitate CAEN ${esc(item.code)}">
        <div class="caen-sheet__code">CAEN ${esc(item.code)}</div>
        <div class="caen-sheet__content">
          <h2>Fisa de eligibilitate pentru ${esc(item.label)}</h2>
          <div class="design-card-grid design-card-grid--caen">
            <article class="mini-card design-card"><span class="design-card__badge">Cod CAEN</span><h3>Activitate</h3><p>${esc(item.label)}</p></article>
            <article class="mini-card design-card"><span class="design-card__badge">Programe</span><h3>Compatibile</h3><p>${esc(programs || "Se verifica in ghidul activ")}</p></article>
            <article class="mini-card design-card"><span class="design-card__badge">Finantare</span><h3>Ce poate fi finantat</h3><p>${esc(investments || "investitii legate direct de activitate")}</p></article>
            <article class="mini-card design-card"><span class="design-card__badge">Risc</span><h3>Ce trebuie verificat</h3><p>autorizare, localizare, cofinantare si legatura dintre investitie si activitate.</p></article>
          </div>
        </div>
      </section>`;
}

function li(items) {
  return (items || []).map((item) => `<li>${esc(item)}</li>`).join("\n");
}

function configuredBody(item) {
  const body = String(item?.body || "").trim();
  return body ? `\n      ${body}` : "";
}

function normalizeFaqEntries(faq) {
  if (!Array.isArray(faq)) return [];
  return faq
    .map((entry) => {
      if (Array.isArray(entry)) return [entry[0], entry[1]];
      return [entry?.question || entry?.name, entry?.answer || entry?.text];
    })
    .filter(([question, answer]) => String(question || "").trim() && String(answer || "").trim());
}

function configuredFaq(item, fallback) {
  const seen = new Set();
  return [...normalizeFaqEntries(item?.faq), ...fallback].filter(([question]) => {
    const key = String(question || "").trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function appendConfiguredBody(body, item) {
  const extra = configuredBody(item);
  return extra ? `${body}${extra}` : body;
}

function stripTags(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function wordCount(html) {
  const words = stripTags(html).match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function relatedLinks(items) {
  return (items || []).map((item) => {
    const href = typeof item === "string" ? item : (Array.isArray(item) ? item[0] : item.href);
    const label = typeof item === "string"
      ? cleanUrl(href).replace(/^\/+/, "").replace(/-/g, " ")
      : (Array.isArray(item) ? (item[1] || cleanUrl(href).replace(/^\/+/, "").replace(/-/g, " ")) : (item.label || item.name || item.title || cleanUrl(href).replace(/^\/+/, "").replace(/-/g, " ")));
    return `<a href="${cleanUrl(href)}">${esc(label)}</a>`;
  }).join("\n");
}

function linkTo(href, label) {
  return `<a href="${cleanUrl(href)}">${esc(label)}</a>`;
}

function renderBreadcrumb(route, currentName) {
  const items = breadcrumbItemsForPath(route, currentName);
  return `<div class="breadcrumb">${items.map((item, index) => {
    const label = esc(item.name);
    if (index === items.length - 1) return label;
    return `<a href="${cleanUrl(item.item)}">${label}</a>`;
  }).join(" / ")}</div>`;
}

function metadataForRoute({ title, description, route, h1, summary }) {
  return buildPageMetadata({
    title,
    description,
    pathname: route,
    fallbackTitle: h1 || cleanUrl(route).replace(/^\/+/, "").replace(/-/g, " "),
    fallbackDescription: summary || h1 || title
  });
}

function schema(title, description, route, faq, updatedAt = "2026-05-20", metadata = metadataForRoute({ title, description, route }), currentName = title) {
  const pageKind = pageKindForPath(route);
  const pageNode = webPageSchema({
    url: metadata.canonicalUrl,
    name: metadata.title,
    description: metadata.description,
    dateModified: updatedAt
  });
  if (pageKind === PAGE_KINDS.ARTICLE) pageNode.mainEntity = { "@id": `${metadata.canonicalUrl}#article` };
  if (pageKind === PAGE_KINDS.SERVICE) pageNode.mainEntity = { "@id": `${metadata.canonicalUrl}#service` };
  const contentNode = pageKind === PAGE_KINDS.ARTICLE
    ? articleSchema({
      url: metadata.canonicalUrl,
      headline: publicText(metadata.title),
      description: publicText(metadata.description),
      datePublished: updatedAt,
      dateModified: updatedAt
    })
    : pageKind === PAGE_KINDS.SERVICE
      ? serviceSchema({
        url: metadata.canonicalUrl,
        name: currentName || metadata.title,
        description: metadata.description,
        serviceType: "Consultanță pentru fonduri europene"
      })
      : null;
  return jsonLdGraph([
    organizationSchema(),
    websiteSchema(),
    pageNode,
    breadcrumbSchema(breadcrumbItemsForPath(route, currentName)),
    contentNode,
    faqPageSchema(faq, { minItems: 2 })
  ]);
}

function html({ title, description, h1, route, category, summary, body, faq, related, updatedAt = "2026-05-20" }) {
  const metadata = metadataForRoute({ title, description, route, h1, summary });
  const family = designFamilyForRoute(route, category);
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(metadata.title)}</title>
  <meta name="description" content="${esc(metadata.description)}" />
  <meta name="robots" content="index, follow" />
  <meta name="seo-depth" content="true" />
  <meta name="seo-min-words" content="${PROGRAMMATIC_MIN_WORDS}" />
  <meta name="seo-min-faq" content="${PROGRAMMATIC_MIN_FAQ}" />
  <link rel="canonical" href="${metadata.canonicalUrl}" />
  <meta property="og:url" content="${metadata.ogUrl}" />
  <link rel="stylesheet" href="/assets/seo-hub.css" />
  <link rel="stylesheet" href="/assets/see-also.css" />
  <script type="application/ld+json">${schema(title, description, route, faq, updatedAt, metadata, h1)}</script>
${ANALYTICS_EVENTS_SCRIPT}
</head>
<body class="page-family-${esc(family)}">
  ${GLOBAL_HEADER}
  ${renderBreadcrumb(route, h1)}
  <header ${heroAttrs(route, category)}>
    <span class="hero-icon" aria-hidden="true"><i class="${esc(heroIconForRoute(route, category))}"></i></span>
    <span class="eyebrow design-badge design-badge--${esc(family)}">${esc(heroBadgeForRoute(route, category))}</span>
    <h1>${esc(h1)}</h1>
    <p>${esc(description)}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Verifica eligibilitatea</a>
      <a class="btn btn-secondary" href="${family === "caen" ? "/fonduri-europene" : "/surse-oficiale-fonduri-europene"}">${family === "caen" ? "Vezi programe compatibile" : "Vezi surse oficiale"}</a>
    </div>
    ${renderHeroSummary({ route, category, summary })}
  </header>
  <main class="container">
    <article class="panel">
      <h2>Raspuns scurt</h2>
      <p class="intro">${esc(summary)}</p>
      ${body}
      <h2>Intrebari frecvente</h2>
      ${faq.map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`).join("\n")}
      <h2>Resurse conexe</h2>
      <div class="related-links">${relatedLinks(standardInternalLinksForPath(route, related))}</div>
    </article>
    <section class="cta-box">
      <h2>Verifica proiectul inainte de depunere</h2>
      <p>Trimite date despre solicitant, localitate, cod CAEN, buget si investitie. Analiza initiala nu garanteaza aprobarea, dar poate identifica riscuri.</p>
      <div class="cta-actions"><a class="btn btn-primary" href="/contact">Trimite datele proiectului</a></div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER - Atelier de Consultanță</footer>
</body>
</html>
`;
}

function writePage(route, content) {
  const file = path.join(ROOT, cleanUrl(route).slice(1), "index.html");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, normalizeHtmlCopy(content), "utf8");
}

function redirectFallbackPage({ route, target, title }) {
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Redirectionare | ${esc(title)}</title>
  <meta name="robots" content="noindex, follow" />
  <link rel="canonical" href="${canonical(target)}" />
  <meta http-equiv="refresh" content="0; url=${cleanUrl(target)}" />
  <script>window.location.replace('${cleanUrl(target)}');</script>
${ANALYTICS_EVENTS_SCRIPT}
</head>
<body>
  <main style="font-family: Arial, sans-serif; max-width: 720px; margin: 12vh auto; padding: 32px; line-height: 1.6; color: #1a2540;">
    <h1>Ești redirecționat către o nouă adresă</h1>
    <p>Pagina veche a fost mutată. Dacă redirecționarea nu pornește automat, deschide <a href="${cleanUrl(target)}">${cleanUrl(target)}</a>.</p>
  </main>
  <script>window.location.replace('${cleanUrl(target)}');</script>
</body>
</html>
`;
}

function ensureDepth(body, context) {
  const paragraphs = [
    `Pentru ${context}, decizia nu se ia doar dupa denumirea programului. Trebuie verificata potrivirea dintre solicitant, activitate, localitate, documente, investitie, buget si calendarul apelului activ.`,
    "Un dosar bine pregatit porneste de la documente verificabile. Certificatul constatator, documentele pentru spatiu, situatiile financiare, ofertele si descrierea investitiei trebuie sa sustina aceeasi poveste economica.",
    "Cheltuielile eligibile trebuie legate direct de activitatea finantata. Daca o achizitie nu poate fi explicata prin fluxul de lucru, prin obiectivele proiectului sau prin rezultatele asteptate, riscul de clarificari creste.",
    "Cofinantarea se analizeaza separat de grant. Beneficiarul trebuie sa inteleaga ce plateste din surse proprii, ce nu se deconteaza, ce documente sunt cerute la plata si ce se intampla daca apar diferente de pret.",
    "Punctajul orientativ se verifica inainte de depunere si se reface dupa fiecare schimbare de buget sau investitie. Un proiect eligibil poate ramane nefinantat daca nu intra in bugetul disponibil al apelului.",
    "Informatiile de pe pagina sunt orientative. Eligibilitatea finala depinde de ghidul oficial, anexele apelului, documentele solicitantului si evaluarea autoritatii finantatoare.",
    "O verificare utila incepe cu intrebari simple: cine aplica, unde se implementeaza investitia, ce activitate este autorizata, ce se cumpara si cum se sustine contributia proprie. Raspunsurile trebuie confirmate in documente, nu doar declarate in discutia initiala.",
    "Daca proiectul are lucrari, echipamente sau servicii tehnice, ofertele trebuie sa fie comparabile si suficient de clare. Specificatiile vagi pot duce la clarificari, ajustari de buget sau eliminarea unor costuri.",
    "Pentru firmele cu mai multe activitati, codul CAEN trebuie citit impreuna cu activitatea reala si cu punctul de lucru. Un cod prezent in certificat nu este suficient daca investitia nu poate fi legata de fluxul operational.",
    "Pentru ferme, analiza include suprafete, efective, documente APIA sau registre relevante, dreptul de folosinta si dimensiunea economica. O schimbare aparent mica in date poate modifica eligibilitatea sau punctajul.",
    "Pentru proiectele de digitalizare, lista de achizitii trebuie legata de procese: vanzari, productie, gestiune, raportare, securitate sau relatia cu clientii. Un buget IT general este mai greu de aparat decat un buget conectat la probleme concrete.",
    "Pentru proiectele energetice, consumul, amplasamentul, avizele si dimensionarea tehnica trebuie verificate inainte de buget. O capacitate aleasa doar dupa plafonul programului poate fi vulnerabila la evaluare.",
    "Calendarul conteaza la fel de mult ca bugetul. Documentele pentru spatiu, oferte, certificate, autorizatii sau registre pot avea durate diferite de obtinere si pot bloca depunerea daca sunt lasate la final.",
    "Un raspuns responsabil poate fi si amanarea depunerii. Daca documentele sunt incomplete, cofinantarea este neclara sau ghidul nu este final, pregatirea trebuie continuata pana cand riscurile principale sunt intelese.",
    "Dupa depunere, proiectul nu se incheie. Contractarea, achizitiile, cererile de plata si monitorizarea cer aceeasi coerenta intre ce s-a promis in dosar si ce se poate implementa practic."
  ];
  let html = body;
  let index = 0;
  while (wordCount(html) < PROGRAMMATIC_MIN_WORDS) {
    html += `\n      <p>${esc(paragraphs[index % paragraphs.length])}</p>`;
    index += 1;
  }
  return html;
}

function caenPage(item) {
  const route = `/fonduri-europene-caen/${item.code}-${item.slug}`;
  const title = `Fonduri europene pentru CAEN ${item.code} - ${item.label}`;
  const description = `Ghid pentru CAEN ${item.code}: programe posibile, investitii eligibile, documente, punctaj si checklist pentru ${item.label}.`;
  const faq = configuredFaq(item, [
    [`Pot obtine fonduri europene pentru CAEN ${item.code}?`, `Da, daca activitatea ${item.label} este eligibila in apelul activ si solicitantul indeplineste conditiile programului.`],
    [`Ce documente sunt utile pentru CAEN ${item.code}?`, "Certificatul constatator, autorizarea CAEN, documentele firmei, ofertele, bugetul si documentele pentru spatiul investitiei."],
    [`Ce programe pot fi relevante pentru CAEN ${item.code}?`, item.programs.join("; ")],
    [`Ce trebuie verificat inainte de buget pentru CAEN ${item.code}?`, "Eligibilitatea solicitantului, codul CAEN, cheltuielile permise, cofinantarea si punctajul."],
    [`Ce investitii pot fi analizate pentru CAEN ${item.code}?`, `Pot fi analizate ${item.investments.join(", ")}, daca sunt permise de ghidul activ si au legatura directa cu activitatea ${item.label}.`]
  ]);
  const programRows = item.programs
    .map((program) => `<tr><td>${esc(program)}</td><td>Se confirma in ghidul activ</td><td>Contributie proprie estimata separat de grant</td><td>Eligibilitatea depinde de solicitant, regiune, cod CAEN, buget si documentele investitiei.</td></tr>`)
    .join("\n");
  let body = `
      <h2>Descriere CAEN</h2>
      <p>CAEN ${esc(item.code)} - ${esc(item.label)} descrie activitatea economica pentru care investitia trebuie justificata prin documente, autorizare, flux operational si buget. Codul nu garanteaza finantarea; el este doar prima piesa verificata inainte de alegerea programului.</p>
      ${renderCaenSheet(item)}
      <h2>Programe eligibile pentru CAEN ${esc(item.code)}</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Program</th><th>Buget orientativ</th><th>Cofinantare</th><th>Conditii</th></tr></thead>
          <tbody>${programRows}</tbody>
        </table>
      </div>
      <h2>Exemplu de proiect tipic</h2>
      <p>Un proiect pentru CAEN ${esc(item.code)} poate porni de la o investitie de 50.000 EUR in echipamente, software sau dotari direct legate de activitatea ${esc(item.label)}. Daca apelul ar permite orientativ 70% sprijin, grantul ar fi 35.000 EUR, iar contributia proprie ar incepe de la 15.000 EUR, la care se adauga cheltuieli neeligibile, TVA sau rezerve de implementare.</p>
      <h2>Programe relevante</h2>
      <p>Pentru CAEN ${esc(item.code)}, analiza trebuie facuta pe program, nu pe cod izolat. Un cod poate fi potrivit intr-un apel si exclus in altul, in functie de regiune, obiective si tipul investitiei.</p>
      <ul>${li(item.programs)}</ul>
      <h2>Investitii posibile</h2>
      <p>Investitiile trebuie sa fie direct legate de activitatea autorizata si sa poata fi justificate prin oferte, flux operational si rezultate masurabile.</p>
      <ul>${li(item.investments)}</ul>
      <h2>Checklist minim</h2>
      <ul>
        <li>verifica autorizarea sau autorizabilitatea codului CAEN;</li>
        <li>confirma locatia investitiei si documentele pentru spatiu;</li>
        <li>pregateste ofertele si specificatiile tehnice;</li>
        <li>calculeaza cofinantarea si cheltuielile neeligibile;</li>
        <li>verifica grila de punctaj inainte de depunere.</li>
      </ul>`;
  body = ensureDepth(appendConfiguredBody(body, item), `CAEN ${item.code} - ${item.label}`);
  return { route, content: html({ title, description, h1: title, route, category: "Cod CAEN", summary: `Pentru CAEN ${item.code}, fondurile europene se aleg dupa program, regiune, investitie si documente, nu doar dupa denumirea codului.`, body, faq, related: ["/fonduri-europene-imm", "/instrumente", "/contact"] }) };
}

function localPage(item, consulting) {
  const route = consulting ? `/consultanta-fonduri-europene-${item.slug}` : `/fonduri-europene-${item.slug}`;
  const title = consulting ? `Consultanta fonduri europene ${item.city}` : `Fonduri europene ${item.county}`;
  const description = consulting
    ? `Consultanta pentru fonduri europene in ${item.city}: programe active, documente, eligibilitate, buget si pregatirea dosarului.`
    : `Ghid fonduri europene pentru ${item.county}: programe active, regiune, IMM-uri, agricultura, digitalizare, energie si documente.`;
  const isBucharest = item.slug === "bucuresti";
  const faq = configuredFaq(item, [
    [`Ce fonduri europene sunt relevante in ${item.county}?`, `Depinde de regiune, solicitant si investitie. In ${item.region}, verifica programele regionale, nationale, AFIR, digitalizare si energie.`],
    [`Conteaza localitatea investitiei in ${item.county}?`, "Da. Pentru programele regionale si unele scheme sectoriale, localizarea investitiei este esentiala."],
    [`Ce documente pregatesc pentru un proiect in ${item.county}?`, "Documente de firma, cod CAEN, documente pentru spatiu, buget, oferte, situatii financiare si descrierea investitiei."],
    [`Pot primi consultanta la distanta pentru ${item.county}?`, "Da. Analiza initiala se poate face pe baza datelor si documentelor transmise electronic."],
    [`Cand este utila o pagina locala pentru ${item.county}?`, "Cand localizarea poate schimba eligibilitatea, punctajul, documentele pentru punctul de lucru sau programul recomandat."],
    [`Ce verific prima data pentru un proiect din ${item.county}?`, "Verifica solicitantul, locul de implementare, codul CAEN sau activitatea agricola, bugetul, cofinantarea si ghidul activ."]
  ]);
  let body = isBucharest ? `<h2>Particularitati pentru Bucuresti-Ilfov</h2>
      <p>${esc(item.county)} se analizeaza prin regiunea ${esc(item.region)}, prin locul real de implementare si prin tipul programului. Pentru ${esc(item.focus)}, localizarea poate conta diferit fata de proiectele din alte regiuni: unele apeluri sunt nationale, unele sunt regionale, iar altele cer documente clare pentru punctul de lucru sau amplasament.</p>
      <p>O firma din Bucuresti nu ar trebui sa aleaga programul doar dupa numele finantarii. Trebuie verificate activitatea autorizata, codul CAEN, vechimea, locatia investitiei, bugetul, cofinantarea si daca ghidul activ accepta cheltuielile propuse.</p>
      <h2>Programe de verificat pentru Bucuresti</h2>
      <ul>
        <li>programe nationale pentru IMM-uri, antreprenoriat si servicii;</li>
        <li>Start-Up Nation, daca editia activa permite profilul solicitantului;</li>
        <li>digitalizare, software, automatizare, securitate cibernetica si cloud;</li>
        <li>energie pentru autoconsum sau eficienta, daca solicitantul si amplasamentul se incadreaza;</li>
        <li>apeluri regionale Bucuresti-Ilfov, atunci cand ghidul activ le confirma.</li>
      </ul>
      <h2>Exemple locale si bugete orientative</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Exemplu Bucuresti</th><th>Program posibil</th><th>Buget de discutie</th><th>Ce se verifica</th></tr></thead>
          <tbody>
            <tr><td>Firma de servicii sau productie usoara</td><td>program national sau regional IMM</td><td>50.000 - 300.000 EUR orientativ</td><td>CAEN, punct de lucru, cheltuieli, cofinantare, punctaj</td></tr>
            <tr><td>Start-up cu investitii initiale</td><td>Start-Up Nation sau schema nationala similara</td><td>pana la plafonul apelului activ</td><td>varsta firmei, asociati, activitate, buget, loc implementare</td></tr>
            <tr><td>Firma care vrea digitalizare</td><td>Digitalizare IMM / PNRR / apel national</td><td>10.000 - 100.000 EUR orientativ</td><td>procese digitalizate, software, hardware, securitate, indicatori</td></tr>
            <tr><td>Proiect energetic pentru sediu sau punct de lucru</td><td>Fondul pentru Modernizare sau apel de autoconsum</td><td>se confirma in ghidul activ</td><td>consum, drept de folosinta, avize, dimensionare, eligibilitate</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Checklist local Bucuresti</h2>
      <p>Inainte de depunere, verifica daca investitia se implementeaza in Bucuresti sau Ilfov, daca punctul de lucru este documentat, daca activitatea este autorizata sau autorizabila si daca toate cheltuielile au legatura directa cu proiectul.</p>
      <p>Pentru servicii, software si digitalizare, bugetul trebuie legat de procese concrete: vanzari, productie, gestiune, securitate, raportare sau relatia cu clientii. Pentru energie, trebuie verificate consumul, amplasamentul, racordarea, avizele si dreptul de folosinta.</p>` : `<h2>Particularitati locale</h2>
      <p>${esc(item.county)} se analizeaza prin regiunea ${esc(item.region)} si prin tipul investitiei. Pentru ${esc(item.focus)}, conteaza codul CAEN, localitatea, documentele pentru spatiu si calendarul apelurilor.</p>
      <p>Programele AFIR DR14, digitalizare IMM, investitii regionale si energie pentru autoconsum apar frecvent in discutiile locale, dar eligibilitatea se confirma numai dupa ghidul activ si documentele solicitantului.</p>
      <h2>Programe de verificat</h2>
      <ul>
        <li>programe regionale pentru IMM-uri si microintreprinderi;</li>
        <li>AFIR pentru ferme si investitii agricole;</li>
        <li>Digitalizare IMM si instrumente PNRR, cand sunt active;</li>
        <li>Fondul pentru Modernizare si energie regenerabila;</li>
        <li>Start-Up Nation si programe nationale pentru antreprenori.</li>
      </ul>
      <h2>Exemple locale si bugete orientative</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Exemplu local</th><th>Program posibil</th><th>Buget de discutie</th><th>Ce se verifica</th></tr></thead>
          <tbody>
            <tr><td>Ferma sau exploatatie mica</td><td>AFIR DR14 / DR12</td><td>25.000 - 100.000 EUR, in functie de apel</td><td>SO, terenuri, animale, varsta, cofinantare</td></tr>
            <tr><td>IMM de servicii sau productie</td><td>Program regional / IMM</td><td>50.000 - 300.000 EUR orientativ</td><td>CAEN, locatie, vechime, punctaj, cash-flow</td></tr>
            <tr><td>Firma cu nevoie de software</td><td>Digitalizare IMM / PNRR</td><td>10.000 - 100.000 EUR orientativ</td><td>ERP, CRM, hardware, securitate, indicatori</td></tr>
          </tbody>
        </table>
      </div>
      <h2>Checklist local</h2>
      <p>Inainte de depunere, verifica daca locatia investitiei este eligibila, daca punctul de lucru este documentat, daca autorizatiile pot fi obtinute si daca investitia are legatura cu activitatea firmei.</p>`;
  body = ensureDepth(appendConfiguredBody(body, item), `${title} in ${item.region}`);
  const related = isBucharest
    ? [
        consulting ? "/fonduri-europene-bucuresti" : "/consultanta-fonduri-europene-bucuresti",
        "/fonduri-europene",
        "/consultanta-fonduri-europene",
        "/digitalizare-imm",
        "/consultanta-start-up-nation-2026",
        "/consultanta-pnrr-digitalizare",
        "/contact"
      ]
    : ["/fonduri-europene", "/verificare-eligibilitate-fonduri-europene", "/contact"];
  return { route, content: html({ title, description, h1: title, route, category: consulting ? "Consultanta locala" : "Fonduri locale", summary: `${title}: eligibilitatea se verifica dupa regiune, solicitant, cod CAEN, investitie si documente.`, body, faq, related }) };
}

function regionalPage(item) {
  const route = `/${item.slug}`;
  const counties = item.counties || [];
  const title = item.title || `Fonduri europene ${item.region}`;
  const description = item.description || `Ghid regional pentru fonduri europene in ${item.region}.`;
  const faq = configuredFaq(item, [
    [`Ce judete acopera pagina ${item.region}?`, `Pagina acopera orientativ judetele ${counties.join(", ")}.`],
    ["Care este diferenta dintre programe regionale, AFIR si nationale?", "Programele regionale tin de regiunea investitiei si de autoritatea regionala. AFIR acopera proiecte agricole si rurale. Programele nationale sau PNRR au reguli stabilite la nivel national si pot avea criterii diferite de localizare."],
    ["Cand conteaza ADR Nord-Est?", "ADR Nord-Est conteaza pentru apelurile Programului Regional Nord-Est: ghiduri, clarificari, criterii regionale si documentele specifice apelului activ."],
    ["Pot folosi pagina pentru o decizie finala de depunere?", "Nu. Pagina este un filtru initial; decizia finala se ia dupa ghidul activ, anexele oficiale si documentele solicitantului."],
    ["De ce nu sunt indexate paginile locale separate?", "Paginile locale separate raman consolidate pana exista date locale reale, surse regionale sau exemple aprobate care sa justifice continut distinct."]
  ]);
  let body = `
      <h2>Rolul hub-ului regional Nord-Est</h2>
      <p>Această pagină grupează toate rutele de finanțare relevante pentru proiecte implementate în regiunea Nord-Est: Programul Regional administrat de ADR Nord-Est, intervențiile AFIR pentru agricultură și rural, programe naționale pentru IMM și antreprenoriat, digitalizare, energie și alte scheme sectoriale. Nu este pagina unui singur apel și nu presupune că orice proiect din regiune trebuie depus prin Programul Regional.</p>
      <p>Pentru orientare națională folosește ${linkTo("/fonduri-regionale", "hub-ul programelor regionale și ADR-urilor")}. Pentru cadrul Programului Regional și apelurile destinate firmelor folosește ${linkTo("/por-adr-nord-est", "Programul Regional Nord-Est")}. Pentru condițiile unei singure sesiuni deschide ${linkTo("/investitii-modernizarea-microintreprinderilor-apel-2", "Investiții pentru modernizarea microîntreprinderilor – Apel 2")}.</p>
      <h2>Judete acoperite</h2>
      <p>Pagina consolideaza intentiile locale pentru Regiunea ${esc(item.region)} si acopera orientativ judetele: ${esc(counties.join(", "))}. In locul unor pagini separate pentru fiecare oras, analiza porneste de la regiune, program, localizarea investitiei si documentele beneficiarului.</p>
      <h2>Programe relevante in Nord-Est</h2>
      <p>Pentru firme si microintreprinderi, pot fi relevante apeluri din Programul Regional Nord-Est, inclusiv investitii productive, modernizare, digitalizare sau eficienta energetica atunci cand ghidul permite. Pentru ferme si activitati agricole, traseul este de obicei AFIR si Planul Strategic PAC. Pentru digitalizare, energie sau antreprenoriat, pot aparea apeluri nationale, PNRR sau scheme sectoriale.</p>
      <h2>Rolul ADR Nord-Est</h2>
      <p>ADR Nord-Est este relevanta pentru apelurile regionale: publica sau administreaza informatii despre program, ghiduri, clarificari si reguli de eligibilitate pentru investitii in regiune. Pentru un proiect local, nu este suficient sa existe o firma in regiune; trebuie verificata locatia investitiei, codul CAEN, tipul solicitantului, cheltuielile si calendarul apelului activ.</p>
      <h2>Regional, AFIR sau national?</h2>
      <p>Un proiect din Iasi, Suceava, Bacau, Botosani, Neamt sau Vaslui nu intra automat intr-un program regional. Daca investitia este agricola sau rurala, AFIR poate fi ruta principala. Daca investitia este digitalizare, energie sau antreprenoriat, poate fi mai potrivit un program national. Daca investitia este productiva pentru o microintreprindere sau IMM local, merita verificat Programul Regional Nord-Est si apelurile active.</p>
      <table>
        <thead>
          <tr><th>Tip beneficiar</th><th>Program posibil</th><th>Ce verificam</th><th>Link intern</th></tr>
        </thead>
        <tbody>
          <tr><td>Microintreprindere din Nord-Est</td><td>Program Regional Nord-Est / POR</td><td>locatia investitiei, CAEN, vechime, buget, cofinantare</td><td>${linkTo("/por-adr-nord-est", "POR ADR Nord-Est")}</td></tr>
          <tr><td>IMM cu investitie productiva</td><td>Programe regionale sau scheme IMM</td><td>eligibilitate firma, cheltuieli, punctaj, documente pentru spatiu</td><td>${linkTo("/fonduri-europene-imm", "Fonduri IMM")}</td></tr>
          <tr><td>Ferma sau exploatatie agricola</td><td>AFIR, DR 12, DR 14 sau alte interventii PAC</td><td>SO, terenuri/animale, forma juridica, documente agricole</td><td>${linkTo("/afir", "AFIR")}</td></tr>
          <tr><td>Firma care vrea software sau automatizare</td><td>Digitalizare IMM, PNRR sau apeluri regionale</td><td>nevoia digitala, cheltuieli IT, indicatori, oferte</td><td>${linkTo("/fonduri-europene-digitalizare", "Digitalizare")}</td></tr>
          <tr><td>Firma sau institutie cu proiect energetic</td><td>Fondul pentru Modernizare sau apeluri de autoconsum</td><td>consum, avize, solutie tehnica, solicitant eligibil</td><td>${linkTo("/fondul-de-modernizare", "Energie")}</td></tr>
        </tbody>
      </table>
      <h2>Exemple locale orientative</h2>
      <ul>
        <li>Iasi: microintreprindere de servicii care verifica Programul Regional Nord-Est si buget IT.</li>
        <li>Suceava: ferma sau afacere turistica unde trebuie comparate AFIR, programe regionale si investitii energetice.</li>
        <li>Bacau: firma de productie sau servicii care verifica echipamente, cofinantare si documentele pentru punctul de lucru.</li>
      </ul>
      <h2>Intrebari locale frecvente</h2>
      <p>Conteaza orasul sau judetul? Da, mai ales la programele regionale si cand investitia trebuie localizata in regiune. Conteaza sediul social sau punctul de lucru? Depinde de ghid: unele apeluri urmaresc locul implementarii, nu doar sediul. Pot depune online fara intalnire locala? De obicei analiza initiala se poate face la distanta, dar documentele trebuie sa sustina locatia si investitia.</p>
      <h2>Cum verificam un proiect pe judet</h2>
      <p>Analiza regionala nu inseamna ca toate judetele sunt tratate identic. Pentru fiecare proiect notam unde se implementeaza investitia, ce document exista pentru locatie si daca activitatea se desfasoara efectiv acolo. Pentru o firma cu sediu intr-un judet si punct de lucru in alt judet, locul implementarii poate fi mai important decat sediul social.</p>
      <p>In practica, cerem minimum cinci informatii inainte sa recomandam o ruta: judetul si localitatea investitiei, forma juridica, codul CAEN sau activitatea agricola, tipul cheltuielilor si bugetul estimat. Dupa aceea comparam programele posibile: regional pentru investitii productive, AFIR pentru agricultura, digitalizare sau PNRR pentru software si automatizare, energie pentru autoconsum sau eficienta.</p>
      <h2>Cand ar merita o pagina locala separata</h2>
      <p>O pagina separata pentru un judet ar fi justificata doar daca poate raspunde la intrebari pe care pagina regionala nu le acopera: apel cu restrictii clare pe teritoriu, sursa oficiala judeteana, diferenta de calendar, exemplu anonimizat local sau intrebari frecvente din proiecte reale. Fara aceste elemente, o pagina locala devine doar un schimb de nume in titlu si H1.</p>
      <h2>Ce trimiti pentru verificarea eligibilitatii</h2>
      <p>Pentru o analiza initiala, sunt utile datele firmei, judetul si localitatea investitiei, descrierea activitatii, lista de cheltuieli dorite, bugetul estimat, cofinantarea disponibila si documentele pentru spatiu sau teren. Pentru agricultura, sunt necesare si informatii despre exploatatie, culturi, animale si dimensiune economica.</p>
      <h2>Surse oficiale regionale</h2>
      <ul>
        <li><a href="https://regionordest.ro/" target="_blank" rel="noopener noreferrer">Programul Regional Nord-Est 2021–2027</a> pentru calendar, apeluri și documentele administrate regional.</li>
        <li><a href="https://www.adrnordest.ro/regiunea-nord-est/organizare-administrativ-teritoriala/" target="_blank" rel="noopener noreferrer">ADR Nord-Est - organizare administrativ-teritorială</a> pentru componența regiunii.</li>
        <li>${linkTo("/surse-oficiale-fonduri-europene", "Tabelul intern de surse oficiale")}</li>
      </ul>`;
  body = ensureDepth(appendConfiguredBody(body, item), `fonduri europene ${item.region}`);
  return {
    route,
    content: html({
      title,
      description,
      h1: item.h1 || title,
      route,
      category: "Pagina regionala",
      summary: `Fondurile europene in ${item.region} se verifica dupa judet, localizarea investitiei, tipul beneficiarului si programul activ.`,
      body,
      faq,
      related: item.related || ["/por-adr-nord-est", "/fonduri-europene-imm", "/consultanta-fonduri-europene", "/contact"]
    })
  };
}

function faqPage(item) {
  const route = `/intrebari/${item.slug}`;
  const title = `Raspuns rapid: ${item.question}`;
  const description = `Raspuns rapid pentru intrebarea "${item.question}": ${item.answer.slice(0, 120)}...`;
  const faq = configuredFaq(item, [
    [item.question, item.answer],
    ["Ce trebuie verificat inainte de aplicare?", "Solicitantul, programul, documentele, bugetul, cheltuielile eligibile si regulile apelului activ."],
    ["Raspunsul garanteaza eligibilitatea?", "Nu. Raspunsul este orientativ si trebuie confirmat prin documentele proiectului si apelul activ."],
    ["Cum pot primi analiza pe cazul meu?", "Trimite datele proiectului prin pagina de contact pentru o verificare initiala."],
    ["Cand trebuie actualizat raspunsul?", "Raspunsul trebuie actualizat cand se publica un ghid nou, apar clarificari oficiale sau documentele solicitantului schimba incadrarea."]
  ]);
  let body = `
      <h2>Raspuns scurt</h2>
      <p>${esc(item.answer)}</p>
      <h2>Ce inseamna in practica</h2>
      <p>Intrebarea trebuie verificata in contextul programului, solicitantului si investitiei. Aceeasi regula poate avea efecte diferite pentru o firma, o ferma sau o institutie publica.</p>
      <h2>Checklist de verificare</h2>
      <ul>
        <li>identifica programul si apelul activ;</li>
        <li>verifica solicitantul si documentele;</li>
        <li>confirma cheltuielile eligibile si neeligibile;</li>
        <li>calculeaza cofinantarea si calendarul;</li>
        <li>cere o analiza daca exista incertitudini.</li>
      </ul>`;
  body = ensureDepth(appendConfiguredBody(body, item), item.question);
  return { route, content: html({ title, description, h1: title, route, category: "Intrebare frecventa", summary: item.answer, body, faq, related: item.related }) };
}

function updateSitemap(routes, updatedAt, excludedRoutes = []) {
  const existing = fs.existsSync(SITEMAP)
    ? [...fs.readFileSync(SITEMAP, "utf8").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].replace(SITE, ""))
    : ["/"];
  const seen = new Set();
  const excluded = new Set(excludedRoutes.map(cleanUrl));
  const all = [...existing, ...routes].map(cleanUrl).filter((route) => {
    if (seen.has(route)) return false;
    if (excluded.has(route)) return false;
    if (route.includes("/admin") || route.includes("herambursabile") || route.includes("/index")) return false;
    seen.add(route);
    return true;
  });
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${all.map((route) => `  <url>
    <loc>${SITE}${route}</loc>
    <lastmod>${updatedAt}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>${route.includes("/intrebari/") ? "0.6" : "0.7"}</priority>
  </url>`).join("\n")}
</urlset>
`;
  fs.writeFileSync(SITEMAP, xml, "utf8");
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG, "utf8"));
  const onlyArgument = process.argv.slice(2).find((argument) => argument.startsWith("--only="));
  const onlyRoutes = onlyArgument
    ? new Set(onlyArgument.slice("--only=".length).split(",").map((route) => cleanUrl(route.trim())).filter(Boolean))
    : null;
  const activeLocalPages = (config.localPages || []).filter((item) => item.status !== "consolidate");
  const localRedirects = (config.localPages || [])
    .filter((item) => item.status === "consolidate" && item.redirectTo)
    .flatMap((item) => [
      {
        route: `/fonduri-europene-${item.slug}`,
        target: item.redirectTo,
        title: `Fonduri europene ${item.county}`
      },
      {
        route: `/consultanta-fonduri-europene-${item.slug}`,
        target: item.consultingRedirectTo || item.redirectTo,
        title: `Consultanta fonduri europene ${item.city}`
      }
    ]);
  const faqRedirects = (config.faqPages || [])
    .filter((item) => item.status === "redirect" && item.redirectTo)
    .map((item) => ({
      route: `/intrebari/${item.slug}`,
      target: item.redirectTo,
      title: item.question || item.slug
    }));
  const generatedPages = [
    ...(config.caenPages || []).map(caenPage),
    ...(config.regionalPages || []).map(regionalPage),
    ...activeLocalPages.flatMap((item) => [localPage(item, false), localPage(item, true)]),
    ...(config.faqPages || []).filter((item) => item.status !== "redirect").map(faqPage)
  ];
  const pages = onlyRoutes
    ? generatedPages.filter((page) => onlyRoutes.has(cleanUrl(page.route)))
    : generatedPages;
  if (onlyRoutes && pages.length !== onlyRoutes.size) {
    const found = new Set(pages.map((page) => cleanUrl(page.route)));
    const missing = [...onlyRoutes].filter((route) => !found.has(route));
    throw new Error(`Unknown or redirected --only route(s): ${missing.join(", ")}`);
  }
  for (const page of pages) writePage(page.route, page.content);
  if (onlyRoutes) {
    console.log(`Generated ${pages.length} selected programmatic SEO page(s): ${[...onlyRoutes].join(", ")}.`);
    return;
  }
  for (const redirect of [...localRedirects, ...faqRedirects]) writePage(redirect.route, redirectFallbackPage(redirect));
  updateSitemap(
    pages.map((page) => page.route),
    config.updatedAt || "2026-05-19",
    [...localRedirects, ...faqRedirects].map((redirect) => redirect.route)
  );
  console.log(`Generated ${pages.length} programmatic SEO pages and ${localRedirects.length + faqRedirects.length} redirect fallbacks.`);
}

main();
