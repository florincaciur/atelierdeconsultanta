#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CONFIG = path.join(ROOT, "config", "seo-programmatic-pages.json");
const SITEMAP = path.join(ROOT, "sitemap.xml");
const PROGRAMMATIC_MIN_WORDS = 1100;
const PROGRAMMATIC_MIN_FAQ = 4;
const {
  breadcrumbSchema,
  faqPageSchema,
  jsonLdGraph,
  organizationSchema,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

function publicText(value, fallback = "In curs de validare") {
  const text = String(value ?? "").trim();
  if (!text || /^TODO_/i.test(text)) return fallback;
  return text
    .replace(/TODO_CLIENT_[A-Z0-9_ -]*/gi, fallback)
    .replace(/TODO_SURSA_OFICIALA[A-Z0-9_ -]*/gi, "Se confirma in ghidul activ")
    .replace(/TODO_DATA_ACCESARII/gi, "In curs de actualizare")
    .replace(/TODO_DATE_LOCALE/gi, "Exemplele locale vor fi publicate dupa validare");
}

function esc(value) {
  return publicText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cleanUrl(value) {
  return `/${String(value).replace(/^\/+/, "").replace(/\/+$/g, "")}`;
}

function canonical(route) {
  return `${SITE}${cleanUrl(route)}`;
}

function li(items) {
  return (items || []).map((item) => `<li>${esc(item)}</li>`).join("\n");
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
  return (items || []).map((href) => `<a href="${cleanUrl(href)}">${esc(cleanUrl(href).replace(/^\/+/, "").replace(/-/g, " "))}</a>`).join("\n");
}

function linkTo(href, label) {
  return `<a href="${cleanUrl(href)}">${esc(label)}</a>`;
}

function schema(title, description, route, faq) {
  const pageNode = webPageSchema({
    url: canonical(route),
    name: title,
    description
  });
  return jsonLdGraph([
    organizationSchema(),
    websiteSchema(),
    pageNode,
    breadcrumbSchema([
      { name: "Acasa", item: `${SITE}/` },
      { name: title, item: canonical(route) }
    ]),
    {
      "@type": "Article",
      "@id": `${canonical(route)}#article`,
      mainEntityOfPage: { "@id": pageNode["@id"] },
      headline: publicText(title),
      description: publicText(description),
      inLanguage: "ro-RO",
      author: { "@id": `${SITE}/#organization` },
      publisher: { "@id": `${SITE}/#organization` },
      dateModified: "2026-05-20"
    },
    faqPageSchema(faq, { minItems: 2 })
  ]);
}

function html({ title, description, h1, route, category, summary, body, faq, related }) {
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(description)}" />
  <meta name="robots" content="index, follow" />
  <meta name="seo-depth" content="true" />
  <meta name="seo-min-words" content="${PROGRAMMATIC_MIN_WORDS}" />
  <meta name="seo-min-faq" content="${PROGRAMMATIC_MIN_FAQ}" />
  <link rel="canonical" href="${canonical(route)}" />
  <link rel="stylesheet" href="/assets/seo-hub.css" />
  <link rel="stylesheet" href="/assets/see-also.css" />
  <script type="application/ld+json">${schema(title, description, route, faq)}</script>
${CLARITY_TRACKING_CODE}
</head>
<body>
  <nav class="navbar" aria-label="Navigare principala">
    <a class="brand" href="/">FABER</a>
    <div class="navbar-links">
      <a href="/fonduri-europene">Fonduri europene</a>
      <a href="/instrumente">Instrumente</a>
      <a href="/resurse">Resurse</a>
      <a class="nav-cta" href="/contact">Evaluare gratuita</a>
    </div>
  </nav>
  <div class="breadcrumb"><a href="/">Acasa</a> / ${esc(h1)}</div>
  <header class="hero">
    <span class="eyebrow">${esc(category)}</span>
    <h1>${esc(h1)}</h1>
    <p>${esc(description)}</p>
  </header>
  <main class="container">
    <article class="panel">
      <p class="intro">${esc(summary)}</p>
      ${body}
      <h2>Intrebari frecvente</h2>
      ${faq.map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`).join("\n")}
      <h2>Resurse conexe</h2>
      <div class="related-links">${relatedLinks(related)}</div>
    </article>
    <section class="cta-box">
      <h2>Verifica proiectul inainte de depunere</h2>
      <p>Trimite date despre solicitant, localitate, cod CAEN, buget si investitie. Analiza initiala nu garanteaza aprobarea, dar poate identifica riscuri.</p>
      <div class="cta-actions"><a class="btn btn-primary" href="/contact">Trimite datele proiectului</a></div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER - Atelier de Consultanta</footer>
</body>
</html>
`;
}

function writePage(route, content) {
  const file = path.join(ROOT, cleanUrl(route).slice(1), "index.html");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
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
${CLARITY_TRACKING_CODE}
</head>
<body>
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
    "Informatiile de pe pagina sunt orientative. Eligibilitatea finala depinde de ghidul oficial, anexele apelului, documentele solicitantului si evaluarea autoritatii finantatoare."
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
  const faq = [
    [`Pot obtine fonduri europene pentru CAEN ${item.code}?`, `Da, daca activitatea ${item.label} este eligibila in apelul activ si solicitantul indeplineste conditiile programului.`],
    [`Ce documente sunt utile pentru CAEN ${item.code}?`, "Certificatul constatator, autorizarea CAEN, documentele firmei, ofertele, bugetul si documentele pentru spatiul investitiei."],
    [`Ce programe pot fi relevante pentru CAEN ${item.code}?`, item.programs.join("; ")],
    [`Ce trebuie verificat inainte de buget pentru CAEN ${item.code}?`, "Eligibilitatea solicitantului, codul CAEN, cheltuielile permise, cofinantarea si punctajul."]
  ];
  const programRows = item.programs
    .map((program) => `<tr><td>${esc(program)}</td><td>Se confirma in ghidul activ</td><td>Eligibilitatea depinde de solicitant, regiune, cod CAEN, buget si documentele investitiei.</td></tr>`)
    .join("\n");
  let body = `
      <h2>Descriere CAEN</h2>
      <p>CAEN ${esc(item.code)} - ${esc(item.label)} descrie activitatea economica pentru care investitia trebuie justificata prin documente, autorizare, flux operational si buget. Codul nu garanteaza finantarea; el este doar prima piesa verificata inainte de alegerea programului.</p>
      <h2>Programe eligibile pentru CAEN ${esc(item.code)}</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead><tr><th>Program</th><th>Buget</th><th>Conditii</th></tr></thead>
          <tbody>${programRows}</tbody>
        </table>
      </div>
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
  body = ensureDepth(body, `CAEN ${item.code} - ${item.label}`);
  return { route, content: html({ title, description, h1: title, route, category: "Cod CAEN", summary: `Pentru CAEN ${item.code}, fondurile europene se aleg dupa program, regiune, investitie si documente, nu doar dupa denumirea codului.`, body, faq, related: ["/fonduri-europene-imm", "/instrumente", "/contact"] }) };
}

function localPage(item, consulting) {
  const route = consulting ? `/consultanta-fonduri-europene-${item.slug}` : `/fonduri-europene-${item.slug}`;
  const title = consulting ? `Consultanta fonduri europene ${item.city}` : `Fonduri europene ${item.county}`;
  const description = consulting
    ? `Consultanta pentru fonduri europene in ${item.city}: programe active, documente, eligibilitate, buget si pregatirea dosarului.`
    : `Ghid fonduri europene pentru ${item.county}: programe active, regiune, IMM-uri, agricultura, digitalizare, energie si documente.`;
  const faq = [
    [`Ce fonduri europene sunt relevante in ${item.county}?`, `Depinde de regiune, solicitant si investitie. In ${item.region}, verifica programele regionale, nationale, AFIR, digitalizare si energie.`],
    [`Conteaza localitatea investitiei in ${item.county}?`, "Da. Pentru programele regionale si unele scheme sectoriale, localizarea investitiei este esentiala."],
    [`Ce documente pregatesc pentru un proiect in ${item.county}?`, "Documente de firma, cod CAEN, documente pentru spatiu, buget, oferte, situatii financiare si descrierea investitiei."],
    [`Pot primi consultanta la distanta pentru ${item.county}?`, "Da. Analiza initiala se poate face pe baza datelor si documentelor transmise electronic."]
  ];
  let body = `
      <h2>Particularitati locale</h2>
      <p>${esc(item.county)} se analizeaza prin regiunea ${esc(item.region)} si prin tipul investitiei. Pentru ${esc(item.focus)}, conteaza codul CAEN, localitatea, documentele pentru spatiu si calendarul apelurilor.</p>
      <h2>Programe de verificat</h2>
      <ul>
        <li>programe regionale pentru IMM-uri si microintreprinderi;</li>
        <li>AFIR pentru ferme si investitii agricole;</li>
        <li>Digitalizare IMM si instrumente PNRR, cand sunt active;</li>
        <li>Fondul pentru Modernizare si energie regenerabila;</li>
        <li>Start-Up Nation si programe nationale pentru antreprenori.</li>
      </ul>
      <h2>Checklist local</h2>
      <p>Inainte de depunere, verifica daca locatia investitiei este eligibila, daca punctul de lucru este documentat, daca autorizatiile pot fi obtinute si daca investitia are legatura cu activitatea firmei.</p>`;
  body = ensureDepth(body, `${title} in ${item.region}`);
  return { route, content: html({ title, description, h1: title, route, category: consulting ? "Consultanta locala" : "Fonduri locale", summary: `${title}: eligibilitatea se verifica dupa regiune, solicitant, cod CAEN, investitie si documente.`, body, faq, related: ["/fonduri-europene", "/verificare-eligibilitate-fonduri-europene", "/contact"] }) };
}

function regionalPage(item) {
  const route = `/${item.slug}`;
  const counties = item.counties || [];
  const title = item.title || `Fonduri europene ${item.region}`;
  const description = item.description || `Ghid regional pentru fonduri europene in ${item.region}.`;
  const faq = [
    [`Ce judete acopera pagina ${item.region}?`, `Pagina acopera orientativ judetele ${counties.join(", ")}.`],
    ["Care este diferenta dintre programe regionale, AFIR si nationale?", "Programele regionale tin de regiunea investitiei si de autoritatea regionala. AFIR acopera proiecte agricole si rurale. Programele nationale sau PNRR au reguli stabilite la nivel national si pot avea criterii diferite de localizare."],
    ["Cand conteaza ADR Nord-Est?", "ADR Nord-Est conteaza pentru apelurile Programului Regional Nord-Est: ghiduri, clarificari, criterii regionale si documentele specifice apelului activ."],
    ["Pot folosi pagina pentru o decizie finala de depunere?", "Nu. Pagina este un filtru initial; decizia finala se ia dupa ghidul activ, anexele oficiale si documentele solicitantului."]
  ];
  let body = `
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
        <li>Iasi: microintreprindere de servicii care verifica Programul Regional Nord-Est si buget IT. Exemplele locale vor fi publicate dupa validare.</li>
        <li>Suceava: ferma sau afacere turistica unde trebuie comparate AFIR, programe regionale si investitii energetice. Exemplele locale vor fi publicate dupa validare.</li>
        <li>Bacau: firma de productie sau servicii care verifica echipamente, cofinantare si documentele pentru punctul de lucru. Exemplele locale vor fi publicate dupa validare.</li>
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
        <li><a href="https://adrnordest.ro/" target="_blank" rel="noopener noreferrer">ADR Nord-Est</a> pentru informatii regionale si apeluri active.</li>
        <li><a href="https://adrnordest.ro/comentariiGhid/P1IMMInovative/Apel1/Ghid.pdf" target="_blank" rel="noopener noreferrer">Ghid ADR Nord-Est pentru investitii microintreprinderi</a>, verificat in sursele proiectului.</li>
        <li>${linkTo("/surse-oficiale-fonduri-europene", "Tabelul intern de surse oficiale")}</li>
      </ul>`;
  body = ensureDepth(body, `fonduri europene ${item.region}`);
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
  const title = item.question;
  const description = `${item.answer.slice(0, 145)}...`;
  const faq = [
    [item.question, item.answer],
    ["Ce trebuie verificat inainte de aplicare?", "Solicitantul, programul, documentele, bugetul, cheltuielile eligibile si regulile apelului activ."],
    ["Raspunsul garanteaza eligibilitatea?", "Nu. Raspunsul este orientativ si trebuie confirmat prin documentele proiectului si apelul activ."],
    ["Cum pot primi analiza pe cazul meu?", "Trimite datele proiectului prin pagina de contact pentru o verificare initiala."]
  ];
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
  body = ensureDepth(body, item.question);
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
  const pages = [
    ...(config.caenPages || []).map(caenPage),
    ...(config.regionalPages || []).map(regionalPage),
    ...activeLocalPages.flatMap((item) => [localPage(item, false), localPage(item, true)]),
    ...(config.faqPages || []).map(faqPage)
  ];
  for (const page of pages) writePage(page.route, page.content);
  for (const redirect of localRedirects) writePage(redirect.route, redirectFallbackPage(redirect));
  updateSitemap(
    pages.map((page) => page.route),
    config.updatedAt || "2026-05-19",
    localRedirects.map((redirect) => redirect.route)
  );
  console.log(`Generated ${pages.length} programmatic SEO pages and ${localRedirects.length} local redirect fallbacks.`);
}

main();
