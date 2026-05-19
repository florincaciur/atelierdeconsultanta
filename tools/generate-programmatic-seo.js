#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CONFIG = path.join(ROOT, "config", "seo-programmatic-pages.json");
const SITEMAP = path.join(ROOT, "sitemap.xml");

function esc(value) {
  return String(value ?? "")
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

function relatedLinks(items) {
  return (items || []).map((href) => `<a href="${cleanUrl(href)}">${esc(cleanUrl(href).replace(/^\/+/, "").replace(/-/g, " "))}</a>`).join("\n");
}

function schema(title, description, route, faq) {
  return JSON.stringify({
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${SITE}/#organization`,
        "name": "Atelier de Consultanta",
        "url": SITE,
        "email": "atelier.consultanta@gmail.com",
        "telephone": ["+40769828338", "+40753326229"]
      },
      {
        "@type": "WebPage",
        "@id": `${canonical(route)}#webpage`,
        "url": canonical(route),
        "name": title,
        "description": description,
        "inLanguage": "ro-RO",
        "publisher": { "@id": `${SITE}/#organization` },
        "speakable": {
          "@type": "SpeakableSpecification",
          "cssSelector": ["#speakable-summary", "#speakable-answer"]
        }
      },
      {
        "@type": "BreadcrumbList",
        "itemListElement": [
          { "@type": "ListItem", "position": 1, "name": "Acasa", "item": `${SITE}/` },
          { "@type": "ListItem", "position": 2, "name": title, "item": canonical(route) }
        ]
      },
      {
        "@type": "FAQPage",
        "mainEntity": faq.map(([question, answer]) => ({
          "@type": "Question",
          "name": question,
          "acceptedAnswer": { "@type": "Answer", "text": answer }
        }))
      }
    ]
  }, null, 2);
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
  <link rel="canonical" href="${canonical(route)}" />
  <link rel="stylesheet" href="/assets/seo-hub.css" />
  <link rel="stylesheet" href="/assets/see-also.css" />
  <script type="application/ld+json">${schema(title, description, route, faq)}</script>
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
      <p id="speakable-summary" class="intro speakable" data-speakable="true">${esc(summary)}</p>
      ${body}
      <h2>Intrebari frecvente</h2>
      ${faq.map(([question, answer], index) => `<section class="faq-item"><h3>${esc(question)}</h3><p${index === 0 ? ' id="speakable-answer" class="speakable" data-speakable="true"' : ""}>${esc(answer)}</p></section>`).join("\n")}
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

function caenPage(item) {
  const route = `/fonduri-europene-caen/${item.code}-${item.slug}`;
  const title = `Fonduri europene pentru CAEN ${item.code} - ${item.label}`;
  const description = `Ghid pentru CAEN ${item.code}: programe posibile, investitii eligibile, documente, punctaj si checklist pentru ${item.label}.`;
  const faq = [
    [`Pot obtine fonduri europene pentru CAEN ${item.code}?`, `Da, daca activitatea ${item.label} este eligibila in apelul activ si solicitantul indeplineste conditiile programului.`],
    ["Ce documente sunt utile?", "Certificatul constatator, autorizarea CAEN, documentele firmei, ofertele, bugetul si documentele pentru spatiul investitiei."],
    ["Ce programe pot fi relevante?", item.programs.join("; ")],
    ["Ce trebuie verificat inainte de buget?", "Eligibilitatea solicitantului, codul CAEN, cheltuielile permise, cofinantarea si punctajul."]
  ];
  const body = `
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
    ["Conteaza localitatea investitiei?", "Da. Pentru programele regionale si unele scheme sectoriale, localizarea investitiei este esentiala."],
    ["Ce documente pregatesc?", "Documente de firma, cod CAEN, documente pentru spatiu, buget, oferte, situatii financiare si descrierea investitiei."],
    ["Pot primi consultanta la distanta?", "Da. Analiza initiala se poate face pe baza datelor si documentelor transmise electronic."]
  ];
  const body = `
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
  return { route, content: html({ title, description, h1: title, route, category: consulting ? "Consultanta locala" : "Fonduri locale", summary: `${title}: eligibilitatea se verifica dupa regiune, solicitant, cod CAEN, investitie si documente.`, body, faq, related: ["/fonduri-europene", "/verificare-eligibilitate-fonduri-europene", "/contact"] }) };
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
  const body = `
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
  return { route, content: html({ title, description, h1: title, route, category: "Intrebare frecventa", summary: item.answer, body, faq, related: item.related }) };
}

function updateSitemap(routes, updatedAt) {
  const existing = fs.existsSync(SITEMAP)
    ? [...fs.readFileSync(SITEMAP, "utf8").matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1].replace(SITE, ""))
    : ["/"];
  const seen = new Set();
  const all = [...existing, ...routes].map(cleanUrl).filter((route) => {
    if (seen.has(route)) return false;
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
  const pages = [
    ...(config.caenPages || []).map(caenPage),
    ...(config.localPages || []).flatMap((item) => [localPage(item, false), localPage(item, true)]),
    ...(config.faqPages || []).map(faqPage)
  ];
  for (const page of pages) writePage(page.route, page.content);
  updateSitemap(pages.map((page) => page.route), config.updatedAt || "2026-05-19");
  console.log(`Generated ${pages.length} programmatic SEO pages.`);
}

main();
