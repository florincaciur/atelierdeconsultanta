const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const TODAY = "2026-05-11";
const {
  SITE,
  buildPageMetadata,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  canonicalUrl,
  faqPageSchema,
  jsonLdGraph,
  normalizeCanonicalPath,
  organizationSchema,
  standardInternalLinksForPath,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const { designFamilyForSlug } = require("./design-family-map");
const { brandLogoLink } = require("./brand-logo");
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;
const CANONICAL_ALIASES = new Map([
  ["/start-up-nation", "/start-up-nation-2026"],
  ["/consultanta-start-up-nation", "/consultanta-start-up-nation-2026"],
  ["/start-up-nation-2026-idei-afaceri-plan", "/start-up-nation-2026-idei-afaceri"],
]);
const REDIRECTED_PAGE_SLUGS = new Set(["start-up-nation", "consultanta-start-up-nation"]);

function cleanPath(value) {
  if (!value || value === "/") return "/";
  const hashIndex = value.indexOf("#");
  const queryIndex = value.indexOf("?");
  const suffixIndex = [hashIndex, queryIndex].filter((index) => index >= 0).sort((a, b) => a - b)[0];
  const pathname = suffixIndex >= 0 ? value.slice(0, suffixIndex) : value;
  const suffix = suffixIndex >= 0 ? value.slice(suffixIndex) : "";
  if (!pathname || pathname === "/") return `/${suffix}`;
  const withoutHtml = pathname.replace(/\.html$/i, "");
  const withoutSlash = withoutHtml.length > 1 ? withoutHtml.replace(/\/+$/g, "") : withoutHtml;
  const clean = withoutSlash || "/";
  return `${CANONICAL_ALIASES.get(clean) || clean}${suffix}`;
}

function cleanHref(value) {
  if (!value) return value;
  if (value.startsWith(`${SITE}/`)) {
    const pathPart = value.slice(SITE.length);
    return cleanPath(pathPart);
  }
  if (value.startsWith("/")) return cleanPath(value);
  return value;
}

function pageText(page) {
  return `${page.slug || ""} ${page.category || ""} ${page.title || ""} ${page.h1 || ""}`.toLowerCase();
}

function designFamilyFor(page) {
  const mappedFamily = designFamilyForSlug(page.slug || "");
  if (mappedFamily) return mappedFamily;
  const text = pageText(page);
  if (/afir|dr12|dr14|agricultur|ferme|utilaje/.test(text)) return "afir";
  if (/digitalizare|pnrr|software|cloud|crm|erp/.test(text)) return "digital";
  if (/start-up|startup|femei antreprenor|femeia/.test(text)) return "startup";
  if (/energie|fotovoltaic|modernizare|autoconsum|e-move|infra/.test(text)) return "energy";
  if (/consultanta|consultant|eligibilitate|servici/.test(text)) return "service";
  if (/studii|testimoniale|portofoliu|caz/.test(text)) return "trust";
  if (/ghid|blog|resurse|glosar|calendar|intrebari/.test(text)) return "editorial";
  return "cluster";
}

function designProfileFor(page) {
  const family = designFamilyFor(page);
  const profiles = {
    afir: ["AFIR | status apel | verificare documente", "ph-duotone ph-plant", ["Solicitant", "Investitie", "Documente", "Punctaj"]],
    digital: ["PNRR/MIPE | digitalizare | ghid verificat", "ph-duotone ph-desktop", ["Hardware", "Software", "Cloud", "Cybersecurity"]],
    startup: ["Antreprenoriat | ghid | status oficial", "ph-duotone ph-rocket-launch", ["Eligibilitate", "CAEN", "Buget", "Plan afaceri"]],
    energy: ["Energie | autoconsum | avize", "ph-duotone ph-sun", ["Consum", "Avize", "Capacitate", "Buget"]],
    service: ["Serviciu FABER | proces | livrabile", "ph-duotone ph-magnifying-glass", ["Verificare", "Strategie", "Dosar", "Clarificari"]],
    editorial: ["Ghid editorial | actualizat | surse citate", "ph-duotone ph-file-text", ["Pe scurt", "Ce verifici", "Greseli", "Pasi"]],
    trust: ["Dovada sociala | caz anonimizat | rezultat", "ph-duotone ph-bank", ["Beneficiar", "Problema", "Interventie", "Rezultat"]],
    cluster: ["FABER | resursa | actualizare", "ph-duotone ph-info", ["Program", "Solicitant", "Documente", "Riscuri"]]
  };
  return profiles[family] || profiles.cluster;
}

function renderHubHeroSummary(page) {
  const items = [
    ["Beneficiar", (page.audience || [page.category || "solicitant"])[0]],
    ["Status", "se confirma in ghidul activ"],
    ["Documente", (page.checks || ["documente si buget"]).slice(0, 2).join("; ")],
    ["Risc", "eligibilitate neconfirmata"]
  ];
  return `<div class="hero-summary" aria-label="Rezumat vizual">
      ${items.map(([label, value]) => `<span class="hero-summary__item"><strong>${esc(label)}</strong><em>${esc(value)}</em></span>`).join("\n      ")}
    </div>`;
}

function renderHubDesignCards(page) {
  const [badge, , cards] = designProfileFor(page);
  return `<section class="design-card-grid design-card-grid--${esc(designFamilyFor(page))}" aria-label="${esc(badge)}">
        ${cards.map((label, index) => `<article class="mini-card design-card"><span class="design-card__badge">${esc(label)}</span><h3>${esc(label)}</h3><p>${esc((page.checks || page.steps || page.audience || [page.summary])[index] || page.summary)}</p></article>`).join("\n        ")}
      </section>`;
}

const related = {
  contact: ["/contact", "Solicită evaluare gratuită"],
  consultanta: ["/consultanta-fonduri-europene", "Consultanță fonduri europene"],
  fonduri: ["/fonduri-europene", "Fonduri europene"],
  nerambursabile: ["/fonduri-nerambursabile", "Finanțări nerambursabile"],
  eligibilitate: ["/eligibilitate-fonduri-europene", "Eligibilitate fonduri europene"],
  calendar: ["/calendar-fonduri-europene", "Calendar fonduri europene"],
  ghiduri: ["/ghiduri", "Ghiduri fonduri europene"],
  afir: ["/afir", "AFIR"],
  consultantaAfir: ["/consultanta-afir", "Consultanță AFIR"],
  agricultura: ["/fonduri-europene-agricultura", "Fonduri europene agricultură"],
  pnrr: ["/pnrr", "PNRR"],
  digitalizare: ["/fonduri-europene-digitalizare", "Fonduri pentru digitalizare"],
  startup: ["/start-up-nation-2026", "Start-Up Nation 2026"],
  imm: ["/fonduri-europene-imm", "Fonduri europene IMM"],
  nordest: ["/fonduri-europene-nord-est", "Fonduri europene Nord-Est"],
  caseStudies: ["/studii-de-caz-fonduri-europene", "Studii de caz fonduri europene"],
  femei: ["/fonduri-europene-femei-antreprenor", "Fonduri pentru femei antreprenor"],
  intrebari: ["/intrebari-frecvente", "Întrebări frecvente"],
};

const pages = [
  {
    slug: "fonduri-europene",
    category: "Hub fonduri europene",
    title: "Fonduri Europene în România | Ghid pentru IMM-uri și antreprenori",
    description: "Hub despre fonduri europene în România: programe, eligibilitate, documente, pași de aplicare și resurse pentru IMM-uri, fermieri și antreprenori.",
    h1: "Fonduri europene în România",
    summary: "Această pagină centralizează resursele utile pentru antreprenori, IMM-uri, fermieri și instituții care vor să înțeleagă ce finanțări pot fi potrivite înainte de pregătirea unui dosar.",
    audience: ["IMM-uri care planifică investiții în echipamente, digitalizare, energie sau extindere", "Fermieri interesați de AFIR, DR 12, DR 14 sau proiecte pentru ferme", "Antreprenori aflați la început care urmăresc Start-Up Nation sau granturi similare"],
    checks: ["încadrarea solicitantului și codul CAEN", "vechimea firmei, istoricul financiar și obligațiile fiscale", "bugetul investiției, cofinanțarea și documentele care pot fi obținute la timp"],
    steps: ["identifică programul compatibil cu investiția", "verifică ghidul solicitantului și grila de punctaj", "pregătește documentele minime înainte de lansarea apelului", "discută cu un consultant dacă proiectul are condiții tehnice sau financiare sensibile"],
    links: [related.consultanta, related.caseStudies, related.nerambursabile, related.imm, related.agricultura, related.pnrr, related.ghiduri],
  },
  {
    slug: "fonduri-nerambursabile",
    category: "Finanțări nerambursabile",
    title: "Fonduri Nerambursabile | Programe, Eligibilitate și Pași",
    description: "Explicații despre fonduri nerambursabile, diferențe față de credite, pași de pregătire și linkuri către programe relevante pentru firme și fermieri.",
    h1: "Fonduri nerambursabile",
    summary: "Fondurile nerambursabile pot acoperi o parte din investiție, dar fiecare program are reguli proprii privind solicitantul, cheltuielile, contribuția proprie și perioada de implementare.",
    audience: ["firme care vor investi fără să se bazeze exclusiv pe credit bancar", "persoane care pregătesc o firmă nouă sau un proiect de dezvoltare", "beneficiari care au nevoie să compare granturi, ajutoare de stat și scheme sectoriale"],
    checks: ["procentul nerambursabil și contribuția proprie", "cheltuielile eligibile și neeligibile", "obligațiile după aprobare, inclusiv menținerea investiției și raportarea"],
    steps: ["definește investiția în termeni măsurabili", "verifică dacă solicitantul este eligibil", "calculează cash-flow-ul și cofinanțarea", "pregătește documentele înainte de deschiderea apelului"],
    links: [related.fonduri, related.eligibilitate, related.calendar, related.consultanta, ["/acte-necesare-fonduri-europene-nerambursabile", "Acte necesare fonduri europene"]],
  },
  {
    slug: "pnrr",
    category: "PNRR",
    title: "PNRR pentru IMM-uri | Digitalizare, Eligibilitate și Consultanță",
    description: "Hub PNRR pentru IMM-uri: digitalizare, cheltuieli eligibile, pași de pregătire, documente și legături către ghiduri utile.",
    h1: "PNRR pentru IMM-uri și proiecte de digitalizare",
    summary: "PNRR finanțează proiecte cu obiective clare, rezultate măsurabile și termene stricte. Pentru IMM-uri, zona de digitalizare rămâne una dintre cele mai căutate direcții.",
    audience: ["IMM-uri care vor ERP, CRM, automatizare, cloud sau securitate cibernetică", "firme care trebuie să conecteze investiția la procese reale", "antreprenori care vor să evite liste de echipamente fără justificare"],
    checks: ["nevoia reală de digitalizare și procesele afectate", "compatibilitatea cheltuielilor cu ghidul activ", "capacitatea de implementare și raportare în termen"],
    steps: ["descrie fluxurile actuale ale firmei", "separă software-ul, hardware-ul și serviciile eligibile", "verifică indicatorii ceruți de program", "pregătește ofertele și justificarea tehnică"],
    links: [related.digitalizare, ["/digitalizare-imm-pnrr", "Digitalizare IMM / PNRR"], ["/pnrr-digitalizare-imm-cheltuieli-eligibile", "Cheltuieli eligibile PNRR"], ["/consultanta-pnrr-digitalizare", "Consultanță PNRR digitalizare"], related.contact],
  },
  {
    slug: "afir",
    category: "AFIR",
    title: "AFIR | Fonduri pentru Fermieri, DR 12, DR 14 și Agricultură",
    description: "Hub AFIR cu linkuri către DR 12, DR 14, calculator SO, consultanță AFIR și resurse pentru fonduri europene în agricultură.",
    h1: "AFIR: fonduri pentru fermieri și proiecte agricole",
    summary: "Programele AFIR cer o verificare atentă a exploatației, a dimensiunii economice, a formei juridice și a documentelor privind terenurile, animalele sau investițiile propuse.",
    audience: ["tineri fermieri interesați de instalare", "ferme mici care urmăresc investiții prin DR 14", "ferme și procesatori care analizează energie, utilaje sau modernizare"],
    checks: ["Standard Output și încadrarea exploatației", "documentele APIA, ANSVSA, registrul agricol sau alte evidențe cerute", "eligibilitatea investiției față de ghidul programului"],
    steps: ["calculează dimensiunea economică a fermei", "verifică forma juridică și istoricul exploatației", "pregătește planul de investiții și ofertele", "revizuiește riscurile înainte de depunere"],
    links: [related.consultantaAfir, ["/dr12-afir", "DR 12 AFIR"], ["/dr14", "DR 14 AFIR"], ["/calculator-soc", "Calculator SO AFIR"], related.agricultura],
  },
  {
    slug: "start-up-nation",
    category: "Start-Up Nation",
    title: "Start-Up Nation | Condiții, Cheltuieli și Consultanță",
    description: "Hub Start-Up Nation cu resurse despre condiții, cheltuieli eligibile, idei de afaceri, plan de afaceri și consultanță pentru aplicare.",
    h1: "Start-Up Nation",
    summary: "Start-Up Nation este un program urmărit de antreprenorii la început de drum. Pregătirea corectă începe cu o idee realistă, un buget coerent și documente care pot susține planul de afaceri.",
    audience: ["viitori antreprenori care vor să testeze eligibilitatea ideii", "persoane care pregătesc codul CAEN, bugetul și locurile de muncă", "firme noi care vor să evite cheltuieli greu de justificat"],
    checks: ["condițiile solicitantului și forma juridică", "codul CAEN și autorizațiile necesare", "bugetul, contribuția proprie și cheltuielile eligibile"],
    steps: ["alege ideea de afacere și codul CAEN", "verifică lista de cheltuieli eligibile", "construiește bugetul și planul de afaceri", "pregătește documentele înainte de deschiderea apelului"],
    links: [["/start-up-nation-2026", "Start-Up Nation 2026"], ["/start-up-nation-2026-conditii", "Condiții Start-Up Nation"], ["/start-up-nation-2026-cheltuieli-eligibile", "Cheltuieli eligibile"], ["/consultanta-start-up-nation", "Consultanță Start-Up Nation"], related.contact],
  },
  {
    slug: "fonduri-europene-imm",
    category: "IMM",
    title: "Fonduri Europene pentru IMM-uri | Investiții, Digitalizare, Energie",
    description: "Resurse pentru IMM-uri care caută fonduri europene: investiții, digitalizare, energie, eligibilitate, pași și consultanță.",
    h1: "Fonduri europene pentru IMM-uri",
    summary: "IMM-urile pot accesa finanțări pentru investiții productive, digitalizare, eficiență energetică, extindere sau servicii specializate, în funcție de regiune și program.",
    audience: ["microîntreprinderi, întreprinderi mici și mijlocii", "firme cu investiții în utilaje, software, energie sau extindere", "antreprenori care vor o evaluare înainte de pregătirea dosarului"],
    checks: ["încadrarea IMM și datele financiare", "codul CAEN autorizat sau autorizabil", "cofinanțarea și capacitatea de implementare"],
    steps: ["stabilește investiția și obiectivele economice", "verifică programul regional sau național potrivit", "pregătește bugetul și documentele firmei", "corelează proiectul cu punctajul programului"],
    links: [related.consultanta, related.nordest, related.digitalizare, related.startup, ["/por-adr-nord-est", "POR ADR Nord-Est"], related.eligibilitate],
  },
  {
    slug: "fonduri-europene-agricultura",
    category: "Agricultură",
    title: "Fonduri Europene Agricultură | AFIR, Ferme, Utilaje și Tineri Fermieri",
    description: "Hub despre fonduri europene pentru agricultură: AFIR, DR 12, DR 14, ferme mici, utilaje agricole, calculator SO și consultanță.",
    h1: "Fonduri europene pentru agricultură",
    summary: "În agricultură, eligibilitatea depinde de exploatație, dimensiune economică, documentele de folosință și investiția propusă. O verificare timpurie reduce riscul unui dosar respins.",
    audience: ["tineri fermieri", "ferme mici sau ferme aflate în dezvoltare", "beneficiari care pregătesc utilaje, construcții agricole sau energie pentru fermă"],
    checks: ["Standard Output, suprafețe și efective", "acte de proprietate sau folosință", "încadrarea investiției în ghidul activ"],
    steps: ["calculează SO", "pregătește documentele exploatației", "alege investițiile compatibile", "verifică punctajul și riscurile de eligibilitate"],
    links: [related.afir, related.consultantaAfir, ["/fonduri-pentru-ferme", "Fonduri pentru ferme"], ["/fonduri-pentru-utilaje-agricole", "Fonduri pentru utilaje agricole"], ["/calculator-soc", "Calculator SO"]],
  },
  {
    slug: "fonduri-europene-digitalizare",
    category: "Digitalizare",
    title: "Fonduri Europene Digitalizare | PNRR și Granturi pentru IMM-uri",
    description: "Hub despre fonduri pentru digitalizare: PNRR, ERP, CRM, cloud, securitate cibernetică, automatizare și consultanță pentru IMM-uri.",
    h1: "Fonduri europene pentru digitalizare",
    summary: "Proiectele de digitalizare sunt mai solide când pornesc de la procesele firmei: vânzări, producție, contabilitate, stocuri, relația cu clienții sau securitatea datelor.",
    audience: ["IMM-uri care vor software de gestiune sau automatizare", "firme care pregătesc investiții în cloud, securitate sau echipamente IT", "beneficiari care au nevoie să justifice transformarea digitală"],
    checks: ["nevoia de business și indicatorii digitali", "eligibilitatea software-ului, hardware-ului și serviciilor", "ofertele și specificațiile tehnice"],
    steps: ["cartografiază procesele actuale", "definește rezultatul digital urmărit", "verifică ghidul și cheltuielile eligibile", "pregătește dosarul cu justificări clare"],
    links: [related.pnrr, ["/digitalizare-imm", "Digitalizare IMM"], ["/digitalizare-imm-pnrr", "Digitalizare IMM / PNRR"], ["/granturi-digitalizare-imm", "Granturi digitalizare IMM"], ["/consultanta-pnrr-digitalizare", "Consultanță PNRR digitalizare"]],
  },
  {
    slug: "fonduri-europene-femei-antreprenor",
    category: "Antreprenoriat feminin",
    title: "Fonduri Europene pentru Femei Antreprenor | Ghid și Consultanță",
    description: "Resurse pentru femei antreprenor: programe dedicate, eligibilitate, idei de afaceri, documente, buget și pași de pregătire.",
    h1: "Fonduri europene pentru femei antreprenor",
    summary: "Programele dedicate femeilor antreprenor trebuie analizate prin prisma structurii acționariatului, activității firmei, vechimii, codului CAEN și investițiilor planificate.",
    audience: ["firme cu acționariat majoritar feminin", "antreprenoare care pregătesc investiții sau extindere", "beneficiare care vor să compare programul dedicat cu alte finanțări pentru IMM-uri"],
    checks: ["structura acționariatului și istoricul firmei", "codul CAEN și investiția eligibilă", "documentele contabile și bugetul proiectului"],
    steps: ["verifică eligibilitatea firmei", "clarifică ideea de investiție", "pregătește bugetul și documentele", "compară programul cu alte finanțări IMM"],
    links: [["/femeia-antreprenor-2026", "Femeia Antreprenor 2026"], ["/femeia-antreprenor-2026-conditii-idei-afaceri", "Condiții și idei de afaceri"], related.imm, related.consultanta, related.contact],
  },
  {
    slug: "calendar-fonduri-europene",
    category: "Calendar",
    title: "Calendar Fonduri Europene | Programe și Pregătire Dosare",
    description: "Calendar orientativ pentru fonduri europene: ce programe urmărești, ce pregătești înainte de apel și cum eviți depunerea pe grabă.",
    h1: "Calendar fonduri europene",
    summary: "Un calendar util nu înseamnă doar data lansării. Înseamnă documente pregătite, buget verificat, oferte actualizate și o decizie clară privind programul potrivit.",
    audience: ["firme care vor să pregătească dosarul înainte de deschiderea apelului", "fermieri care urmăresc sesiunile AFIR", "antreprenori care nu vor să piardă termene din lipsă de documente"],
    checks: ["stadiul ghidului solicitantului", "documentele care pot expira", "timpul necesar pentru oferte, avize sau autorizații"],
    steps: ["monitorizează programele relevante", "pregătește documentele de firmă și investiție", "actualizează ofertele înainte de depunere", "confirmă eligibilitatea înainte de a bloca bugetul"],
    links: [related.fonduri, related.eligibilitate, related.ghiduri, ["/blog", "Blog fonduri europene"], related.contact],
  },
  {
    slug: "eligibilitate-fonduri-europene",
    category: "Eligibilitate",
    title: "Eligibilitate Fonduri Europene | Verificare Firmă și Proiect",
    description: "Ghid pentru verificarea eligibilității la fonduri europene: firmă, CAEN, cheltuieli, documente, cofinanțare și riscuri frecvente.",
    h1: "Eligibilitate fonduri europene",
    summary: "Eligibilitatea se verifică pe două niveluri: solicitantul și proiectul. O firmă eligibilă poate avea o investiție neeligibilă, iar o idee bună poate pica din lipsă de documente.",
    audience: ["firme care vor o verificare înainte de pregătirea dosarului", "fermieri care trebuie să confirme încadrarea exploatației", "antreprenori care compară mai multe programe"],
    checks: ["statutul solicitantului, codul CAEN și situația fiscală", "vechimea firmei, datele financiare și ajutoarele primite", "cheltuielile, locația investiției și documentele suport"],
    steps: ["strânge datele de firmă", "descrie investiția în detaliu", "compară cerințele programului", "notează riscurile și documentele lipsă"],
    links: [related.consultanta, related.contact, ["/acte-necesare-fonduri-europene-nerambursabile", "Acte necesare"], related.calendar, related.intrebari],
  },
  {
    slug: "ghiduri",
    category: "Ghiduri",
    title: "Ghiduri Fonduri Europene | Resurse pentru Pregătirea Dosarului",
    description: "Colecție de ghiduri și articole despre fonduri europene, AFIR, PNRR, Start-Up Nation, documente, cheltuieli eligibile și greșeli frecvente.",
    h1: "Ghiduri pentru fonduri europene",
    summary: "Ghidurile de pe site sunt resurse orientative pentru pregătirea proiectelor. Pentru decizii finale trebuie verificat întotdeauna ghidul oficial al apelului activ.",
    audience: ["antreprenori care vor să înțeleagă pașii înainte de depunere", "beneficiari care compară programe", "echipe care pregătesc documente și bugete"],
    checks: ["data actualizării informației", "diferența dintre articol informativ și ghid oficial", "linkurile către programele și paginile conexe"],
    steps: ["alege clusterul potrivit", "citește pagina comercială relevantă", "verifică articolul detaliat", "solicită evaluare dacă există neclarități"],
    links: [[ "/blog", "Blog" ], ["/cum-alegi-programul-potrivit-fonduri-europene-2026", "Cum alegi programul potrivit"], ["/acte-necesare-fonduri-europene-nerambursabile", "Acte necesare"], ["/greseli-fonduri-europene", "Greșeli frecvente"], related.contact],
  },
  {
    slug: "studii-de-caz",
    category: "Studii de caz",
    title: "Studii de Caz Fonduri Europene | Exemple Publicabile și Lecții",
    description: "Pagină pentru studii de caz publicabile despre fonduri europene. Nu include rezultate, nume de clienți sau cifre fără acord explicit.",
    h1: "Studii de caz pentru fonduri europene",
    summary: "Această secțiune este pregătită pentru exemple reale care pot fi publicate doar cu acordul beneficiarilor. Nu sunt introduse rezultate, recenzii sau cifre comerciale care nu există în proiect.",
    audience: ["vizitatori care vor să înțeleagă cum arată un parcurs de proiect", "beneficiari care vor exemple de documente și decizii", "beneficiari care urmaresc exemple publicabile si lectii aplicate"],
    checks: ["acordul beneficiarului pentru publicare", "datele care pot fi anonimizate", "lecțiile utile fără divulgarea informațiilor confidențiale"],
    steps: ["documentează contextul proiectului", "elimină datele sensibile", "verifică acordul scris", "publică doar informații confirmate"],
    links: [related.caseStudies, related.consultanta, related.ghiduri, related.intrebari, related.contact],
    internalNote: "TODO intern: publicați studii de caz doar cu acordul explicit al clientului și fără date comerciale inventate.",
  },
  {
    slug: "intrebari-frecvente",
    category: "FAQ",
    title: "Întrebări Frecvente Fonduri Europene | Eligibilitate și Consultanță",
    description: "Răspunsuri la întrebări frecvente despre fonduri europene, finanțări nerambursabile, eligibilitate, documente, consultanță și pași de aplicare.",
    h1: "Întrebări frecvente despre fonduri europene",
    summary: "Răspunsurile sunt orientative și ajută la înțelegerea pașilor generali. Condițiile finale se verifică în ghidul solicitantului și în documentele apelului activ.",
    audience: ["antreprenori la prima finanțare", "IMM-uri care compară programe", "fermieri și beneficiari care vor să înțeleagă documentele minime"],
    checks: ["programul potrivit pentru solicitant", "documentele disponibile", "bugetul, contribuția proprie și termenele"],
    steps: ["citește răspunsurile de bază", "alege clusterul relevant", "verifică pagina programului", "trimite datele proiectului pentru evaluare"],
    links: [related.fonduri, related.consultanta, related.eligibilitate, related.ghiduri, related.contact],
  },
  {
    slug: "start-up-nation-2026-conditii",
    category: "Start-Up Nation",
    title: "Start-Up Nation 2026 Condiții | Cine poate aplica",
    description: "Condiții Start-Up Nation 2026: solicitant, cod CAEN, firmă, documente și verificări necesare înainte de pregătirea planului de afaceri.",
    h1: "Start-Up Nation 2026: condiții de verificat",
    summary: "Condițiile trebuie verificate înainte de cheltuieli sau promisiuni către furnizori. Programul poate cere reguli diferite pentru solicitant, firmă, cod CAEN și locuri de muncă.",
    audience: ["persoane care vor să înființeze o firmă", "antreprenori care pregătesc dosarul", "beneficiari care trebuie să confirme condițiile înainte de aplicare"],
    checks: ["vârsta sau categoria solicitantului, dacă ghidul o cere", "firma, capitalul social și codul CAEN", "obligațiile privind locurile de muncă și implementarea"],
    steps: ["verifică solicitantul", "alege codul CAEN", "testează investiția în buget", "pregătește documentele firmei"],
    links: [related.startup, ["/start-up-nation-2026", "Program Start-Up Nation 2026"], ["/start-up-nation-2026-cheltuieli-eligibile", "Cheltuieli eligibile"], ["/consultanta-start-up-nation", "Consultanță Start-Up Nation"]],
  },
  {
    slug: "start-up-nation-2026-cheltuieli-eligibile",
    category: "Start-Up Nation",
    title: "Start-Up Nation 2026 Cheltuieli Eligibile | Buget și Achiziții",
    description: "Ghid despre cheltuieli eligibile Start-Up Nation 2026: echipamente, software, servicii, buget, cofinanțare și greșeli de evitat.",
    h1: "Start-Up Nation 2026: cheltuieli eligibile",
    summary: "Cheltuielile eligibile trebuie să susțină activitatea firmei și să fie justificate în planul de afaceri. Lista exactă depinde de ghidul solicitantului activ.",
    audience: ["antreprenori care construiesc bugetul", "firme care compară oferte", "beneficiari care vor să evite cheltuieli greu de justificat"],
    checks: ["legătura dintre cheltuială și activitatea firmei", "plafoanele, procentul nerambursabil și contribuția proprie", "documentele de achiziție și ofertele"],
    steps: ["listează investițiile necesare", "separă eligibilul de neeligibil", "cere oferte comparabile", "verifică bugetul cu un consultant"],
    links: [related.startup, ["/start-up-nation-2026-plan-de-afaceri", "Plan de afaceri"], ["/start-up-nation-2026-idei-afaceri", "Idei de afaceri"], related.contact],
  },
  {
    slug: "start-up-nation-2026-idei-afaceri",
    category: "Start-Up Nation",
    title: "Start-Up Nation 2026 Idei de Afaceri | Cum alegi proiectul",
    description: "Idei de afaceri pentru Start-Up Nation 2026 și criterii de alegere: CAEN, buget, piață, echipamente, documente și fezabilitate.",
    h1: "Start-Up Nation 2026: idei de afaceri",
    summary: "O idee finanțabilă trebuie să fie realistă, autorizabilă și susținută de un buget coerent. Nu orice idee bună comercial este automat potrivită pentru grant.",
    audience: ["persoane care aleg între mai multe idei", "antreprenori care caută codul CAEN potrivit", "beneficiari care vor să evite proiectele greu de implementat"],
    checks: ["cererea reală din piață", "autorizațiile și locația", "echipamentele, furnizorii și calendarul de implementare"],
    steps: ["notează 2-3 idei posibile", "verifică autorizarea", "estimează bugetul", "alege varianta care poate fi justificată în plan"],
    links: [[ "/start-up-nation-2026-idei-afaceri-plan", "Articol idei și plan" ], related.startup, ["/start-up-nation-2026-conditii", "Condiții"], ["/consultanta-start-up-nation", "Consultanță"]],
  },
  {
    slug: "start-up-nation-2026-plan-de-afaceri",
    category: "Start-Up Nation",
    title: "Start-Up Nation 2026 Plan de Afaceri | Structură și Buget",
    description: "Plan de afaceri Start-Up Nation 2026: structură, buget, cod CAEN, investiții, documente și verificări înainte de depunere.",
    h1: "Start-Up Nation 2026: plan de afaceri",
    summary: "Planul de afaceri trebuie să explice clar ce face firma, cum va folosi investiția și de ce bugetul este justificat. Evită estimările fără legătură cu realitatea operațională.",
    audience: ["antreprenori care pregătesc documentația", "persoane care au deja o idee și vor un buget coerent", "firme noi care trebuie să explice fluxul de activitate"],
    checks: ["descrierea activității și piața", "bugetul și ofertele", "indicatorii, locurile de muncă și calendarul"],
    steps: ["scrie modelul de business", "corelează investițiile cu veniturile estimate", "pregătește documentele suport", "revizuiește riscurile de implementare"],
    links: [related.startup, ["/start-up-nation-2026-cheltuieli-eligibile", "Cheltuieli eligibile"], ["/consultanta-start-up-nation", "Consultanță Start-Up Nation"], related.contact],
  },
  {
    slug: "consultanta-start-up-nation",
    category: "Consultanță",
    title: "Consultanță Start-Up Nation | Verificare Eligibilitate și Dosar",
    description: "Consultanță Start-Up Nation pentru verificarea eligibilității, alegerea codului CAEN, buget, plan de afaceri și pregătirea documentelor.",
    h1: "Consultanță Start-Up Nation",
    summary: "Consultanța pentru Start-Up Nation ajută la verificarea ideii, structurarea bugetului și pregătirea dosarului fără promisiuni absolute de aprobare.",
    audience: ["viitori antreprenori care vor să aplice", "persoane care nu știu dacă ideea lor este potrivită", "firme noi care au nevoie de un plan de afaceri coerent"],
    checks: ["eligibilitatea solicitantului", "codul CAEN și documentele firmei", "bugetul, ofertele și contribuția proprie"],
    steps: ["transmiți datele proiectului", "verificăm eligibilitatea", "stabilim documentele lipsă", "pregătim structura dosarului"],
    links: [related.startup, ["/start-up-nation-2026-conditii", "Condiții"], ["/start-up-nation-2026-plan-de-afaceri", "Plan de afaceri"], related.contact],
  },
  {
    slug: "consultanta-afir",
    category: "Consultanță AFIR",
    title: "Consultanță AFIR | DR 12, DR 14, Ferme și Proiecte Agricole",
    description: "Consultanță AFIR pentru fermieri: verificare SO, eligibilitate, documente, buget, DR 12, DR 14 și pregătirea dosarului.",
    h1: "Consultanță AFIR",
    summary: "Consultanța AFIR începe cu verificarea exploatației și a investiției. Scopul este să fie clar dacă programul ales se potrivește fermei și documentelor disponibile.",
    audience: ["tineri fermieri", "ferme mici și ferme în dezvoltare", "beneficiari care pregătesc utilaje, construcții sau energie"],
    checks: ["SO, suprafețe, animale și forma juridică", "dreptul de folosință și documentele exploatației", "investiția, ofertele și punctajul"],
    steps: ["calculăm dimensiunea exploatației", "verificăm documentele", "alegem programul potrivit", "pregătim pașii pentru dosar"],
    links: [related.afir, ["/dr12-afir", "DR 12 AFIR"], ["/dr14", "DR 14 AFIR"], ["/fonduri-pentru-ferme", "Fonduri pentru ferme"], related.contact],
  },
  {
    slug: "fonduri-pentru-ferme",
    category: "Agricultură",
    title: "Fonduri pentru Ferme | AFIR, Investiții și Eligibilitate",
    description: "Fonduri pentru ferme: programe AFIR, eligibilitate, documente, investiții, utilaje, calcul SO și pași pentru pregătirea proiectului.",
    h1: "Fonduri pentru ferme",
    summary: "O fermă poate pregăti proiecte pentru instalare, modernizare, utilaje, energie sau dezvoltare, dar programul potrivit depinde de dimensiunea economică și documentele disponibile.",
    audience: ["ferme mici", "tineri fermieri", "exploatații care pregătesc investiții în utilaje sau infrastructură"],
    checks: ["dimensiunea economică", "documentele privind terenurile și animalele", "investiția propusă și calendarul de implementare"],
    steps: ["calculează SO", "alege programul potrivit", "pregătește documentele fermei", "verifică investiția și ofertele"],
    links: [related.afir, related.consultantaAfir, ["/fonduri-pentru-utilaje-agricole", "Utilaje agricole"], ["/calculator-soc", "Calculator SO"], related.contact],
  },
  {
    slug: "fonduri-pentru-utilaje-agricole",
    category: "Agricultură",
    title: "Fonduri pentru Utilaje Agricole | Eligibilitate și Buget",
    description: "Fonduri pentru utilaje agricole: cum verifici eligibilitatea, ofertele, capacitatea fermei, justificarea investiției și legătura cu programele AFIR.",
    h1: "Fonduri pentru utilaje agricole",
    summary: "Utilajele trebuie justificate prin dimensiunea și activitatea fermei. Un echipament prea mare, necorelat cu exploatația, poate crea riscuri de eligibilitate sau punctaj.",
    audience: ["fermieri care vor tractoare, echipamente sau tehnologii agricole", "ferme care compară oferte", "beneficiari care pregătesc un buget AFIR"],
    checks: ["capacitatea utilajului raportată la exploatație", "eligibilitatea cheltuielii în ghid", "ofertele, specificațiile și necesitatea investiției"],
    steps: ["descrie lucrările fermei", "alege echipamentele proporționale", "cere oferte comparabile", "verifică bugetul înainte de depunere"],
    links: [related.agricultura, related.afir, related.consultantaAfir, ["/fonduri-pentru-ferme", "Fonduri pentru ferme"], related.contact],
  },
  {
    slug: "granturi-digitalizare-imm",
    category: "Digitalizare",
    title: "Granturi Digitalizare IMM | Software, Automatizare și Securitate",
    description: "Granturi pentru digitalizarea IMM-urilor: software, ERP, CRM, automatizare, cloud, securitate cibernetică, documente și pași de pregătire.",
    h1: "Granturi pentru digitalizarea IMM-urilor",
    summary: "Granturile pentru digitalizare trebuie să arate cum investiția schimbă modul de lucru al firmei, nu doar că achiziționează echipamente sau licențe.",
    audience: ["IMM-uri care pregătesc ERP, CRM sau automatizare", "firme care vor securitate cibernetică sau cloud", "antreprenori care au nevoie de justificare tehnică"],
    checks: ["procesele digitalizate", "cheltuielile eligibile", "indicatorii și documentele tehnice"],
    steps: ["definește problema operațională", "alege soluțiile compatibile", "pregătește ofertele", "verifică indicatorii ceruți"],
    links: [related.digitalizare, related.pnrr, ["/digitalizare-imm", "Digitalizare IMM"], ["/consultanta-pnrr-digitalizare", "Consultanță PNRR"], related.contact],
  },
  {
    slug: "consultanta-pnrr-digitalizare",
    category: "Consultanță",
    title: "Consultanță PNRR Digitalizare | Eligibilitate și Dosar IMM",
    description: "Consultanță PNRR digitalizare pentru IMM-uri: verificare eligibilitate, cheltuieli, buget, documente, indicatori și pregătirea proiectului.",
    h1: "Consultanță PNRR digitalizare",
    summary: "Consultanța PNRR digitalizare ajută la transformarea unei liste de achiziții într-un proiect justificat prin procese, indicatori și rezultate măsurabile.",
    audience: ["IMM-uri care vor să aplice pe digitalizare", "firme cu investiții în software sau automatizare", "beneficiari care trebuie să clarifice indicatorii"],
    checks: ["eligibilitatea firmei", "cheltuielile și indicatorii", "ofertele și documentele tehnice"],
    steps: ["analizăm procesele firmei", "verificăm cheltuielile", "structurăm bugetul", "pregătim documentele pentru dosar"],
    links: [related.pnrr, related.digitalizare, ["/pnrr-digitalizare-imm-cheltuieli-eligibile", "Cheltuieli eligibile"], related.contact],
  },
  {
    slug: "finantari-panouri-fotovoltaice",
    category: "Energie",
    title: "Finanțări Panouri Fotovoltaice | Autoconsum și Energie",
    description: "Finanțări pentru panouri fotovoltaice: autoconsum, energie pentru ferme, instituții publice, Fondul de Modernizare și pași de pregătire.",
    h1: "Finanțări pentru panouri fotovoltaice",
    summary: "Proiectele fotovoltaice trebuie dimensionate după consum, locație, putere instalată, avize și condițiile programului. Finanțarea depinde de solicitant și de apelul activ.",
    audience: ["ferme și procesatori agroalimentari", "instituții publice", "firme interesate de autoconsum și eficiență energetică"],
    checks: ["consumul energetic și dimensionarea", "locația, avizele și soluția tehnică", "programul potrivit pentru tipul solicitantului"],
    steps: ["analizează consumul", "alege programul compatibil", "pregătește documentele tehnice", "verifică bugetul și termenele"],
    links: [["/fondul-de-modernizare", "Fondul de Modernizare"], ["/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum", "Energie și autoconsum"], ["/afir-autoconsum-agroalimentar", "AFIR Autoconsum Agroalimentar"], ["/autoconsum-public-fotovoltaice-institutii-publice", "Autoconsum instituții publice"], related.contact],
  },
  {
    slug: "cum-alegi-consultant-fonduri-europene",
    category: "Consultanță",
    title: "Cum alegi un Consultant pentru Fonduri Europene | Criterii utile",
    description: "Criterii pentru alegerea unui consultant de fonduri europene: experiență relevantă, transparență, documente, comunicare și evitarea promisiunilor nerealiste.",
    h1: "Cum alegi un consultant pentru fonduri europene",
    summary: "Un consultant bun nu promite aprobarea finanțării, ci clarifică eligibilitatea, riscurile, documentele și responsabilitățile înainte de depunere.",
    audience: ["antreprenori care caută consultanță pentru prima dată", "firme care au avut dosare respinse", "beneficiari care vor o colaborare clară"],
    checks: ["modul în care se verifică eligibilitatea", "transparența privind documentele și responsabilitățile", "evitarea promisiunilor absolute de aprobare"],
    steps: ["cere o evaluare inițială", "verifică ce include serviciul", "clarifică termenele și documentele", "păstrează deciziile importante în scris"],
    links: [related.consultanta, ["/firma-consultanta-fonduri-europene", "Firmă consultanță fonduri europene"], ["/cat-costa-consultanta-fonduri-europene", "Cost consultanță"], related.contact],
  },
  {
    slug: "cat-costa-consultanta-fonduri-europene",
    category: "Consultanță",
    title: "Cât Costă Consultanța pentru Fonduri Europene | Factori și Etape",
    description: "Explicații despre costul consultanței pentru fonduri europene: complexitatea proiectului, documente, buget, implementare și ce trebuie clarificat.",
    h1: "Cât costă consultanța pentru fonduri europene",
    summary: "Costul consultanței depinde de program, complexitatea proiectului, documentele necesare, valoarea investiției și nivelul de suport cerut la implementare.",
    audience: ["firme care compară oferte de consultanță", "antreprenori care vor să înțeleagă etapele serviciului", "beneficiari care pregătesc bugetul proiectului"],
    checks: ["ce include evaluarea inițială", "ce include pregătirea dosarului", "dacă implementarea și raportarea sunt incluse separat"],
    steps: ["descrie proiectul", "transmite datele firmei", "clarifică programul și documentele", "solicită o ofertă adaptată proiectului"],
    links: [related.consultanta, ["/cum-alegi-consultant-fonduri-europene", "Cum alegi consultantul"], ["/eligibilitate-fonduri-europene", "Eligibilitate"], related.contact],
  },
  {
    slug: "firma-consultanta-fonduri-europene",
    category: "Consultanță",
    title: "Firmă Consultanță Fonduri Europene | Servicii pentru IMM-uri",
    description: "Ce servicii poate oferi o firmă de consultanță pentru fonduri europene: eligibilitate, dosar, buget, plan de afaceri, depunere și implementare.",
    h1: "Firmă de consultanță pentru fonduri europene",
    summary: "O firmă de consultanță poate sprijini proiectul de la analiza inițială până la depunere și implementare, cu responsabilități clare pentru fiecare etapă.",
    audience: ["IMM-uri care pregătesc investiții", "fermieri și beneficiari AFIR", "antreprenori care caută finanțări nerambursabile"],
    checks: ["programul potrivit", "documentele firmei și investiției", "rolurile consultantului și beneficiarului"],
    steps: ["solicită evaluare", "primește lista de documente", "pregătește dosarul", "urmărește implementarea și raportarea"],
    links: [related.consultanta, related.imm, related.afir, related.pnrr, related.contact],
  },
  {
    slug: "consultant-fonduri-europene-imm",
    category: "IMM",
    title: "Consultant Fonduri Europene IMM | Verificare Proiect și Dosar",
    description: "Consultant fonduri europene pentru IMM-uri: verificare eligibilitate, program potrivit, buget, documente, plan de afaceri și suport la depunere.",
    h1: "Consultant fonduri europene pentru IMM-uri",
    summary: "Pentru IMM-uri, consultanța trebuie să lege investiția de obiectivele firmei și să verifice dacă programul ales permite cheltuielile propuse.",
    audience: ["microîntreprinderi", "întreprinderi mici și mijlocii", "firme care vor să compare programe de finanțare"],
    checks: ["încadrarea IMM", "codul CAEN și istoricul financiar", "bugetul, contribuția proprie și documentele"],
    steps: ["transmite datele firmei", "descrie investiția", "verificăm programele potrivite", "pregătim lista de documente"],
    links: [related.nordest, related.imm, related.consultanta, ["/por-adr-nord-est", "POR ADR Nord-Est"], related.digitalizare, related.contact],
  },
  {
    slug: "greseli-fonduri-europene",
    category: "Greșeli frecvente",
    title: "Greșeli Frecvente la Fonduri Europene | Ce să verifici înainte",
    description: "Greșeli frecvente la fonduri europene: program ales greșit, documente lipsă, cheltuieli neeligibile, buget nerealist și depunere pe grabă.",
    h1: "Greșeli frecvente la fonduri europene",
    summary: "Multe probleme apar înainte de depunere: program nepotrivit, documente lipsă, buget nejustificat sau cheltuieli care nu respectă ghidul solicitantului.",
    audience: ["beneficiari la prima aplicare", "firme care au fost respinse anterior", "echipe care pregătesc documente sub presiunea termenului"],
    checks: ["eligibilitatea solicitantului", "cheltuielile și bugetul", "documentele, avizele și termenele"],
    steps: ["verifică programul înainte de buget", "nu comanda echipamente înainte de eligibilitate", "actualizează documentele", "cere o revizuire independentă"],
    links: [related.eligibilitate, related.ghiduri, related.consultanta, ["/cum-alegi-programul-potrivit-fonduri-europene-2026", "Cum alegi programul"], related.contact],
  },
];

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function canonical(slug) {
  const path = normalizeCanonicalPath(slug);
  return canonicalUrl(CANONICAL_ALIASES.get(path) || path);
}

function metadataForPage(page) {
  return buildPageMetadata({
    title: page.title,
    description: page.description,
    pathname: page.slug,
    fallbackTitle: page.h1 || page.slug,
    fallbackDescription: page.summary || page.h1
  });
}

function breadcrumbItemsForPage(page) {
  return breadcrumbItemsForPath(`/${page.slug}`, page.h1 || page.title);
}

function renderBreadcrumb(items) {
  return `<div class="breadcrumb">${items.map((item, index) => {
    const label = esc(item.name);
    if (index === items.length - 1) return label;
    return `<a href="${cleanHref(item.item)}">${label}</a>`;
  }).join(" / ")}</div>`;
}

function faqFor(page) {
  return [
    {
      q: `Este suficienta pagina ${page.h1} pentru a decide aplicarea?`,
      a: `Nu. Pagina este orientativa. Decizia trebuie luata dupa verificarea ghidului solicitantului activ si a documentelor concrete ale solicitantului.`,
    },
    {
      q: `Pot solicita o verificare de eligibilitate pentru ${page.h1}?`,
      a: `Da. Poti trimite datele proiectului prin pagina de contact, iar analiza initiala urmareste solicitantul, investitia, documentele si programul potrivit.`,
    },
    {
      q: `Ce fac daca programul relevant pentru ${page.h1} nu este deschis inca?`,
      a: `Poti pregati din timp documentele de baza, bugetul, ofertele si verificarile interne, astfel incat sa nu incepi dosarul pe graba cand apelul se lanseaza.`,
    },
  ];
}

function list(items) {
  return items.map((item) => `<li>${esc(item)}</li>`).join("\n");
}

function links(items) {
  return (items || []).map((item) => {
    const href = typeof item === "string" ? item : (Array.isArray(item) ? item[0] : item.href);
    const label = typeof item === "string"
      ? cleanHref(href).replace(/^\/+/, "").replace(/-/g, " ")
      : (Array.isArray(item) ? (item[1] || cleanHref(href).replace(/^\/+/, "").replace(/-/g, " ")) : (item.label || item.name || item.title || cleanHref(href).replace(/^\/+/, "").replace(/-/g, " ")));
    return `<a href="${cleanHref(href)}">${esc(label)}</a>`;
  }).join("\n");
}

function schema(page, faq, metadata = metadataForPage(page)) {
  return jsonLdGraph([
    organizationSchema(),
    websiteSchema(),
    webPageSchema({
      url: metadata.canonicalUrl,
      name: metadata.title,
      description: metadata.description,
      about: page.h1,
      dateModified: TODAY
    }),
    breadcrumbSchema(breadcrumbItemsForPage(page)),
    faqPageSchema(faq.map((item) => ({ question: item.q, answer: item.a })), { minItems: 2 })
  ]);
}

function pageHtml(page) {
  const faq = faqFor(page);
  const family = designFamilyFor(page);
  const [, heroIcon] = designProfileFor(page);
  const metadata = metadataForPage(page);
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(metadata.title)}</title>
  <meta name="description" content="${esc(metadata.description)}" />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="${metadata.canonicalUrl}" />
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
  <meta property="og:title" content="${esc(metadata.title)}" />
  <meta property="og:description" content="${esc(metadata.description)}" />
  <meta property="og:url" content="${metadata.ogUrl}" />
  <meta property="og:type" content="website" />
  <meta property="og:image" content="${SITE}/og-image.jpg" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="stylesheet" href="/assets/seo-hub.css" />
  <script type="application/ld+json">${schema(page, faq, metadata)}</script>
${CLARITY_TRACKING_CODE}
</head>
<body class="page-family-${esc(family)}">
  ${page.internalNote ? `<!-- ${page.internalNote} -->\n  ` : ""}<nav class="navbar" aria-label="Navigare principală">
    ${brandLogoLink()}
    <div class="navbar-links">
      <a href="${cleanHref("/fonduri-europene")}">Fonduri europene</a>
      <a href="${cleanHref("/ghiduri")}">Ghiduri</a>
      <a href="${cleanHref("/blog")}">Blog</a>
      <a class="nav-cta btn-primary" href="${cleanHref("/contact")}">Evaluare gratuită</a>
    </div>
  </nav>
  ${renderBreadcrumb(breadcrumbItemsForPage(page))}
  <header class="hero hero--${esc(family)}" data-design-family="${esc(family)}">
    <span class="hero-icon" aria-hidden="true"><i class="${esc(heroIcon)}"></i></span>
    <span class="eyebrow design-badge design-badge--${esc(family)}">${esc(designProfileFor(page)[0])}</span>
    <h1>${esc(page.h1)}</h1>
    <p>${esc(page.summary)}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="${cleanHref("/contact")}">Solicită evaluare gratuită</a>
      <a class="btn btn-secondary" href="${cleanHref("/consultanta-fonduri-europene")}">Vezi serviciile de consultanță</a>
    </div>
    ${renderHubHeroSummary(page)}
  </header>
  <main class="container">
    <article class="panel">
      ${renderHubDesignCards(page)}
      <p class="intro">${esc(page.summary)}</p>
      <h2>Pe scurt</h2>
      <p>Pagina explică ce trebuie verificat înainte de pregătirea dosarului și trimite către resursele conexe deja publicate pe Atelier de Consultanță. Conținutul este informativ și nu înlocuiește ghidul oficial al programului de finanțare.</p>
      <div class="grid">
        <section class="mini-card">
          <h3>Cui se adresează</h3>
          <ul>${list(page.audience)}</ul>
        </section>
        <section class="mini-card">
          <h3>Ce trebuie verificat</h3>
          <ul>${list(page.checks)}</ul>
        </section>
      </div>
      <h2>Pași recomandați</h2>
      <ol>${list(page.steps)}</ol>
      <div class="note">Informațiile sunt orientative. Pentru fiecare apel trebuie verificat ghidul solicitantului, anexele, grila de punctaj și forma finală publicată de autoritatea finanțatoare.</div>
      <h2>Resurse conexe</h2>
      <div class="related-links">${links(standardInternalLinksForPath(`/${page.slug}`, page.links))}</div>
      <h2>Întrebări frecvente</h2>
      ${faq.map((item) => `<section class="faq-item"><h3>${esc(item.q)}</h3><p>${esc(item.a)}</p></section>`).join("\n      ")}
    </article>
    <section class="cta-box">
      <h2>Cum poate ajuta Atelier de Consultanță</h2>
      <p>Putem verifica eligibilitatea proiectului, documentele disponibile, bugetul estimat și programul potrivit, fără promisiuni absolute privind aprobarea finanțării.</p>
      <div class="cta-actions">
        <a class="btn btn-primary" href="${cleanHref("/contact")}">Verifică eligibilitatea proiectului</a>
        <a class="btn btn-secondary" href="${cleanHref("/consultanta-fonduri-europene")}">Consultanță fonduri europene</a>
      </div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER - Atelier de Consultanță · <a href="${cleanHref("/fonduri-europene")}">Fonduri europene</a> · <a href="${cleanHref("/contact")}">Contact</a></footer>
</body>
</html>
`;
}

const pagesToGenerate = pages.filter((page) => !REDIRECTED_PAGE_SLUGS.has(page.slug));

for (const page of pagesToGenerate) {
  const dir = path.join(ROOT, page.slug);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "index.html"), pageHtml(page), "utf8");
}

const existing = [
  ["/", "1.0"],
  ["/consultanta-fonduri-europene", "0.9"],
  ["/verificare-eligibilitate-fonduri-europene", "0.8"],
  ["/fonduri-europene-nerambursabile-2026", "0.9"],
  ["/dr12-afir", "0.9"],
  ["/dr14", "0.9"],
  ["/dr-14-afir-conditii-eligibilitate-greseli-frecvente", "0.7"],
  ["/start-up-nation-2026", "0.9"],
  ["/femeia-antreprenor-2026", "0.9"],
  ["/digitalizare-imm", "0.9"],
  ["/digitalizare-imm-pnrr", "0.8"],
  ["/fondul-de-modernizare", "0.8"],
  ["/afir-autoconsum-agroalimentar", "0.8"],
  ["/autoconsum-public-fotovoltaice-institutii-publice", "0.8"],
  ["/por-adr-nord-est", "0.8"],
  ["/fonduri-europene-nord-est", "0.8"],
  ["/pro-infra", "0.8"],
  ["/calculator-soc", "0.8"],
  ["/contact", "0.8"],
  ["/blog", "0.8"],
  ["/cum-alegi-programul-potrivit-fonduri-europene-2026", "0.7"],
  ["/acte-necesare-fonduri-europene-nerambursabile", "0.7"],
  ["/dr-12-afir-instalarea-tinerilor-fermieri", "0.7"],
  ["/cod-caen-start-up-nation-2026", "0.7"],
  ["/consultanta-start-up-nation-2026", "0.8"],
  ["/start-up-nation-2026-idei-afaceri-plan", "0.7"],
  ["/femeia-antreprenor-2026-conditii-idei-afaceri", "0.7"],
  ["/pnrr-digitalizare-imm-cheltuieli-eligibile", "0.7"],
  ["/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum", "0.7"],
  ["/blog-afir-fotovoltaice-ferme-2026", "0.5"],
  ["/gdpr", "0.3"],
  ["/politica-de-confidentialitate", "0.3"],
  ["/termeni-si-conditii", "0.3"],
];

const hubUrls = pagesToGenerate.map((page) => [`/${page.slug}`, page.slug.includes("consultanta") || page.slug.includes("fonduri-europene") || ["pnrr", "afir", "start-up-nation"].includes(page.slug) ? "0.8" : "0.7"]);
const seen = new Set();
const sitemapUrls = [...existing, ...hubUrls].filter(([url]) => {
  const cleanUrl = cleanPath(url);
  if (seen.has(cleanUrl)) return false;
  seen.add(cleanUrl);
  return true;
}).map(([url, priority]) => [cleanPath(url), priority]);

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemapUrls.map(([url, priority]) => `  <url>
    <loc>${SITE}${url}</loc>
    <lastmod>${TODAY}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>${priority}</priority>
  </url>`).join("\n")}
</urlset>
`;

fs.writeFileSync(path.join(ROOT, "sitemap.xml"), sitemap, "utf8");

const adminPath = path.join(ROOT, "admin", "index.html");
if (fs.existsSync(adminPath)) {
  const adminHtml = fs.readFileSync(adminPath, "utf8");
  const adminBlock = `const SITEMAP_STATIC_URLS = [
${sitemapUrls.map(([url, priority]) => `    ["${url}", "${priority}"]`).join(",\n")}
  ];`;
  const nextAdminHtml = adminHtml.replace(/const SITEMAP_STATIC_URLS = \[[\s\S]*?\n  \];/, adminBlock);
  if (nextAdminHtml !== adminHtml) {
    fs.writeFileSync(adminPath, nextAdminHtml, "utf8");
  }
}

console.log(`Generated ${pages.length} SEO hub pages and sitemap.xml with ${sitemapUrls.length} URLs.`);
