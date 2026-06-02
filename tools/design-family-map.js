"use strict";

const DESIGN_FAMILY_BY_SLUG = Object.freeze({
  "": "home",
  "apeluri-gal": "gal",
  "consultanta-fonduri-europene": "service",
  "digitalizare-imm": "digital",
  "dr12-afir": "afir",
  "dr14": "afir",
  "fonduri-europene": "cluster",
  "start-up-nation-2026": "startup",
  "blog": "editorial",
  "despre-faber": "generic",
  "glosar-fonduri-europene": "editorial",
  "metodologie-verificare-eligibilitate": "service",
  "studii-de-caz-fonduri-europene": "trust",
  "surse-oficiale-fonduri-europene": "cluster",
  "acte-necesare-fonduri-europene-nerambursabile": "editorial",
  "afir": "afir",
  "afir-autoconsum-agroalimentar": "afir",
  "autoconsum-public-fotovoltaice-institutii-publice": "energy",
  "blog-afir-fotovoltaice-ferme-2026": "afir",
  "calculator-soc": "tool",
  "calendar-fonduri-europene": "editorial",
  "cand-merita-consultant-fonduri-europene": "editorial",
  "cat-costa-consultanta-fonduri-europene": "editorial",
  "cat-costa-consultanta-fonduri-europene-ghid": "editorial",
  "ce-acte-sunt-necesare-fonduri-europene": "editorial",
  "cheltuieli-eligibile-digitalizare-imm": "digital",
  "cod-caen-start-up-nation-2026": "caen",
  "consultant-fonduri-europene-imm": "service",
  "consultanta-afir": "afir",
  "consultanta-pnrr-digitalizare": "digital",
  "consultanta-start-up-nation-2026": "startup",
  "contact": "contact",
  "cum-alegi-consultant-fonduri-europene": "editorial",
  "cum-alegi-programul-potrivit-fonduri-europene-2026": "editorial",
  "cum-se-calculeaza-cofinantarea-fonduri-europene": "editorial",
  "cum-se-verifica-eligibilitatea-fonduri-europene": "editorial",
  "digitalizare-imm-erp-crm-cloud": "digital",
  "digitalizare-imm-pnrr": "digital",
  "dr-12-afir-instalarea-tinerilor-fermieri": "afir",
  "dr-14-afir-conditii-eligibilitate-greseli-frecvente": "afir",
  "dr12-vs-dr14": "afir",
  "dr14-afir-ferme-mici": "afir",
  "e-move": "energy",
  "eligibilitate-fonduri-europene": "service",
  "femeia-antreprenor-2026": "startup",
  "femeia-antreprenor-2026-conditii-idei-afaceri": "startup",
  "finantari-panouri-fotovoltaice": "energy",
  "firma-consultanta-fonduri-europene": "service",
  "fondul-de-modernizare": "energy",
  "fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum": "energy",
  "fondul-modernizare-energie-regenerabila-2026": "energy",
  "fonduri-europene-agricultura": "cluster",
  "fonduri-europene-digitalizare": "digital",
  "fonduri-europene-femei-antreprenor": "startup",
  "fonduri-europene-imm": "cluster",
  "fonduri-europene-nerambursabile-2026": "cluster",
  "fonduri-europene-nord-est": "cluster",
  "fonduri-nerambursabile": "cluster",
  "fonduri-pentru-ferme": "afir",
  "fonduri-pentru-utilaje-agricole": "afir",
  "gal-afir": "gal",
  "gdpr": "legal",
  "ghiduri": "editorial",
  "granturi-digitalizare-imm": "digital",
  "greseli-fonduri-europene": "editorial",
  "idei-afaceri-fonduri-europene": "editorial",
  "instrumente": "tool",
  "intrebari-frecvente": "editorial",
  "investitii-modernizarea-microintreprinderilor-apel-2": "generic",
  "pnrr": "digital",
  "pnrr-digitalizare-imm-cheltuieli-eligibile": "digital",
  "politica-de-confidentialitate": "legal",
  "por-adr-nord-est": "generic",
  "portofoliu": "trust",
  "pro-infra": "energy",
  "resurse": "editorial",
  "start-up-nation-2026-cheltuieli-eligibile": "startup",
  "start-up-nation-2026-conditii": "startup",
  "start-up-nation-2026-idei-afaceri": "startup",
  "start-up-nation-2026-plan-de-afaceri": "startup",
  "studii-de-caz": "trust",
  "termeni-si-conditii": "legal",
  "testimoniale": "trust",
  "verificare-eligibilitate-fonduri-europene": "service",
  "webinarii": "generic",
  "fonduri-europene-caen/0111-culturi-cereale": "caen",
  "fonduri-europene-caen/4321-instalatii-electrice": "caen",
  "fonduri-europene-caen/5610-restaurante": "caen",
  "fonduri-europene-caen/6201-dezvoltare-software": "caen"
});

function normalizeDesignSlug(value = "") {
  return String(value)
    .trim()
    .replace(/^https?:\/\/atelierdeconsultanta\.ro\/?/i, "")
    .replace(/^\/+|\/+$/g, "")
    .replace(/\/index\.html$/i, "")
    .replace(/\.html$/i, "")
    .toLowerCase();
}

function designFamilyForSlug(value = "") {
  return DESIGN_FAMILY_BY_SLUG[normalizeDesignSlug(value)];
}

module.exports = {
  DESIGN_FAMILY_BY_SLUG,
  designFamilyForSlug,
  normalizeDesignSlug
};
