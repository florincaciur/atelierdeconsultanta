import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { PHRASE_RULES, inspectPage, loadExceptions } = require("../tools/audit-generative-language.js");
const { normalizeRomanianCopy } = require("../tools/normalize-copy-ro.js");
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const requiredRules = [
  "Într-o lume în continuă schimbare",
  "Este important de menționat",
  "Joacă un rol crucial",
  "Nu doar..., ci și...",
  "Descoperă",
  "Ghid complet",
  "Tot ce trebuie să știi",
  "Maximizează șansele",
  "Navighează cu succes",
  "Soluții personalizate",
  "Abordare holistică",
  "Proces complex",
  "Oportunitate unică",
  "Transformă-ți visul în realitate"
];

const configuredLabels = new Set(PHRASE_RULES.map((item) => item.label));
for (const label of requiredRules) {
  assert(configuredLabels.has(label), `Lipsește regula editorială: ${label}`);
}

assert.equal(normalizeRomanianCopy("Pot verifica documentele."), "Pot verifica documentele.");
assert.equal(normalizeRomanianCopy("Nu completa acest câmp"), "Nu completa acest câmp");
assert.equal(normalizeRomanianCopy("documentație completa"), "documentație completă");
assert.equal(normalizeRomanianCopy("Pot schimba concluzia."), "Pot schimba concluzia.");
assert.equal(normalizeRomanianCopy("Regulile se schimba."), "Regulile se schimbă.");
assert.equal(normalizeRomanianCopy("Aceasta este pagina corectă."), "Aceasta este pagina corectă.");
assert.equal(normalizeRomanianCopy("Această este pagina corectă."), "Aceasta este pagina corectă.");
assert.equal(normalizeRomanianCopy("Această pagină este corectă."), "Această pagină este corectă.");
assert.equal(normalizeRomanianCopy("Pot există apeluri diferite."), "Pot exista apeluri diferite.");
assert.equal(normalizeRomanianCopy("Adresă sediului nu este suficientă."), "Adresa sediului nu este suficientă.");
assert.equal(normalizeRomanianCopy("Adresă de e-mail"), "Adresă de e-mail");
assert.equal(normalizeRomanianCopy("Pagină evită valori speculative."), "Pagina evită valori speculative.");
assert.equal(normalizeRomanianCopy("Pagină această rămâne publică."), "Pagina aceasta rămâne publică.");
assert.equal(normalizeRomanianCopy("Consultanță poate reduce riscurile."), "Consultanța poate reduce riscurile.");
assert.equal(normalizeRomanianCopy("Atelier de Consultanță poate sprijini proiectul."), "Atelier de Consultanță poate sprijini proiectul.");
assert.equal(normalizeRomanianCopy("Se pot adaugă documente."), "Se pot adăuga documente.");
assert.equal(normalizeRomanianCopy("Evaluatorul poate corectă eroarea."), "Evaluatorul poate corecta eroarea.");
assert.equal(normalizeRomanianCopy("Poți aplică după verificare."), "Poți aplica după verificare.");
assert.equal(normalizeRomanianCopy("Poți compară ofertele."), "Poți compara ofertele.");
assert.equal(normalizeRomanianCopy("Pentru a evită erorile."), "Pentru a evita erorile.");
assert.equal(normalizeRomanianCopy("Înainte de a verifică dosarul."), "Înainte de a verifica dosarul.");
assert.equal(normalizeRomanianCopy("Pentru a arată diferența."), "Pentru a arăta diferența.");
assert.equal(normalizeRomanianCopy("Poate lăsă câmpul gol."), "Poate lăsa câmpul gol.");
assert.equal(normalizeRomanianCopy("Poți solicită clarificări."), "Poți solicita clarificări.");
assert.equal(normalizeRomanianCopy("Aceasta este pagină aplicata."), "Aceasta este pagina aplicată.");
assert.equal(normalizeRomanianCopy("Folosește pagină dedicata."), "Folosește pagina dedicată.");
assert.equal(normalizeRomanianCopy("Pagină MIPE publică ghidul."), "Pagina MIPE publică ghidul.");
assert.equal(normalizeRomanianCopy("Pagină a fost revizuită."), "Pagina a fost revizuită.");
assert.equal(normalizeRomanianCopy("Pentru buget consulta pagină de cheltuieli."), "Pentru buget consultă pagina de cheltuieli.");
assert.equal(normalizeRomanianCopy("O sesiune noua poate avea intensitate maxima."), "O sesiune nouă poate avea intensitate maximă.");
assert.equal(normalizeRomanianCopy("Locurile de munca și obligatiile."), "Locurile de muncă și obligațiile.");
assert.equal(normalizeRomanianCopy("GAL-ul acopera localitatea."), "GAL-ul acoperă localitatea.");

for (const rule of PHRASE_RULES) {
  const synthetic = `<!doctype html><html><head><title>Test</title></head><body><main><p>${rule.label === "Nu doar..., ci și..." ? "Nu doar verificăm actele, ci și analizăm bugetul." : rule.label}</p></main></body></html>`;
  const result = inspectPage("/__test-editorial", "__test-editorial.html", synthetic);
  assert(
    result.findings.some((finding) => finding.category === rule.category),
    `Regula nu detectează exemplul propriu: ${rule.label}`
  );
}

const exceptions = loadExceptions();
for (const exception of exceptions) {
  assert(["official_name", "verbatim_quote"].includes(exception.kind), `Tip de excepție nepermis: ${exception.kind}`);
  for (const field of ["route", "category", "fragment", "reason", "source"]) {
    assert(String(exception[field] || "").trim(), `Excepție fără documentare în câmpul ${field}`);
  }
}

const siteCheck = spawnSync(process.execPath, ["tools/audit-generative-language.js", "--check-high", "--no-report"], {
  cwd: ROOT,
  encoding: "utf8"
});
assert.equal(siteCheck.status, 0, `${siteCheck.stdout}\n${siteCheck.stderr}`.trim());

console.log(`Generative language checks passed (${PHRASE_RULES.length} reguli, ${exceptions.length} excepții documentate).`);
