const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";

const fallbacks = [
  ["fonduri-europene-herambursabile-2026.html", "/fonduri-europene-nerambursabile-2026/"],
  ["fonduri-europene-herambursabile-2026/index.html", "/fonduri-europene-nerambursabile-2026/"],
  ["fonduri-europene-nerambursabile-2026.html", "/fonduri-europene-nerambursabile-2026/"],
  ["digitalizare-imm-pnrr.html", "/digitalizare-imm-pnrr/"],
  ["fondul-de-modernizare.html", "/fondul-de-modernizare/"],
  ["fonduri-europene.html", "/fonduri-europene/"],
  ["fonduri-nerambursabile.html", "/fonduri-nerambursabile/"],
  ["pnrr.html", "/pnrr/"],
  ["afir.html", "/afir/"],
  ["start-up-nation.html", "/start-up-nation/"],
  ["fonduri-europene-imm.html", "/fonduri-europene-imm/"],
  ["fonduri-europene-agricultura.html", "/fonduri-europene-agricultura/"],
  ["fonduri-europene-digitalizare.html", "/fonduri-europene-digitalizare/"],
  ["fonduri-europene-femei-antreprenor.html", "/fonduri-europene-femei-antreprenor/"],
  ["calendar-fonduri-europene.html", "/calendar-fonduri-europene/"],
  ["eligibilitate-fonduri-europene.html", "/eligibilitate-fonduri-europene/"],
  ["ghiduri.html", "/ghiduri/"],
  ["studii-de-caz.html", "/studii-de-caz/"],
  ["intrebari-frecvente.html", "/intrebari-frecvente/"],
  ["start-up-nation-2026-conditii.html", "/start-up-nation-2026-conditii/"],
  ["start-up-nation-2026-cheltuieli-eligibile.html", "/start-up-nation-2026-cheltuieli-eligibile/"],
  ["start-up-nation-2026-idei-afaceri.html", "/start-up-nation-2026-idei-afaceri/"],
  ["start-up-nation-2026-plan-de-afaceri.html", "/start-up-nation-2026-plan-de-afaceri/"],
  ["consultanta-start-up-nation.html", "/consultanta-start-up-nation/"],
  ["consultanta-afir.html", "/consultanta-afir/"],
  ["fonduri-pentru-ferme.html", "/fonduri-pentru-ferme/"],
  ["fonduri-pentru-utilaje-agricole.html", "/fonduri-pentru-utilaje-agricole/"],
  ["granturi-digitalizare-imm.html", "/granturi-digitalizare-imm/"],
  ["consultanta-pnrr-digitalizare.html", "/consultanta-pnrr-digitalizare/"],
  ["finantari-panouri-fotovoltaice.html", "/finantari-panouri-fotovoltaice/"],
  ["cum-alegi-consultant-fonduri-europene.html", "/cum-alegi-consultant-fonduri-europene/"],
  ["cat-costa-consultanta-fonduri-europene.html", "/cat-costa-consultanta-fonduri-europene/"],
  ["firma-consultanta-fonduri-europene.html", "/firma-consultanta-fonduri-europene/"],
  ["consultant-fonduri-europene-imm.html", "/consultant-fonduri-europene-imm/"],
  ["greseli-fonduri-europene.html", "/greseli-fonduri-europene/"],
];

function titleFor(target) {
  return target.replace(/^\/|\/$/g, "").replace(/-/g, " ") || "pagina principala";
}

function html(target) {
  const canonical = `${SITE}${target}`;
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Redirectionare | ${titleFor(target)}</title>
  <meta name="robots" content="noindex, follow" />
  <link rel="canonical" href="${canonical}" />
  <meta http-equiv="refresh" content="0; url=${target}" />
  <script>window.location.replace('${target}');</script>
</head>
<body>
  <p>Pagina canonică este disponibilă la <a href="${target}">${canonical}</a>.</p>
</body>
</html>
`;
}

for (const [file, target] of fallbacks) {
  const fullPath = path.join(ROOT, file);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, html(target), "utf8");
}

console.log(`Generated ${fallbacks.length} redirect fallback pages.`);
