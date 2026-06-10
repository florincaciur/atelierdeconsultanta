const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const {
  SITE,
  canonicalUrl,
  normalizeCanonicalPath
} = require("./schema-helpers");
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

function cleanTarget(target) {
  return normalizeCanonicalPath(target);
}

const fallbacks = [
  ["afir.html", "/afir"],
  ["blog.html", "/blog"],
  ["calendar-fonduri-europene.html", "/calendar-fonduri-europene"],
  ["cat-costa-consultanta-fonduri-europene.html", "/cat-costa-consultanta-fonduri-europene"],
  ["consultant-fonduri-europene-imm.html", "/consultant-fonduri-europene-imm"],
  ["consultanta-afir.html", "/consultanta-afir"],
  ["consultanta-fonduri-europene.html", "/consultanta-fonduri-europene"],
  ["consultanta-pnrr-digitalizare.html", "/consultanta-pnrr-digitalizare"],
  ["consultanta-start-up-nation.html", "/consultanta-start-up-nation-2026"],
  ["consultanta-start-up-nation/index.html", "/consultanta-start-up-nation-2026"],
  ["contact.html", "/contact"],
  ["cum-alegi-consultant-fonduri-europene.html", "/cum-alegi-consultant-fonduri-europene"],
  ["digitalizare-imm-pnrr.html", "/digitalizare-imm-pnrr"],
  ["eligibilitate-fonduri-europene.html", "/eligibilitate-fonduri-europene"],
  ["femeia-antreprenor-2026.html", "/femeia-antreprenor-2026"],
  ["fonduri-europene-agricultura.html", "/fonduri-europene-agricultura"],
  ["fonduri-europene-digitalizare.html", "/fonduri-europene-digitalizare"],
  ["fonduri-europene-femei-antreprenor.html", "/fonduri-europene-femei-antreprenor"],
  ["fonduri-europene-herambursabile-2026.html", "/fonduri-europene-nerambursabile-2026"],
  ["fonduri-europene-herambursabile-2026/index.html", "/fonduri-europene-nerambursabile-2026"],
  ["fonduri-europene.html", "/fonduri-europene"],
  ["fonduri-nerambursabile.html", "/fonduri-europene-nerambursabile-2026"],
  ["fonduri-pentru-ferme.html", "/fonduri-pentru-ferme"],
  ["fonduri-pentru-utilaje-agricole.html", "/fonduri-pentru-utilaje-agricole"],
  ["ghiduri.html", "/ghiduri"],
  ["granturi-digitalizare-imm.html", "/granturi-digitalizare-imm"],
  ["greseli-fonduri-europene.html", "/greseli-fonduri-europene"],
  ["intrebari-frecvente.html", "/intrebari-frecvente"],
  ["pnrr.html", "/pnrr"],
  ["pnrr-digitalizare-imm.html", "/digitalizare-imm-pnrr"],
  ["pnrr-digitalizare-imm/index.html", "/digitalizare-imm-pnrr"],
  ["por-adr-nord-est.html", "/por-adr-nord-est"],
  ["pro-infra.html", "/pro-infra"],
  ["studii-de-caz.html", "/studii-de-caz"],
  ["start-up-nation-2026-cheltuieli-eligibile.html", "/start-up-nation-2026-cheltuieli-eligibile"],
  ["start-up-nation-2026-conditii.html", "/start-up-nation-2026-conditii"],
  ["start-up-nation-2026-idei-afaceri.html", "/start-up-nation-2026-idei-afaceri"],
  ["start-up-nation-2026-plan-de-afaceri.html", "/start-up-nation-2026-plan-de-afaceri"],
  ["start-up-nation-2026.html", "/start-up-nation-2026"],
  ["autoconsum-publici.html", "/autoconsum-public-fotovoltaice-institutii-publice"],
  ["start-up-nation.html", "/start-up-nation-2026"],
  ["start-up-nation-2026-idei-afaceri-plan.html", "/start-up-nation-2026-idei-afaceri"],
  ["testimoniale.html", "/testimoniale"],
];

function titleFor(target) {
  return target.replace(/^\/|\/$/g, "").replace(/-/g, " ") || "pagina principala";
}

function html(target) {
  target = cleanTarget(target);
  const canonical = canonicalUrl(target);
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
${CLARITY_TRACKING_CODE}
</head>
<body>
  <main style="font-family: Arial, sans-serif; max-width: 720px; margin: 12vh auto; padding: 32px; line-height: 1.6; color: #1a2540;">
    <h1>Esti redirectionat catre o noua adresa</h1>
    <p>Pagina veche a fost mutata. Daca redirectionarea nu porneste automat, deschide <a href="${target}">${target}</a>.</p>
  </main>
  <script>window.location.replace('${target}');</script>
</body>
</html>
`;
}

function targetExists(target) {
  const clean = cleanTarget(target);
  if (clean === "/") return true;
  return fs.existsSync(path.join(ROOT, clean.slice(1), "index.html"));
}

for (const [file, target] of fallbacks) {
  if (!targetExists(target)) {
    console.warn(`Skipping ${file}: target ${target} has no index.html yet.`);
    continue;
  }
  const fullPath = path.join(ROOT, file);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, html(target), "utf8");
}

console.log(`Generated ${fallbacks.length} redirect fallback pages.`);
