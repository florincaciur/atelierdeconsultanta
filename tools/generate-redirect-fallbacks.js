const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

function cleanTarget(target) {
  if (!target || target === "/") return "/";
  return target.replace(/\.html$/i, "").replace(/\/+$/g, "");
}

const fallbacks = [
  ["fonduri-europene-herambursabile-2026.html", "/fonduri-europene-nerambursabile-2026"],
  ["fonduri-europene-herambursabile-2026/index.html", "/fonduri-europene-nerambursabile-2026"],
  ["autoconsum-publici.html", "/autoconsum-public-fotovoltaice-institutii-publice"],
  ["start-up-nation.html", "/start-up-nation-2026"],
  ["consultanta-start-up-nation.html", "/consultanta-start-up-nation-2026"],
  ["start-up-nation-2026-idei-afaceri-plan.html", "/start-up-nation-2026-idei-afaceri"],
];

function titleFor(target) {
  return target.replace(/^\/|\/$/g, "").replace(/-/g, " ") || "pagina principala";
}

function html(target) {
  target = cleanTarget(target);
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
${CLARITY_TRACKING_CODE}
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
