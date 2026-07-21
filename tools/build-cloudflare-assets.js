const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const { collectSiteState } = require("./generate-sitemap");

const ROOT = path.resolve(__dirname, "..");
const OUT_DIR = path.join(ROOT, "dist");

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "config",
  "dist",
  "node_modules",
  "reports",
  "scripts",
  "tools",
  "archive",
]);

const EXCLUDED_FILES = new Set([
  ".gitignore",
  "ADMIN_WORKFLOW.md",
  "CHANGELOG.md",
  "CNAME",
  "POST_DEPLOY_VERIFICATION.md",
  "PROMPT_TEMPLATE_BLOG_SEO.md",
  "README.md",
  "SEO_AUDIT_FIXES.md",
  "SEO_BLOG_AUDIT_2026-05-07.md",
  "SEO_BLOG_AUTOMATION.md",
  "SEO_NOTES.md",
  "netlify.toml",
  "package.json",
  "package-lock.json",
  "wrangler.jsonc",
]);

const PUBLIC_EXTENSIONS = new Set([
  ".css",
  ".gif",
  ".html",
  ".ico",
  ".jpeg",
  ".jpg",
  ".js",
  ".json",
  ".map",
  ".png",
  ".pdf",
  ".svg",
  ".txt",
  ".webmanifest",
  ".webp",
  ".xlsx",
  ".xml",
]);

const CANONICAL_ROOT_HTML_ROUTES = new Set([
  "por-adr-nord-est",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "dr12-afir",
  "dr14-afir-ferme-mici",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "fondul-modernizare-energie-regenerabila-2026",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "pro-infra",
  "start-up-nation-2026",
  "calculator-soc",
]);

const CANONICAL_DIRECTORY_HTML_ROUTES = [
  "blog",
  "contact",
  "despre-faber",
  "apeluri-gal",
  "e-move",
  "gal-afir",
  "consultanta-fonduri-europene",
  "proiectare-fonduri-europene",
  "studiu-fezabilitate-fonduri-europene",
  "plan-de-afaceri-fonduri-europene",
  "management-proiecte-fonduri-europene",
  "consultanta-fonduri-europene-bucuresti",
  "fonduri-regionale",
  "fonduri-europene-nord-est",
  "fonduri-europene-bucuresti",
  "verificare-eligibilitate-fonduri-europene",
  "digitalizare-imm-pnrr",
  "fondul-de-modernizare",
  "fonduri-europene",
  "fonduri-nerambursabile",
  "pnrr",
  "afir",
  "programul-tranzitie-justa",
  "programul-tranzitie-justa-intrebari-documente",
  "fonduri-europene-imm",
  "fonduri-europene-agricultura",
  "fonduri-europene-digitalizare",
  "fonduri-europene-femei-antreprenor",
  "calendar-fonduri-europene",
  "eligibilitate-fonduri-europene",
  "ghiduri",
  "studii-de-caz",
  "studii-de-caz-fonduri-europene",
  "intrebari-frecvente",
  "start-up-nation-2026-conditii",
  "start-up-nation-2026-cheltuieli-eligibile",
  "start-up-nation-2026-idei-afaceri",
  "start-up-nation-2026-plan-de-afaceri",
  "cod-caen-start-up-nation-2026",
  "consultanta-start-up-nation-2026",
  "consultanta-afir",
  "fonduri-pentru-ferme",
  "fonduri-pentru-utilaje-agricole",
  "granturi-digitalizare-imm",
  "consultanta-pnrr-digitalizare",
  "finantari-panouri-fotovoltaice",
  "cum-alegi-consultant-fonduri-europene",
  "cat-costa-consultanta-fonduri-europene",
  "firma-consultanta-fonduri-europene",
  "consultant-fonduri-europene-imm",
  "greseli-fonduri-europene",
  "fonduri-europene-nerambursabile-2026",
  "portofoliu",
  "testimoniale",
  "instrumente",
  "resurse",
  "resurse-utile",
  "webinarii",
  "metodologie-verificare-eligibilitate",
  "surse-oficiale-fonduri-europene",
  "glosar-fonduri-europene",
];

function posixPath(value) {
  return value.split(path.sep).join("/");
}

function firstSegment(relativePath) {
  return relativePath.split("/")[0];
}

function isPublicFile(relativePath) {
  const normalized = posixPath(relativePath);
  if (!normalized || normalized.startsWith("../")) return false;
  if (EXCLUDED_DIRS.has(firstSegment(normalized))) return false;
  if (EXCLUDED_FILES.has(normalized)) return false;
  for (const route of CANONICAL_ROOT_HTML_ROUTES) {
    if (normalized === `${route}/index.html` && fs.existsSync(path.join(ROOT, `${route}.html`))) return false;
  }
  if (CANONICAL_DIRECTORY_HTML_ROUTES.includes(normalized.replace(/\/index\.html$/i, "")) && normalized.endsWith("/index.html")) {
    return false;
  }
  if (normalized === "_redirects" || normalized === "_headers") return true;
  return PUBLIC_EXTENSIONS.has(path.posix.extname(normalized).toLowerCase());
}

function trackedFiles() {
  try {
    return cp
      .execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: ROOT })
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
  } catch {
    const result = [];
    function walk(dir) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        const relativePath = posixPath(path.relative(ROOT, fullPath));
        if (EXCLUDED_DIRS.has(firstSegment(relativePath))) continue;
        if (entry.isDirectory()) walk(fullPath);
        else result.push(relativePath);
      }
    }
    walk(ROOT);
    return result;
  }
}

function copyFile(relativePath) {
  const source = path.join(ROOT, relativePath);
  const target = path.join(OUT_DIR, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}

function gitCommit() {
  const fromEnvironment = process.env.CF_PAGES_COMMIT_SHA || process.env.GITHUB_SHA || process.env.COMMIT_SHA;
  if (/^[a-f0-9]{40}$/i.test(fromEnvironment || "")) return fromEnvironment.toLowerCase();
  return cp.execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim().toLowerCase();
}

function syncCanonicalHtmlAliases() {
  let synchronized = 0;
  for (const entry of collectSiteState().entries) {
    if (entry.route === "/") continue;
    const route = entry.route.replace(/^\/+|\/+$/g, "");
    const canonicalSource = path.join(ROOT, entry.sourceFile);
    const candidates = [
      path.join(OUT_DIR, `${route}.html`),
      path.join(OUT_DIR, route, "index.html"),
    ].filter((candidate) => fs.existsSync(candidate));
    for (const candidate of candidates) {
      fs.copyFileSync(canonicalSource, candidate);
      synchronized += 1;
    }
  }
  return synchronized;
}

if (!OUT_DIR.startsWith(ROOT + path.sep)) {
  throw new Error(`Refusing to clean output outside repository: ${OUT_DIR}`);
}

fs.rmSync(OUT_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
fs.mkdirSync(OUT_DIR, { recursive: true });

const files = trackedFiles().map(posixPath).filter(isPublicFile).sort();
for (const file of files) copyFile(file);

for (const route of CANONICAL_DIRECTORY_HTML_ROUTES) {
  const indexFile = `${route}/index.html`;
  const source = path.join(ROOT, indexFile);
  if (fs.existsSync(source)) {
    const target = path.join(OUT_DIR, `${route}.html`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }
}

const synchronizedAliases = syncCanonicalHtmlAliases();
fs.writeFileSync(path.join(OUT_DIR, "release.json"), `${JSON.stringify({
  commit: gitCommit(),
  builtAt: new Date().toISOString(),
}, null, 2)}\n`, "utf8");

console.log(`Cloudflare assets built in ${path.relative(ROOT, OUT_DIR)} (${files.length} files; ${synchronizedAliases} canonical HTML aliases synchronized).`);
