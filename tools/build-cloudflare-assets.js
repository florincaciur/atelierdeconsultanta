const cp = require("child_process");
const fs = require("fs");
const path = require("path");

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
  ".svg",
  ".txt",
  ".webmanifest",
  ".webp",
  ".xml",
]);

const CANONICAL_ROOT_HTML_ROUTES = new Set([
  "por-adr-nord-est",
  "dr12-afir",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "pro-infra",
  "start-up-nation-2026",
  "calculator-soc",
]);

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
  if (normalized === "_redirects") return true;
  return PUBLIC_EXTENSIONS.has(path.posix.extname(normalized).toLowerCase());
}

function trackedFiles() {
  try {
    return cp
      .execFileSync("git", ["ls-files", "-z"], { cwd: ROOT })
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

if (!OUT_DIR.startsWith(ROOT + path.sep)) {
  throw new Error(`Refusing to clean output outside repository: ${OUT_DIR}`);
}

fs.rmSync(OUT_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
fs.mkdirSync(OUT_DIR, { recursive: true });

const files = trackedFiles().map(posixPath).filter(isPublicFile).sort();
for (const file of files) copyFile(file);

console.log(`Cloudflare assets built in ${path.relative(ROOT, OUT_DIR)} (${files.length} files).`);
