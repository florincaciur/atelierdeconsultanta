const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const SITE_HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const TEXT_EXTENSIONS = new Set([".html", ".json", ".xml", ".txt", ".js"]);
const INTERNAL_PATH_PREFIXES = ["tools/", "config/", "partials/", "reports/"];
const SKIP_PREFIXES = ["mailto:", "tel:", "sms:", "javascript:", "data:", "blob:", "whatsapp:"];
const PROGRAM_ROUTES = [
  "dr12-afir",
  "dr14",
  "por-adr-nord-est",
  "fonduri-regionale",
  "fonduri-europene-nord-est",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "afir-autoconsum-agroalimentar",
  "autoconsum-public-fotovoltaice-institutii-publice",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "apeluri-gal",
  "fondul-modernizare-energie-regenerabila-2026",
  "pro-infra",
  "start-up-nation-2026",
  "instrumente",
  "resurse",
  "portofoliu",
  "testimoniale",
  "webinarii",
];

function posixFromFs(file) {
  return file.split(path.sep).join("/");
}

function isPublicAuditFile(file) {
  const normalized = posixFromFs(file);
  return !INTERNAL_PATH_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function trackedFiles() {
  try {
    return cp
      .execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: ROOT, encoding: "utf8" })
      .split("\0")
      .filter(Boolean)
      .filter(isPublicAuditFile)
      .filter((file) => TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()));
  } catch {
    const result = [];
    function walk(dir) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === ".git" || entry.name.endsWith("_files")) continue;
        const full = path.join(dir, entry.name);
        const relative = posixFromFs(path.relative(ROOT, full));
        if (!isPublicAuditFile(relative)) continue;
        if (entry.isDirectory()) walk(full);
        else if (TEXT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) result.push(path.relative(ROOT, full));
      }
    }
    walk(ROOT);
    return result.map(posixFromFs);
  }
}

function read(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function htmlFileForRoute(route) {
  const clean = route.replace(/^\/+/, "");
  if (!clean) return "index.html";
  if (route.endsWith("/")) return `${clean}index.html`;
  if (path.posix.extname(clean)) return clean;
  const dirIndex = `${clean}/index.html`;
  if (fs.existsSync(path.join(ROOT, dirIndex))) return dirIndex;
  return `${clean}.html`;
}

function normalizeTarget(rawValue, sourceFile) {
  if (!rawValue) return null;
  const value = rawValue.replace(/&amp;/g, "&").trim();
  if (!value || value === "#") return null;
  if (/^TODO(?:_|$)/.test(value)) return null;
  if (value.includes("${") || value.includes("{{")) return null;
  if (SKIP_PREFIXES.some((prefix) => value.toLowerCase().startsWith(prefix))) return null;

  let pathname;
  let hash = "";

  try {
    if (/^https?:\/\//i.test(value)) {
      const url = new URL(value);
      if (!SITE_HOSTS.has(url.hostname)) return null;
      pathname = url.pathname || "/";
      hash = url.hash || "";
    } else {
      const [withoutHash, rawHash = ""] = value.split("#");
      hash = rawHash ? `#${rawHash}` : "";
      if (!withoutHash) {
        const sourceRoute = sourceFile.endsWith("index.html")
          ? `/${path.posix.dirname(sourceFile).replace(/^\.$/, "")}/`.replace("//", "/")
          : `/${sourceFile}`;
        pathname = sourceRoute;
      } else if (withoutHash.startsWith("/")) {
        pathname = withoutHash;
      } else {
        pathname = `/${path.posix.normalize(path.posix.join(path.posix.dirname(sourceFile), withoutHash))}`;
      }
    }
  } catch {
    return null;
  }

  return {
    route: pathname,
    hash,
    targetFile: htmlFileForRoute(pathname),
  };
}

function lineNumber(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function extractLinks(file, text) {
  const links = [];
  const patterns = [
    /\b(?:href|src|action)=["']([^"']+)["']/gi,
    /"(?:ctaLink|canonicalUrl|url)"\s*:\s*"([^"]+)"/gi,
    /<loc>\s*(https?:\/\/[^<]+)\s*<\/loc>/gi,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text))) {
      const target = normalizeTarget(match[1], file);
      if (target) links.push({ sourceFile: file, line: lineNumber(text, match.index), value: match[1], ...target });
    }
  }
  return links;
}

function idsFor(file) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full) || path.extname(file).toLowerCase() !== ".html") return new Set();
  const text = fs.readFileSync(full, "utf8");
  const ids = new Set();
  let match;
  const idPattern = /\b(?:id|name)=["']([^"']+)["']/gi;
  while ((match = idPattern.exec(text))) ids.add(match[1]);
  return ids;
}

function parseRedirects() {
  const redirectsPath = path.join(ROOT, "_redirects");
  if (!fs.existsSync(redirectsPath)) return [];
  const lines = fs.readFileSync(redirectsPath, "utf8").split(/\r?\n/);
  return lines
    .map((line, index) => ({ line: index + 1, raw: line.trim() }))
    .filter((entry) => entry.raw && !entry.raw.startsWith("#"))
    .map((entry) => {
      const [from, to, status = ""] = entry.raw.split(/\s+/);
      return { ...entry, from, to, status };
    });
}

function containsDynamicToken(value) {
  return String(value || "").includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/.test(String(value || ""));
}

function compileRedirectPattern(pattern) {
  const names = [];
  const escaped = String(pattern)
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_, name) => {
      names.push(name);
      return "([^/]+)";
    });
  return { regex: new RegExp(`^${escaped}$`), names };
}

function redirectDestination(redirect, pathname) {
  if (redirect.from === pathname) return redirect.to;
  if (!containsDynamicToken(redirect.from)) return "";
  if (!redirect.compiled) redirect.compiled = compileRedirectPattern(redirect.from);
  const match = pathname.match(redirect.compiled.regex);
  if (!match) return "";
  let destination = redirect.to;
  redirect.compiled.names.forEach((name, index) => {
    destination = destination.replace(new RegExp(`:${name}\\b`, "g"), match[index + 1]);
  });
  return destination;
}

const files = trackedFiles();
const links = files.flatMap((file) => extractLinks(file, read(file)));
const missingTargets = [];
const missingAnchors = [];
const idCache = new Map();

for (const link of links) {
  const full = path.join(ROOT, link.targetFile);
  if (!fs.existsSync(full)) {
    missingTargets.push(link);
    continue;
  }
  if (link.hash) {
    const id = decodeURIComponent(link.hash.slice(1));
    if (!idCache.has(link.targetFile)) idCache.set(link.targetFile, idsFor(link.targetFile));
    if (!idCache.get(link.targetFile).has(id)) missingAnchors.push({ ...link, id });
  }
}

const redirects = parseRedirects();
const redirectIssues = [];
for (const redirect of redirects) {
  if (containsDynamicToken(redirect.from) || containsDynamicToken(redirect.to)) continue;
  const target = normalizeTarget(redirect.to, "_redirects");
  if (target && !fs.existsSync(path.join(ROOT, target.targetFile))) {
    redirectIssues.push({ ...redirect, targetFile: target.targetFile });
  }
}

const programRouteIssues = [];
for (const slug of PROGRAM_ROUTES) {
  const cleanRoute = `/${slug}`;
  const fileRoute = `/${slug}.html`;
  const hasCleanRewrite = redirects.some(
    (redirect) => redirect.from === cleanRoute && redirect.to === fileRoute && redirect.status.startsWith("200")
  );
  const hasHtmlRedirect = redirects.some(
    (redirect) => {
      if (!redirect.status.startsWith("301")) return false;
      const destination = redirectDestination(redirect, fileRoute);
      if (!destination) return false;
      const target = normalizeTarget(destination, "_redirects");
      return target?.route === cleanRoute;
    }
  );
  const hasHtmlAsset = fs.existsSync(path.join(ROOT, `${slug}.html`));
  const hasDirectoryAsset = fs.existsSync(path.join(ROOT, slug, "index.html"));
  if (!hasCleanRewrite && !hasHtmlAsset && !hasDirectoryAsset) {
    programRouteIssues.push(`${cleanRoute} should be backed by ${fileRoute} or /${slug}/index.html`);
  }
  if (!hasHtmlRedirect) programRouteIssues.push(`${fileRoute} should redirect to ${cleanRoute}`);
}

const dr14BadRedirect = redirects.find(
  (redirect) => {
    if (!["/dr14.html", "/dr14-afir.html", "/dr-14-afir.html"].includes(redirect.from)) return false;
    const target = normalizeTarget(redirect.to, "_redirects");
    return target?.route !== "/dr14";
  }
);

console.log("Functional link audit");
console.log(`Files scanned: ${files.length}`);
console.log(`Local links scanned: ${links.length}`);
console.log(`Missing local targets: ${missingTargets.length}`);
console.log(`Missing local anchors: ${missingAnchors.length}`);
console.log(`Redirect target issues: ${redirectIssues.length}`);
console.log(`Program route issues: ${programRouteIssues.length}`);
console.log(`Bad DR14 redirects: ${dr14BadRedirect ? "YES" : "NO"}`);

if (missingTargets.length || missingAnchors.length || redirectIssues.length || programRouteIssues.length || dr14BadRedirect) {
  if (missingTargets.length) {
    console.log("\nMissing targets:");
    for (const item of missingTargets) console.log(`- ${item.sourceFile}:${item.line} -> ${item.value} (${item.targetFile})`);
  }
  if (missingAnchors.length) {
    console.log("\nMissing anchors:");
    for (const item of missingAnchors) console.log(`- ${item.sourceFile}:${item.line} -> ${item.value} (${item.targetFile} #${item.id})`);
  }
  if (redirectIssues.length) {
    console.log("\nRedirect issues:");
    for (const item of redirectIssues) console.log(`- _redirects:${item.line} ${item.from} -> ${item.to} (${item.targetFile})`);
  }
  if (programRouteIssues.length) {
    console.log("\nProgram route issues:");
    for (const item of programRouteIssues) console.log(`- ${item}`);
  }
  if (dr14BadRedirect) console.log(`\nBad DR14 redirect: _redirects:${dr14BadRedirect.line} ${dr14BadRedirect.raw}`);
  process.exitCode = 1;
}
