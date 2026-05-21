const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = fs.existsSync(path.join(ROOT, "dist")) ? path.join(ROOT, "dist") : ROOT;
const SITE = "https://atelierdeconsultanta.ro";
const URLS = [
  "https://atelierdeconsultanta.ro/index.html",
  "https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile",
  "https://atelierdeconsultanta.ro/fonduri-europene-imm",
  "https://atelierdeconsultanta.ro/fonduri-europene-agricultura",
  "https://atelierdeconsultanta.ro/fonduri-pentru-utilaje-agricole",
  "https://atelierdeconsultanta.ro/finantari-panouri-fotovoltaice",
  "https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026",
  "https://atelierdeconsultanta.ro/fonduri-pentru-ferme",
  "https://atelierdeconsultanta.ro/consultanta-afir",
  "https://atelierdeconsultanta.ro/granturi-digitalizare-imm",
  "https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri",
  "https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026",
  "https://atelierdeconsultanta.ro/studii-de-caz",
  "https://atelierdeconsultanta.ro/digitalizare-imm-pnrr",
  "https://atelierdeconsultanta.ro/fonduri-nerambursabile",
  "https://atelierdeconsultanta.ro/termeni-si-conditii",
  "https://atelierdeconsultanta.ro/ro/11.html",
  "https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene/",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene-imm/",
  "https://atelierdeconsultanta.ro/consultanta-afir/",
  "https://atelierdeconsultanta.ro/consultanta-pnrr-digitalizare/",
  "https://atelierdeconsultanta.ro/contact/",
  "https://atelierdeconsultanta.ro/fonduri-nerambursabile/",
  "https://atelierdeconsultanta.ro/blog/safir-fotovoltaice-ferme-2026.html",
  "https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html",
  "https://atelierdeconsultanta.ro/consultanta-start-up-nation/",
  "https://atelierdeconsultanta.ro/fonduri-europene/",
  "https://atelierdeconsultanta.ro/fonduri-europene-imm/",
  "https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene",
  "https://atelierdeconsultanta.ro/fonduri-europene",
  "https://atelierdeconsultanta.ro/contact",
];

function parseRedirects() {
  const file = path.join(PUBLIC_DIR, "_redirects");
  return fs.readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [from, to, status = "301"] = line.split(/\s+/);
      return { from, to, status: Number(status) };
    });
}

function fileForPath(pathname) {
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidates = [];
  if (!clean) candidates.push("index.html");
  else if (pathname.endsWith("/")) candidates.push(path.posix.join(clean, "index.html"));
  else if (path.posix.extname(clean)) candidates.push(clean);
  else candidates.push(`${clean}.html`, path.posix.join(clean, "index.html"));
  return candidates.find((candidate) => fs.existsSync(path.join(PUBLIC_DIR, candidate))) || "";
}

function textOf(file) {
  return file ? fs.readFileSync(path.join(PUBLIC_DIR, file), "utf8") : "";
}

function firstMatch(text, pattern) {
  return (text.match(pattern) || [])[1] || "";
}

function meta(file) {
  const text = textOf(file);
  return {
    canonical: firstMatch(text, /<link\s+rel=["']canonical["']\s+href=["']([^"']+)/i),
    robots: firstMatch(text, /<meta\s+name=["']robots["']\s+content=["']([^"']+)/i),
    title: firstMatch(text, /<title>([\s\S]*?)<\/title>/i).replace(/\s+/g, " ").trim(),
    description: firstMatch(text, /<meta\s+name=["']description["']\s+content=["']([^"']+)/i),
    h1: firstMatch(text, /<h1[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim(),
  };
}

function sitemapUrls() {
  const text = fs.readFileSync(path.join(PUBLIC_DIR, "sitemap.xml"), "utf8");
  return new Set([...text.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]));
}

function trace(rawUrl, redirects) {
  const chain = [];
  let current = new URL(rawUrl).pathname;
  const seen = new Set();
  for (let i = 0; i < 8; i += 1) {
    if (seen.has(current)) {
      chain.push({ path: current, status: "LOOP" });
      break;
    }
    seen.add(current);
    const redirect = redirects.find((rule) => rule.from === current);
    if (redirect) {
      chain.push({ path: current, status: redirect.status, to: redirect.to });
      current = redirect.to;
      continue;
    }
    const file = fileForPath(current);
    chain.push({ path: current, status: file ? 200 : 404, file });
    break;
  }
  return chain;
}

const redirects = parseRedirects();
const sitemap = sitemapUrls();
for (const url of URLS) {
  const chain = trace(url, redirects);
  const final = chain[chain.length - 1];
  const finalUrl = final.path ? `${SITE}${final.path === "/" ? "/" : final.path}` : "";
  const data = meta(final.file);
  console.log(JSON.stringify({
    input: url,
    chain,
    finalUrl,
    finalStatus: final.status,
    inSitemap: sitemap.has(finalUrl),
    ...data,
  }));
}
