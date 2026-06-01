const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = fs.existsSync(path.join(ROOT, "dist")) ? path.join(ROOT, "dist") : ROOT;
const SITE = "https://atelierdeconsultanta.ro";

const URLS = [
  "https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/",
  "https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/",
  "https://atelierdeconsultanta.ro/consultanta-start-up-nation/",
  "https://atelierdeconsultanta.ro/fonduri-europene-imm/",
  "https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html",
  "https://atelierdeconsultanta.ro/fonduri-europene/",
  "http://atelierdeconsultanta.ro/politica-de-confidentialitate.html",
  "https://atelierdeconsultanta.ro/dr12-vs-dr14",
  "https://atelierdeconsultanta.ro/dr14-afir-ferme-mici",
  "https://atelierdeconsultanta.ro/afir",
  "https://atelierdeconsultanta.ro/ghiduri",
  "https://atelierdeconsultanta.ro/fonduri-nerambursabile",
  "https://atelierdeconsultanta.ro/blog?post=blog-1",
  "http://atelierdeconsultanta.ro/",
  "https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/",
  "https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/",
  "https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/",
  "https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/",
  "https://atelierdeconsultanta.ro/fonduri-europene-bucuresti",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti",
  "https://atelierdeconsultanta.ro/fonduri-europene-iasi",
  "https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bacau",
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

function parseHeaders() {
  const file = path.join(PUBLIC_DIR, "_headers");
  if (!fs.existsSync(file)) return [];
  const rules = [];
  let current = null;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      current = { pattern: line.trim(), headers: {} };
      rules.push(current);
      continue;
    }
    if (!current) continue;
    const [name, ...rest] = line.trim().split(":");
    current.headers[name.toLowerCase()] = rest.join(":").trim();
  }
  return rules;
}

function matchesPattern(pattern, pathname) {
  if (pattern === pathname) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(pathname);
}

function headersFor(pathname, headerRules) {
  const headers = {};
  for (const rule of headerRules) {
    if (matchesPattern(rule.pattern, pathname)) Object.assign(headers, rule.headers);
  }
  return headers;
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

function tagAttr(tag, attr) {
  const match = tag.match(new RegExp(`\\b${attr}=["']([^"']+)["']`, "i"));
  return match ? match[1].trim() : "";
}

function firstTag(text, pattern) {
  const match = text.match(pattern);
  return match ? match[0] : "";
}

function textMatch(text, pattern) {
  const match = text.match(pattern);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}

function extractCanonical(text) {
  for (const match of text.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0];
    if (/\brel=["'][^"']*\bcanonical\b[^"']*["']/i.test(tag)) return tagAttr(tag, "href");
  }
  return "";
}

function meta(file, pathname, headerRules) {
  const text = textOf(file);
  const robotsTag = firstTag(text, /<meta\b[^>]*\bname=["']robots["'][^>]*>/i);
  const robots = tagAttr(robotsTag, "content");
  const headerRobots = headersFor(pathname, headerRules)["x-robots-tag"] || "";
  return {
    canonical: extractCanonical(text),
    robots: [robots, headerRobots].filter(Boolean).join("; "),
    title: textMatch(text, /<title>([\s\S]*?)<\/title>/i),
    h1: textMatch(text, /<h1[^>]*>([\s\S]*?)<\/h1>/i).replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim(),
  };
}

function sitemapUrls() {
  const file = path.join(PUBLIC_DIR, "sitemap.xml");
  if (!fs.existsSync(file)) return new Set();
  const text = fs.readFileSync(file, "utf8");
  return new Set([...text.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]));
}

function cleanAbsoluteUrl(rawUrl, { keepQuery = false } = {}) {
  const parsed = new URL(rawUrl, SITE);
  parsed.hash = "";
  if (!keepQuery) parsed.search = "";
  if (parsed.pathname !== "/") parsed.pathname = parsed.pathname.replace(/\/+$/g, "");
  return parsed.href;
}

function trace(rawUrl, redirects) {
  const chain = [];
  let currentUrl = new URL(rawUrl);
  const seen = new Set();

  for (let i = 0; i < 10; i += 1) {
    const key = currentUrl.href;
    if (seen.has(key)) {
      chain.push({ url: currentUrl.href, status: "LOOP" });
      break;
    }
    seen.add(key);

    if (currentUrl.protocol === "http:") {
      const next = new URL(currentUrl.href);
      next.protocol = "https:";
      chain.push({ url: currentUrl.href, status: 301, to: next.href });
      currentUrl = next;
      continue;
    }

    const redirect = redirects.find((rule) => matchesPattern(rule.from, currentUrl.pathname));
    if (redirect) {
      const next = new URL(redirect.to, SITE);
      chain.push({ url: currentUrl.href, status: redirect.status, to: next.href });
      currentUrl = next;
      continue;
    }

    const file = fileForPath(currentUrl.pathname);
    chain.push({ url: currentUrl.href, status: file ? 200 : 404, file });
    break;
  }
  return chain;
}

function verdictFor({ input, chain, finalUrl, finalStatus, inSitemap, canonical, robots }) {
  if (chain.some((step) => step.status === "LOOP")) return "FAIL_REDIRECT_LOOP";
  if (finalStatus === 404) return "FAIL_404";
  if (/\bnoindex\b/i.test(robots)) return "FAIL_NOINDEX";
  if (!canonical) return "FAIL_CANONICAL_MISMATCH";

  const inputNoQuery = cleanAbsoluteUrl(input);
  const inputWithQuery = cleanAbsoluteUrl(input, { keepQuery: true });
  const finalNoQuery = cleanAbsoluteUrl(finalUrl);
  const finalWithQuery = cleanAbsoluteUrl(finalUrl, { keepQuery: true });
  const canonicalClean = cleanAbsoluteUrl(canonical);
  const redirected = chain.some((step) => Number(step.status) >= 300 && Number(step.status) < 400);
  const inputIsCanonical = inputNoQuery === canonicalClean && inputWithQuery === canonicalClean;

  if (!inputIsCanonical && inSitemap && finalWithQuery === inputWithQuery) return "FAIL_SITEMAP_DUPLICATE";
  if (redirected && finalNoQuery === canonicalClean) return "PASS_REDIRECT_TO_CANONICAL";
  if (!redirected && finalNoQuery === canonicalClean && inputIsCanonical) return "PASS_CANONICAL_200";
  if (!redirected && finalNoQuery === canonicalClean && !inputIsCanonical) return "PASS_ALTERNATE_CANONICAL";
  if (!redirected && canonicalClean !== finalNoQuery && !inSitemap) return "PASS_ALTERNATE_CANONICAL";
  return "FAIL_CANONICAL_MISMATCH";
}

const redirects = parseRedirects();
const headerRules = parseHeaders();
const sitemap = sitemapUrls();

for (const inputUrl of URLS) {
  const chain = trace(inputUrl, redirects);
  const final = chain[chain.length - 1];
  const finalUrl = final.url || "";
  const finalPath = finalUrl ? new URL(finalUrl).pathname : "";
  const data = meta(final.file, finalPath, headerRules);
  const finalStatus = final.status;
  const inSitemap = finalUrl ? sitemap.has(cleanAbsoluteUrl(finalUrl, { keepQuery: true })) : false;
  const verdict = verdictFor({
    input: inputUrl,
    chain,
    finalUrl,
    finalStatus,
    inSitemap,
    ...data,
  });

  console.log(JSON.stringify({
    inputUrl,
    redirectChain: chain.map(({ file, ...step }) => step),
    finalUrl,
    finalStatus,
    inSitemap,
    ...data,
    verdict,
  }));
}
