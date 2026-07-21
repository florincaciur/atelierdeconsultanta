const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const { collectSiteState } = require("./generate-sitemap");

const ROOT = path.resolve(__dirname, "..");
const ALLOWED_STATUS_CODES = new Set(["200", "301", "302", "303", "307", "308"]);
const MAX_DYNAMIC_REDIRECTS = 99;

function stripJsonComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/.*$/gm, "$1");
}

function readWranglerConfig() {
  const configPath = path.join(ROOT, "wrangler.jsonc");
  if (!fs.existsSync(configPath)) throw new Error("wrangler.jsonc is missing.");
  return JSON.parse(stripJsonComments(fs.readFileSync(configPath, "utf8")));
}

function validateDomainWorkerConfig(errors) {
  const configPath = path.join(ROOT, "wrangler.redirects.jsonc");
  const workerPath = path.join(ROOT, "cloudflare", "domain-seo-redirects.mjs");
  if (!fs.existsSync(configPath)) {
    errors.push("wrangler.redirects.jsonc is missing");
    return;
  }
  if (!fs.existsSync(workerPath)) errors.push("cloudflare/domain-seo-redirects.mjs is missing");
  let workerConfig;
  try {
    workerConfig = JSON.parse(stripJsonComments(fs.readFileSync(configPath, "utf8")));
  } catch (error) {
    errors.push(`wrangler.redirects.jsonc is invalid: ${error.message}`);
    return;
  }
  if (workerConfig.name !== "atelierdeconsultanta-domain-seo") errors.push("domain SEO worker name differs from the managed production worker");
  if (workerConfig.main !== "cloudflare/domain-seo-redirects.mjs") errors.push("domain SEO worker main file differs");
  if (workerConfig.workers_dev !== false) errors.push("domain SEO worker must not expose a workers.dev route");
  const routePatterns = new Set((workerConfig.routes || [])
    .filter((item) => item.zone_name === "atelierdeconsultanta.ro")
    .map((item) => item.pattern));
  for (const required of ["atelierdeconsultanta.ro/*", "www.atelierdeconsultanta.ro/*"]) {
    if (!routePatterns.has(required)) errors.push(`domain SEO worker must cover ${required} in the apex zone`);
  }
}

function validateDomainSeoIntent(file, errors) {
  if (!fs.existsSync(file)) {
    errors.push(`${file} is missing`);
    return;
  }
  let config;
  try {
    config = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    errors.push(`${file} is not valid JSON: ${error.message}`);
    return;
  }
  if (config.canonicalOrigin !== "https://atelierdeconsultanta.ro") errors.push(`${file}: canonicalOrigin must use the HTTPS apex domain`);
  if (config.httpRedirect?.enabled !== true || config.httpRedirect?.status !== 301) errors.push(`${file}: HTTP redirect must be enabled as 301 desired state`);
  if (config.httpRedirect?.preservePath !== true || config.httpRedirect?.preserveQuery !== true) errors.push(`${file}: HTTP redirect must preserve path and query`);
  if (config.httpRedirect?.maximumHops !== 1) errors.push(`${file}: HTTP redirect desired state must use one hop`);
  if (config.legacySearchRedirect?.enabled !== true || config.legacySearchRedirect?.status !== 301) errors.push(`${file}: legacy search redirect must be enabled as 301 desired state`);
  if (config.legacySearchRedirect?.destination !== "https://atelierdeconsultanta.ro/") errors.push(`${file}: legacy search redirect must target the canonical homepage`);
  if (config.legacySearchRedirect?.preserveQuery !== false) errors.push(`${file}: legacy search redirect must discard the obsolete query`);
  if (config.deploymentState === "active_cloudflare_worker_route" && config.hsts?.enabled !== true) errors.push(`${file}: active domain worker must enable the verified HSTS policy`);
  if (config.hsts?.enableOnlyAfterHttpRedirectVerification !== true) errors.push(`${file}: HSTS must be gated by live HTTPS verification`);
  if (config.hsts?.preload !== false) errors.push(`${file}: HSTS preload must remain disabled initially`);
}

function parseRedirects(file) {
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  const rules = [];
  const errors = [];

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const raw = lines[index];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (trimmed.includes("!")) {
      errors.push(`${file}:${lineNumber} uses Netlify-style forced syntax: ${trimmed}`);
    }

    const parts = trimmed.split(/\s+/);
    if (parts.length !== 3) {
      errors.push(`${file}:${lineNumber} must be: [source] [destination] [status]`);
      continue;
    }

    const [source, destination, status] = parts;
    if (!ALLOWED_STATUS_CODES.has(status)) {
      errors.push(`${file}:${lineNumber} invalid status code ${status}`);
    }

    const dynamic = containsDynamicToken(source) || containsDynamicToken(destination);
    rules.push({ lineNumber, source, destination, status, dynamic });
  }

  return { rules, errors };
}

function parseHeaders(file) {
  const rules = [];
  let current = null;
  const errors = [];

  if (!fs.existsSync(file)) {
    return { rules, errors: [`${file} is missing`] };
  }

  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      current = { lineNumber: index + 1, pattern: line.trim(), headers: {} };
      rules.push(current);
      continue;
    }
    if (!current) {
      errors.push(`${file}:${index + 1} header without a path rule`);
      continue;
    }
    const [name, ...rest] = line.trim().split(":");
    if (!name || !rest.length) {
      errors.push(`${file}:${index + 1} invalid header syntax`);
      continue;
    }
    current.headers[name.toLowerCase()] = rest.join(":").trim();
  }

  return { rules, errors };
}

function containsDynamicToken(value) {
  return value.includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/.test(value);
}

function validateOfficialGuidesHeaders(file, errors) {
  const parsed = parseHeaders(file);
  errors.push(...parsed.errors);
  const rule = parsed.rules.find((item) => item.pattern === "/official-guides.json");
  if (!rule) {
    errors.push(`${file}: missing /official-guides.json header rule`);
    return;
  }
  const robots = rule.headers["x-robots-tag"] || "";
  const contentType = rule.headers["content-type"] || "";
  if (!/\bnoindex\b/i.test(robots) || !/\bnofollow\b/i.test(robots)) {
    errors.push(`${file}:${rule.lineNumber} /official-guides.json must set X-Robots-Tag: noindex, nofollow`);
  }
  if (!/^application\/json\b/i.test(contentType)) {
    errors.push(`${file}:${rule.lineNumber} /official-guides.json must set Content-Type: application/json`);
  }
}

function validateReleaseHeaders(file, errors) {
  const parsed = parseHeaders(file);
  errors.push(...parsed.errors);
  const rule = parsed.rules.find((item) => item.pattern === "/release.json");
  if (!rule) {
    errors.push(`${file}: missing /release.json header rule`);
    return;
  }
  const robots = rule.headers["x-robots-tag"] || "";
  const contentType = rule.headers["content-type"] || "";
  const cacheControl = rule.headers["cache-control"] || "";
  if (!/\bnoindex\b/i.test(robots) || !/\bnofollow\b/i.test(robots)) errors.push(`${file}:${rule.lineNumber} /release.json must set X-Robots-Tag: noindex, nofollow`);
  if (!/^application\/json\b/i.test(contentType)) errors.push(`${file}:${rule.lineNumber} /release.json must set Content-Type: application/json`);
  if (!/\bno-store\b/i.test(cacheControl)) errors.push(`${file}:${rule.lineNumber} /release.json must set Cache-Control: no-store`);
}

function validateReleaseManifest(directory, errors) {
  const file = path.join(directory, "release.json");
  if (!fs.existsSync(file)) {
    errors.push(`${path.relative(ROOT, file)} is missing`);
    return;
  }
  try {
    const release = JSON.parse(fs.readFileSync(file, "utf8"));
    const expectedCommit = cp.execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim().toLowerCase();
    if (release.commit !== expectedCommit) errors.push(`${path.relative(ROOT, file)} commit ${release.commit || "missing"} differs from ${expectedCommit}`);
    if (!Number.isFinite(Date.parse(release.builtAt))) errors.push(`${path.relative(ROOT, file)} builtAt is invalid`);
  } catch (error) {
    errors.push(`${path.relative(ROOT, file)} is invalid: ${error.message}`);
  }
}

function validateCanonicalHtmlParity(directory, errors) {
  for (const entry of collectSiteState().entries) {
    if (entry.route === "/") continue;
    const route = entry.route.replace(/^\/+|\/+$/g, "");
    const expected = fs.readFileSync(path.join(ROOT, entry.sourceFile));
    const candidates = [path.join(directory, `${route}.html`), path.join(directory, route, "index.html")].filter((candidate) => fs.existsSync(candidate));
    for (const candidate of candidates) {
      if (!expected.equals(fs.readFileSync(candidate))) errors.push(`${path.relative(ROOT, candidate)} differs from canonical source ${entry.sourceFile}`);
    }
  }
}

function assertCleanAssetDirectory(directory) {
  const normalized = directory.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!normalized || normalized === "." || normalized === "./") {
    throw new Error("wrangler.jsonc assets.directory must not point at the repository root.");
  }

  const fullPath = path.resolve(ROOT, directory);
  if (!fullPath.startsWith(ROOT + path.sep)) {
    throw new Error(`wrangler.jsonc assets.directory escapes the repository: ${directory}`);
  }

  if (fs.existsSync(fullPath)) {
    for (const forbidden of [".git", ".github", ".wrangler", "tools", "scripts", "config"]) {
      const candidate = path.join(fullPath, forbidden);
      if (fs.existsSync(candidate)) {
        throw new Error(`Deploy output contains internal path: ${path.relative(ROOT, candidate)}`);
      }
    }
  }
}

const redirectsPath = path.join(ROOT, "_redirects");
const { rules, errors } = parseRedirects(redirectsPath);
const dynamicRules = rules.filter((rule) => rule.dynamic);
const ruleBySource = new Map(rules.map((rule) => [rule.source, rule]));

if (dynamicRules.length > MAX_DYNAMIC_REDIRECTS) {
  errors.push(
    `${redirectsPath}: ${dynamicRules.length} dynamic redirects; expected fewer than 100`
  );
}

for (const rule of rules) {
  if (rule.source === rule.destination) {
    errors.push(`${redirectsPath}:${rule.lineNumber} redirects ${rule.source} to itself`);
  }
  const inverse = ruleBySource.get(rule.destination);
  if (inverse && inverse.destination === rule.source && rule.lineNumber < inverse.lineNumber) {
    errors.push(
      `${redirectsPath}:${rule.lineNumber} and ${redirectsPath}:${inverse.lineNumber} form a redirect cycle: ${rule.source} <-> ${rule.destination}`
    );
  }
}

const config = readWranglerConfig();
if (!config.assets || !config.assets.directory) {
  errors.push("wrangler.jsonc must define assets.directory.");
} else {
  assertCleanAssetDirectory(config.assets.directory);
  const distOfficialGuides = path.join(ROOT, config.assets.directory, "official-guides.json");
  const distHeaders = path.join(ROOT, config.assets.directory, "_headers");
  const distDirectory = path.join(ROOT, config.assets.directory);
  if (fs.existsSync(path.join(ROOT, config.assets.directory)) && !fs.existsSync(distOfficialGuides)) {
    errors.push(`Deploy output is missing ${path.relative(ROOT, distOfficialGuides)}`);
  }
  if (fs.existsSync(distOfficialGuides)) {
    try {
      JSON.parse(fs.readFileSync(distOfficialGuides, "utf8"));
    } catch (error) {
      errors.push(`${path.relative(ROOT, distOfficialGuides)} is not valid JSON: ${error.message}`);
    }
  }
  if (fs.existsSync(distDirectory)) {
    validateOfficialGuidesHeaders(distHeaders, errors);
    validateReleaseHeaders(distHeaders, errors);
    validateReleaseManifest(distDirectory, errors);
    validateCanonicalHtmlParity(distDirectory, errors);
  }
}
validateOfficialGuidesHeaders(path.join(ROOT, "_headers"), errors);
validateReleaseHeaders(path.join(ROOT, "_headers"), errors);
validateDomainSeoIntent(path.join(ROOT, "config", "cloudflare-domain-seo.json"), errors);
validateDomainWorkerConfig(errors);

if (errors.length) {
  console.error("Cloudflare deploy validation failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Redirect rules: ${rules.length}`);
console.log(`Dynamic redirect rules: ${dynamicRules.length}`);
console.log(`Cloudflare assets directory: ${config.assets.directory}`);
console.log("Cloudflare deploy validation passed.");
