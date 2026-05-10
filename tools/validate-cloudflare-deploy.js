const fs = require("fs");
const path = require("path");

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

function containsDynamicToken(value) {
  return value.includes("*") || /(^|[^A-Za-z0-9_-]):[A-Za-z][A-Za-z0-9_-]*/.test(value);
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

if (dynamicRules.length > MAX_DYNAMIC_REDIRECTS) {
  errors.push(
    `${redirectsPath}: ${dynamicRules.length} dynamic redirects; expected fewer than 100`
  );
}

const config = readWranglerConfig();
if (!config.assets || !config.assets.directory) {
  errors.push("wrangler.jsonc must define assets.directory.");
} else {
  assertCleanAssetDirectory(config.assets.directory);
}

if (errors.length) {
  console.error("Cloudflare deploy validation failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Redirect rules: ${rules.length}`);
console.log(`Dynamic redirect rules: ${dynamicRules.length}`);
console.log(`Cloudflare assets directory: ${config.assets.directory}`);
console.log("Cloudflare deploy validation passed.");
