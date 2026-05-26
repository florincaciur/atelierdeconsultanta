const fs = require("fs");
const http = require("http");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const MAX_REDIRECTS = 10;

const PROGRAM_ROUTES = [
  "/por-adr-nord-est",
  "/fonduri-europene-nord-est",
  "/investitii-modernizarea-microintreprinderilor-apel-2",
  "/dr12-afir",
  "/afir-autoconsum-agroalimentar",
  "/autoconsum-public-fotovoltaice-institutii-publice",
  "/fondul-modernizare-energie-regenerabila-2026",
  "/dr14",
  "/digitalizare-imm",
  "/femeia-antreprenor-2026",
  "/apeluri-gal",
  "/pro-infra",
  "/start-up-nation-2026",
  "/calculator-soc",
  "/instrumente",
  "/resurse",
  "/portofoliu",
  "/testimoniale",
  "/webinarii",
];

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = { base: "" };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--base") parsed.base = args[index + 1] || "";
  }
  return parsed;
}

function parseRedirects(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [source, destination, status] = line.split(/\s+/);
      return { source, destination, status: Number(status) };
    });
}

function safeRelativePath(urlPath) {
  const decoded = decodeURIComponent(urlPath).replace(/^\/+/, "");
  const normalized = path.posix.normalize(decoded);
  if (!normalized || normalized === ".") return "index.html";
  if (normalized.startsWith("../")) return "";
  return normalized;
}

function contentType(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".css") return "text/css; charset=utf-8";
  if (ext === ".js") return "application/javascript; charset=utf-8";
  if (ext === ".json" || ext === ".webmanifest") return "application/json; charset=utf-8";
  if (ext === ".xml") return "application/xml; charset=utf-8";
  if (ext === ".txt") return "text/plain; charset=utf-8";
  return "application/octet-stream";
}

function createLocalServer() {
  const redirects = parseRedirects(path.join(DIST, "_redirects"));

  return http.createServer((request, response) => {
    const url = new URL(request.url, "http://localhost");
    const pathname = url.pathname;
    const redirect = redirects.find((rule) => rule.source === pathname);

    if (redirect && redirect.status >= 300 && redirect.status < 400) {
      response.writeHead(redirect.status, { Location: redirect.destination });
      response.end();
      return;
    }

    if (redirect && redirect.status === 200) {
      servePath(redirect.destination, response);
      return;
    }

    servePath(pathname, response);
  });
}

function servePath(urlPath, response) {
  const relativePath = safeRelativePath(urlPath);
  const candidates = [];

  if (relativePath) {
    candidates.push(relativePath);
    if (!path.posix.extname(relativePath)) candidates.push(`${relativePath}.html`);
    candidates.push(path.posix.join(relativePath, "index.html"));
  }

  for (const candidate of candidates) {
    const fullPath = path.join(DIST, candidate);
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      response.writeHead(200, { "Content-Type": contentType(fullPath) });
      response.end(fs.readFileSync(fullPath));
      return;
    }
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
}

async function startLocalServer() {
  const server = createLocalServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { server, base: `http://127.0.0.1:${port}` };
}

async function traceUrl(startUrl) {
  const chain = [];
  const seen = new Set();
  let current = startUrl;
  let loop = false;

  for (let step = 0; step <= MAX_REDIRECTS; step += 1) {
    if (seen.has(current)) {
      loop = true;
      break;
    }
    seen.add(current);

    const response = await fetch(current, { redirect: "manual" });
    const status = response.status;
    const location = response.headers.get("location");
    chain.push({ url: current, status, location });

    if (status >= 300 && status < 400 && location) {
      current = new URL(location, current).href;
      continue;
    }

    break;
  }

  if (chain.length > MAX_REDIRECTS) loop = true;
  return { chain, loop, final: chain[chain.length - 1] };
}

function pathOf(value) {
  return new URL(value).pathname;
}

function validateResult(label, route, result, expectDirect) {
  const redirects = result.chain.filter((item) => item.status >= 300 && item.status < 400);
  const finalStatus = result.final ? result.final.status : 0;
  const finalPath = result.final ? pathOf(result.final.url) : "";
  const errors = [];

  if (result.loop) errors.push("redirect loop");
  if (finalStatus === 404) errors.push("404");
  if (finalStatus !== 200) errors.push(`final status ${finalStatus}`);
  if (expectDirect && redirects.length !== 0) errors.push(`expected direct 200, got ${redirects.length} redirects`);
  if (!expectDirect && redirects.length > 1) errors.push(`expected max 1 redirect, got ${redirects.length}`);
  if (finalPath !== route) errors.push(`final path ${finalPath}`);

  return {
    label,
    route,
    finalStatus,
    redirects: redirects.length,
    loop: result.loop,
    ok: errors.length === 0,
    errors,
  };
}

async function main() {
  const args = parseArgs();
  let server = null;
  let base = args.base;

  if (!base) {
    if (!fs.existsSync(DIST)) throw new Error("dist is missing. Run npm run build first.");
    const local = await startLocalServer();
    server = local.server;
    base = local.base;
  }

  const results = [];
  try {
    for (const route of PROGRAM_ROUTES) {
      const canonical = await traceUrl(new URL(route, base).href);
      results.push(validateResult("canonical", route, canonical, true));

      const htmlVariant = await traceUrl(new URL(`${route}.html`, base).href);
      results.push(validateResult("html", route, htmlVariant, false));
    }
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
  }

  console.log(`Program route audit base: ${base}`);
  for (const result of results) {
    const marker = result.ok ? "PASS" : "FAIL";
    const details = result.errors.length ? ` (${result.errors.join("; ")})` : "";
    console.log(`${marker} ${result.label.padEnd(9)} ${result.route.padEnd(56)} final=${result.finalStatus} redirects=${result.redirects} loop=${result.loop}${details}`);
  }

  if (results.some((result) => !result.ok)) process.exit(1);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
