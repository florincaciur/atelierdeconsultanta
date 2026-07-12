import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const SITE_ORIGIN = "https://atelierdeconsultanta.ro";
const EXPECTED_CANONICAL_URLS = 102;
const CONSOLIDATED_LOCAL_ROUTES = [
  "/fonduri-europene-bacau",
  "/consultanta-fonduri-europene-bacau",
  "/fonduri-europene-iasi",
  "/consultanta-fonduri-europene-iasi",
  "/fonduri-europene-suceava",
  "/consultanta-fonduri-europene-suceava",
  "/dr14-afir-ferme-mici",
  "/fonduri-europene-herambursabile-2026",
  "/start-up-nation",
  "/consultanta-start-up-nation",
  "/studii-de-caz"
];
const INDEXABLE_LOCAL_ROUTES = [
  "/fonduri-europene-bucuresti",
  "/consultanta-fonduri-europene-bucuresti"
];
const INDEXABLE_PROGRAM_ROUTES = [
  "/proiectare-fonduri-europene",
  "/studiu-fezabilitate-fonduri-europene",
  "/plan-de-afaceri-fonduri-europene",
  "/management-proiecte-fonduri-europene",
  "/resurse-utile",
  "/dr12-afir",
  "/dr14",
  "/e-move",
  "/pro-infra",
  "/start-up-nation-2026",
  "/investitii-modernizarea-microintreprinderilor-apel-2",
  "/pocidif-21"
];
const NOINDEX_TRUST_ROUTES = [
  "/portofoliu",
  "/testimoniale"
];

function parseRedirects() {
  const source = fs.existsSync(path.join(DIST, "_redirects")) ? path.join(DIST, "_redirects") : path.join(ROOT, "_redirects");
  const raw = fs.readFileSync(source, "utf8");
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [from, to, status = "301"] = line.split(/\s+/);
      return { from, to, status: Number(status) || 301 };
    });
}

function parseHeaders() {
  const source = fs.existsSync(path.join(DIST, "_headers")) ? path.join(DIST, "_headers") : path.join(ROOT, "_headers");
  const raw = fs.readFileSync(source, "utf8");
  const rules = [];
  let current = null;

  for (const line of raw.split(/\r?\n/)) {
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
  if (!pattern.includes("*") && !/:([A-Za-z][A-Za-z0-9_]*)/.test(pattern)) return false;
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/:([A-Za-z][A-Za-z0-9_]*)/g, "[^/]+");
  return new RegExp(`^${escaped}$`).test(pathname);
}

function findRedirect(pathname, redirects) {
  for (const rule of redirects) {
    if (rule.from === pathname) return rule;
    const names = [];
    const escaped = rule.from
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/:([A-Za-z][A-Za-z0-9_]*)/g, (_, name) => {
        names.push(name);
        return "([^/]+)";
      });
    const match = pathname.match(new RegExp(`^${escaped}$`));
    if (!match) continue;
    let to = rule.to;
    names.forEach((name, index) => {
      to = to.replace(new RegExp(`:${name}\\b`, "g"), match[index + 1]);
    });
    return { ...rule, to };
  }
  return undefined;
}

function headersFor(pathname, headerRules) {
  const headers = {};
  for (const rule of headerRules) {
    if (matchesPattern(rule.pattern, pathname)) Object.assign(headers, rule.headers);
  }
  return headers;
}

async function fileExists(filePath) {
  try {
    const stat = await fsp.stat(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function resolveStaticFile(pathname) {
  const clean = decodeURIComponent(pathname).replace(/^\/+/, "");
  const candidates = pathname === "/"
    ? [path.join(DIST, "index.html")]
    : [
        path.join(DIST, clean, "index.html"),
        path.join(DIST, `${clean}.html`),
        path.join(DIST, clean)
      ];

  for (const candidate of candidates) {
    if (await fileExists(candidate)) return { filePath: candidate, status: 200 };
  }

  return { filePath: path.join(DIST, "404.html"), status: 404 };
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".css") return "text/css; charset=utf-8";
  if (ext === ".js") return "application/javascript; charset=utf-8";
  if (ext === ".json") return "application/json; charset=utf-8";
  if (ext === ".svg") return "image/svg+xml";
  if (ext === ".png") return "image/png";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  if (ext === ".webp") return "image/webp";
  if (ext === ".avif") return "image/avif";
  return "application/octet-stream";
}

async function createServer() {
  const redirects = parseRedirects();
  const headerRules = parseHeaders();
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", "http://127.0.0.1");
      const pathname = url.pathname;
      const headers = headersFor(pathname, headerRules);
      const redirect = findRedirect(pathname, redirects);

      if (redirect) {
        response.writeHead(redirect.status, { ...headers, location: redirect.to });
        response.end();
        return;
      }

      const { filePath, status } = await resolveStaticFile(pathname);
      const body = await fsp.readFile(filePath);
      response.writeHead(status, { ...headers, "content-type": contentType(filePath) });
      response.end(body);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(String(error.stack || error));
    }
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function fetchManual(url) {
  return fetch(url, { redirect: "manual" });
}

async function assertCanonicalRoutes(baseUrl) {
  const sitemap = await fsp.readFile(path.join(ROOT, "sitemap.xml"), "utf8");
  const paths = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => {
    const url = new URL(match[1]);
    return url.pathname || "/";
  });

  assert.equal(paths.length, EXPECTED_CANONICAL_URLS, "sitemap canonical URL count changed unexpectedly");
  for (const routePath of CONSOLIDATED_LOCAL_ROUTES) {
    assert(!paths.includes(routePath), `${routePath} should stay out of sitemap while consolidated`);
  }
  for (const routePath of NOINDEX_TRUST_ROUTES) {
    assert(!paths.includes(routePath), `${routePath} should stay out of sitemap while noindex`);
  }
  for (const routePath of INDEXABLE_LOCAL_ROUTES) {
    assert(paths.includes(routePath), `${routePath} should be in sitemap as an indexable local landing page`);
  }
  for (const routePath of INDEXABLE_PROGRAM_ROUTES) {
    assert(paths.includes(routePath), `${routePath} should be in sitemap as an indexable program page`);
  }

  for (const routePath of NOINDEX_TRUST_ROUTES) {
    const response = await fetchManual(`${baseUrl}${routePath}`);
    assert.equal(response.status, 200, `${routePath} should remain publicly accessible`);
    const html = await response.text();
    assert.match(html, /<meta\s+name=["']robots["']\s+content=["']noindex,\s*follow["']/i, `${routePath} should declare noindex, follow`);
  }

  for (const routePath of paths) {
    const response = await fetchManual(`${baseUrl}${routePath}`);
    assert.equal(response.status, 200, `${routePath} should return 200`);
    const robots = response.headers.get("x-robots-tag") || "";
    assert(!/noindex/i.test(robots), `${routePath} should not send noindex header`);
    const html = await response.text();
    assert(/<h1[\s>]/i.test(html), `${routePath} should include an H1`);
  }
}

async function assertRedirectsAndFallback(baseUrl) {
  const checks = [
    ["/index.html", "/"],
    ["/contact.html", "/contact"],
    ["/afir/", "/afir"],
    ["/ghiduri/", "/ghiduri"],
    ["/fonduri-nerambursabile/", "/fonduri-nerambursabile"],
    ["/dr12-vs-dr14/", "/dr12-vs-dr14"],
    ["/dr14-afir-ferme-mici/", "/dr14"],
    ["/consultanta-fonduri-europene-imm/", "/consultant-fonduri-europene-imm"],
    ["/consultanta-start-up-nation/", "/consultanta-start-up-nation-2026"],
    ["/pnrr-digitalizare-imm", "/digitalizare-imm-pnrr"],
    ["/blog/safir-fotovoltaice-ferme-2026.html", "/blog-afir-fotovoltaice-ferme-2026"],
    ["/fonduri-europene-bucuresti/", "/fonduri-europene-bucuresti"],
    ["/consultanta-fonduri-europene-bucuresti.html", "/consultanta-fonduri-europene-bucuresti"],
    ["/fonduri-europene-iasi", "/fonduri-europene-nord-est"],
    ["/consultanta-fonduri-europene-bacau", "/fonduri-europene-nord-est"]
  ];

  for (const [from, to] of checks) {
    const response = await fetchManual(`${baseUrl}${from}`);
    assert.equal(response.status, 301, `${from} should redirect`);
    const actualLocation = new URL(response.headers.get("location"), SITE_ORIGIN);
    const expectedLocation = new URL(to, SITE_ORIGIN);
    assert.equal(`${actualLocation.pathname}${actualLocation.search}`, `${expectedLocation.pathname}${expectedLocation.search}`, `${from} should redirect to ${to}`);
  }

  const gscCanonicalPaths = ["/afir", "/ghiduri", "/fonduri-nerambursabile", "/dr12-vs-dr14", ...INDEXABLE_LOCAL_ROUTES];
  for (const routePath of gscCanonicalPaths) {
    const response = await fetchManual(`${baseUrl}${routePath}`);
    assert.equal(response.status, 200, `${routePath} should return 200 for GSC canonical indexing`);
    assert.match(response.headers.get("x-robots-tag") || "index, follow", /index/i, `${routePath} should be indexable`);
    const html = await response.text();
    assert.match(html, new RegExp(`<link\\s+rel=["']canonical["']\\s+href=["']${SITE_ORIGIN}${routePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i"), `${routePath} should self-canonicalize`);
    assert.match(html, /<meta\s+name=["']robots["']\s+content=["']index,\s*follow["']/i, `${routePath} should expose index, follow robots meta`);
  }

  const legacyHtml = await fetchManual(`${baseUrl}/ro/11.html`);
  assert.equal(legacyHtml.status, 301, "legacy /ro/*.html should normalize in one hop");
  assert.equal(new URL(legacyHtml.headers.get("location"), SITE_ORIGIN).pathname, "/ro/11", "legacy /ro/*.html should drop the extension");
  const fallback = await fetchManual(`${baseUrl}/ro/11`);
  assert.equal(fallback.status, 404, "normalized legacy /ro/* fallback should return 404");
  assert.match(fallback.headers.get("x-robots-tag") || "", /noindex/i, "normalized legacy /ro/* fallback should be noindex");
}

async function assertOfficialGuidesResource(baseUrl) {
  assert(fs.existsSync(path.join(DIST, "_headers")), "dist/_headers missing; build must copy deploy headers");
  assert(fs.existsSync(path.join(DIST, "official-guides.json")), "dist/official-guides.json missing");

  const response = await fetchManual(`${baseUrl}/official-guides.json`);
  assert.equal(response.status, 200, "/official-guides.json should remain available");
  assert.match(response.headers.get("content-type") || "", /^application\/json\b/i, "/official-guides.json should be application/json");
  assert.match(response.headers.get("x-robots-tag") || "", /\bnoindex\b/i, "/official-guides.json should send noindex");
  assert.match(response.headers.get("x-robots-tag") || "", /\bnofollow\b/i, "/official-guides.json should keep nofollow");
  await response.json();
}

async function assertHomepageInteractions(baseUrl) {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });

  try {
    await page.goto(`${baseUrl}/`, { waitUntil: "networkidle" });
    assert.equal(await page.locator("h1").count(), 1, "homepage should have one H1");

    await page.locator("#dropdownBtn").click();
    assert.equal(await page.locator("#dropdownBtn").getAttribute("aria-expanded"), "true", "program menu should open");
    assert.equal(await page.locator("#dropdownPanel.open").count(), 1, "program menu panel should be visible");
    assert.equal(await page.locator("#dropdownPanel a[href]").count(), 13, "program menu should expose 13 program links");
    assert.equal(await page.locator('#dropdownPanel a[href="/pocidif-21"]').count(), 1, "program menu should link PoCIDIF 2.1");

    const internalLinks = await page.$$eval(
      ".nav-links a[href], #dropdownPanel a[href], #mobileMenu a[href], #financing-grid a[href], a.btn-primary[href], a.btn-secondary[href]",
      (links) => [...new Set(links.map((link) => link.getAttribute("href")).filter(Boolean))]
    );

    for (const href of internalLinks) {
      if (href.startsWith("#")) continue;
      if (/^(mailto:|tel:|https?:\/\/)/i.test(href) && !href.startsWith(SITE_ORIGIN)) continue;
      const url = href.startsWith(SITE_ORIGIN) ? new URL(href).pathname : href;
      const response = await fetchManual(`${baseUrl}${url}`);
      assert(response.status < 400, `${href} should resolve below 400`);
    }

    const invalidVisibleButtons = await page.$$eval("button", (buttons) =>
      buttons
        .filter((button) => {
          const style = getComputedStyle(button);
          const visible = style.display !== "none" && style.visibility !== "hidden" && button.offsetParent !== null;
          if (!visible) return false;
          const type = (button.getAttribute("type") || "submit").toLowerCase();
          const hasIntent = Boolean(
            button.id ||
            button.getAttribute("onclick") ||
            button.getAttribute("aria-controls") ||
            button.dataset.beneficiaryFilter ||
            type === "submit"
          );
          return !hasIntent;
        })
        .map((button) => button.textContent.trim() || button.outerHTML.slice(0, 80))
    );
    assert.deepEqual(invalidVisibleButtons, [], "visible buttons should have an actionable intent");

    const gridDisplay = await page.$eval("#financing-grid", (element) => getComputedStyle(element).display);
    assert.equal(gridDisplay, "grid", "program section should use a CSS grid");
    assert.equal(await page.locator("#finantare .carousel-btn, #finantare .card-carousel-btn").count(), 0, "program section should not expose carousel controls");
    const totalProgramCards = await page.locator("#financing-grid .finantare-card").count();
    assert(totalProgramCards >= 10, "program grid should contain program cards");
    const initialVisibleCards = await page.$$eval("#financing-grid .finantare-card", (cards) =>
      cards.filter((card) => !card.hidden && getComputedStyle(card).display !== "none").length
    );
    assert.equal(initialVisibleCards, 3, "program grid should initially show only the first row of 3 cards");
    assert.equal(await page.locator("#financing-toggle").getAttribute("aria-expanded"), "false", "program toggle should start collapsed");

    await page.locator("#financing-toggle").click();
    assert.equal(await page.locator("#financing-toggle").getAttribute("aria-expanded"), "true", "program toggle should expand");
    const expandedVisibleCards = await page.$$eval("#financing-grid .finantare-card", (cards) =>
      cards.filter((card) => !card.hidden && getComputedStyle(card).display !== "none").length
    );
    assert.equal(expandedVisibleCards, totalProgramCards, "expanded program grid should show every card for the active filter");

    await page.locator("#financing-toggle").click();
    assert.equal(await page.locator("#financing-toggle").getAttribute("aria-expanded"), "false", "program toggle should collapse");

    await page.locator('[data-beneficiary-filter="public"]').click();
    const publicVisibleCards = await page.$$eval("#financing-grid .finantare-card", (cards) =>
      cards.filter((card) => !card.hidden && getComputedStyle(card).display !== "none").length
    );
    assert(publicVisibleCards > 0, "public beneficiary filter should show at least one card");
    assert(publicVisibleCards <= 3, "public beneficiary filter should respect collapsed first-row display");
    assert.equal(await page.locator('[data-beneficiary-filter="public"]').getAttribute("aria-pressed"), "true", "public filter should set aria-pressed");

    await page.waitForSelector("#blog-grid article.blog-card .blog-image", { timeout: 6000 });
    const renderedBlogVisuals = await page.$$eval("#blog-grid article.blog-card .blog-image", (images) =>
      images.filter((image) => image.querySelector("svg") || getComputedStyle(image).backgroundImage !== "none").length
    );
    assert(renderedBlogVisuals >= 3, "blog cards should render banner images or visible SVG icons instead of text placeholders");
    const textOnlyBlogIcons = await page.$$eval("#blog-grid .blog-card-icon", (icons) =>
      icons.filter((icon) => !icon.querySelector("svg") && icon.textContent.trim()).map((icon) => icon.textContent.trim())
    );
    assert.deepEqual(textOnlyBlogIcons, [], "blog icon placeholders should not render as raw text labels");

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${baseUrl}/`, { waitUntil: "networkidle" });
    await page.locator("#hamburgerBtn").click();
    assert.equal(await page.locator("#hamburgerBtn").getAttribute("aria-expanded"), "true", "mobile hamburger should open");
    assert.equal(await page.locator("#mobileMenu.open").count(), 1, "mobile menu should have open state");
    assert((await page.locator("#mobileMenu a[href]").count()) >= 12, "mobile menu should expose navigation links");
  } finally {
    await browser.close();
  }
}

async function main() {
  assert(fs.existsSync(path.join(DIST, "index.html")), "dist/index.html missing; run npm run build first");
  const { server, baseUrl } = await createServer();

  try {
    await assertCanonicalRoutes(baseUrl);
    await assertRedirectsAndFallback(baseUrl);
    await assertOfficialGuidesResource(baseUrl);
    await assertHomepageInteractions(baseUrl);
    console.log("Functional navigation checks passed.");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
