#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { sitemapUrls } = require("./sitemap-utils");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const ORIGIN = "https://atelierdeconsultanta.ro";
const LIVE_HOST = "atelierdeconsultanta.ro";
const PAGES = [
  { route: "/", file: "index.html", title: "Consultanță și proiectare fonduri europene | FABER", aliases: ["/index.html"] },
  { route: "/afir-autoconsum-agroalimentar", file: "afir-autoconsum-agroalimentar.html", title: "AFIR Autoconsum 2026: fotovoltaice, stocare, ghid | FABER" },
  { route: "/dr12-afir", file: "dr12-afir/index.html", title: "DR 12 AFIR 2026: eligibilitate și pregătirea dosarului | FABER" },
  { route: "/dr14", file: "dr14/index.html", title: "DR 14 AFIR 2026: ghid final, 50.000 € și depunere | FABER" },
  {
    route: "/investitii-modernizarea-microintreprinderilor-apel-2",
    file: "investitii-modernizarea-microintreprinderilor-apel-2/index.html",
    title: "Modernizarea microîntreprinderilor – Apel 2: ghid final | FABER",
    aliases: [
      "/investitii-modernizarea-microintreprinderilor-apel-2.html",
      "/investitii-modernizarea-microintreprinderilor-apel-2/",
      "/investitii-modernizarea-microintreprinderilor-apel-2/index.html",
      "/por-adr-nord-est",
      "/por-adr-nord-est.html",
      "/por-adr-nord-est/",
      "/por-adr-nord-est/index.html"
    ]
  }
];

function documentSignals(html) {
  const $ = cheerio.load(html, { decodeEntities: false });
  return {
    title: $("title").first().text().trim(),
    description: $("meta[name='description']").attr("content") || "",
    canonical: $("link[rel='canonical']").attr("href") || "",
    robots: $("meta[name='robots']").attr("content") || ""
  };
}

function distFileForPage(page) {
  const candidates = [
    path.join(DIST, page.file),
    page.route === "/" ? path.join(DIST, "index.html") : path.join(DIST, `${page.route.slice(1)}.html`)
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || candidates[0];
}

function compareStatic(page, errors) {
  const sourcePath = path.join(ROOT, page.file);
  const distPath = distFileForPage(page);
  if (!fs.existsSync(sourcePath)) {
    errors.push(`${page.route}: source file missing (${page.file})`);
    return;
  }
  if (!fs.existsSync(distPath)) {
    errors.push(`${page.route}: dist file missing; run npm run build`);
    return;
  }
  const source = documentSignals(fs.readFileSync(sourcePath, "utf8"));
  const built = documentSignals(fs.readFileSync(distPath, "utf8"));
  const canonical = `${ORIGIN}${page.route}`;
  for (const [label, signals] of [["source", source], ["dist", built]]) {
    if (signals.title !== page.title) errors.push(`${page.route}: ${label} title differs: ${signals.title}`);
    if (signals.canonical !== canonical) errors.push(`${page.route}: ${label} canonical differs: ${signals.canonical}`);
    if (!signals.description) errors.push(`${page.route}: ${label} description missing`);
    if (/\bnoindex\b/iu.test(signals.robots)) errors.push(`${page.route}: ${label} is noindex`);
  }
  if (JSON.stringify(source) !== JSON.stringify(built)) errors.push(`${page.route}: repository/build snippet parity failed`);
}

async function fetchManual(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    return await fetch(url, {
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "FABER-priority-url-verifier/2026-07-20" }
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function trace(startUrl) {
  const chain = [];
  let current = new URL(startUrl);
  const seen = new Set();
  for (let hop = 0; hop < 5; hop += 1) {
    if (seen.has(current.href)) return { chain, loop: true };
    seen.add(current.href);
    const response = await fetchManual(current.href);
    const location = response.headers.get("location");
    chain.push({ url: current.href, status: response.status, location });
    if (response.status >= 300 && response.status < 400 && location) {
      current = new URL(location, current);
      continue;
    }
    return { chain, loop: false };
  }
  return { chain, loop: true };
}

function permanent(status) {
  return status === 301 || status === 308;
}

function expectedAliases(page) {
  if (page.aliases) return page.aliases;
  return [`${page.route}.html`, `${page.route}/`, `${page.route}/index.html`];
}

async function verifyLivePage(page, errors) {
  const canonical = `${ORIGIN}${page.route}`;
  const direct = await trace(canonical);
  if (direct.loop || direct.chain.length !== 1 || direct.chain[0].status !== 200) {
    errors.push(`${page.route}: HTTPS canonical must return direct 200 (${JSON.stringify(direct.chain)})`);
  }

  for (const aliasPath of expectedAliases(page)) {
    const alias = await trace(`${ORIGIN}${aliasPath}`);
    const final = alias.chain.at(-1);
    if (alias.loop || alias.chain.length !== 2 || !permanent(alias.chain[0]?.status) || final?.status !== 200 || final?.url !== canonical) {
      errors.push(`${aliasPath}: expected one permanent redirect to ${canonical} (${JSON.stringify(alias.chain)})`);
    }
  }

  const query = "gsc_protocol_test=1";
  const httpStart = `http://${LIVE_HOST}${page.route}?${query}`;
  const httpsExpected = `https://${LIVE_HOST}${page.route}?${query}`;
  const protocol = await trace(httpStart);
  const first = protocol.chain[0];
  const final = protocol.chain.at(-1);
  if (
    protocol.loop ||
    protocol.chain.length !== 2 ||
    !permanent(first?.status) ||
    new URL(first?.location || "", first?.url || httpStart).href !== httpsExpected ||
    final?.url !== httpsExpected ||
    final?.status !== 200
  ) {
    errors.push(`${page.route}: HTTP must use one permanent redirect and preserve path/query (${JSON.stringify(protocol.chain)})`);
  }

  if (direct.chain[0]?.status === 200) {
    const response = await fetch(canonical, { headers: { "user-agent": "FABER-priority-url-verifier/2026-07-20" } });
    const live = documentSignals(await response.text());
    const local = documentSignals(fs.readFileSync(path.join(ROOT, page.file), "utf8"));
    if (JSON.stringify(live) !== JSON.stringify(local)) errors.push(`${page.route}: repository/live snippet parity failed`);
  }
}

async function verifyLegacySearchRedirect(errors) {
  const legacy = await trace(`${ORIGIN}/?s=%7Bsearch_term_string%7D`);
  const first = legacy.chain[0];
  const final = legacy.chain.at(-1);
  if (
    legacy.loop ||
    legacy.chain.length !== 2 ||
    !permanent(first?.status) ||
    new URL(first?.location || "", first?.url || ORIGIN).href !== `${ORIGIN}/` ||
    final?.url !== `${ORIGIN}/` ||
    final?.status !== 200
  ) {
    errors.push(`legacy SearchAction URL must use one permanent redirect to ${ORIGIN}/ without query (${JSON.stringify(legacy.chain)})`);
  }
}

async function main() {
  const live = process.argv.includes("--live");
  const errors = [];
  if (!fs.existsSync(DIST)) errors.push("dist is missing; run npm run build");
  else for (const page of PAGES) compareStatic(page, errors);

  const sitemap = new Set(fs.existsSync(path.join(ROOT, "sitemap.xml")) ? sitemapUrls(ROOT) : []);
  for (const page of PAGES) {
    const canonical = `${ORIGIN}${page.route}`;
    if (!sitemap.has(canonical)) errors.push(`${page.route}: canonical missing from sitemap`);
  }

  if (live) {
    for (const page of PAGES) {
      try {
        await verifyLivePage(page, errors);
      } catch (error) {
        errors.push(`${page.route}: live verification error: ${error.message}`);
      }
    }
    try {
      await verifyLegacySearchRedirect(errors);
    } catch (error) {
      errors.push(`legacy SearchAction URL: live verification error: ${error.message}`);
    }
  }

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`Priority URL matrix valid for ${PAGES.length} pages (${live ? "repository/build/live" : "repository/build"}).`);
}

main();
