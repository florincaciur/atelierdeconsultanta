#!/usr/bin/env node
"use strict";

const {
  LEGACY_ROUTES,
  destinationPath,
  localCanonicalAudit,
  parseRedirects,
  redirectFor,
  traceRedirect
} = require("./verify-canonical-map");

const REQUIRED_REDIRECTS = new Map([
  ["/dr12-afir.html", "/dr12-afir"],
  ["/dr12-afir/index.html", "/dr12-afir"],
  ["/dr12-afir-tineri-fermieri", "/dr12-afir"],
  ["/dr12-afir-tineri-fermieri/", "/dr12-afir"],
  ["/dr12-afir-tineri-fermieri.html", "/dr12-afir"],
  ["/dr12-afir-tineri-fermieri/index.html", "/dr12-afir"],
  ["/dr14.html", "/dr14"],
  ["/dr14/index.html", "/dr14"],
  ["/dr14-afir-ferme-mici", "/dr14"],
  ["/dr14-afir-ferme-mici/", "/dr14"],
  ["/dr14-afir-ferme-mici.html", "/dr14"],
  ["/dr14-afir-ferme-mici/index.html", "/dr14"],
  ["/por-adr-nord-est.html", "/por-adr-nord-est"],
  ["/afir-autoconsum-agroalimentar.html", "/afir-autoconsum-agroalimentar"],
  ["/fonduri-europene-herambursabile-2026", "/fonduri-europene-nerambursabile-2026"],
  ["/fonduri-europene-herambursabile-2026/", "/fonduri-europene-nerambursabile-2026"],
  ["/fonduri-europene-herambursabile-2026.html", "/fonduri-europene-nerambursabile-2026"],
  ["/fonduri-europene-herambursabile-2026/index.html", "/fonduri-europene-nerambursabile-2026"],
  ["/start-up-nation", "/start-up-nation-2026"],
  ["/start-up-nation/", "/start-up-nation-2026"],
  ["/start-up-nation.html", "/start-up-nation-2026"],
  ["/start-up-nation/index.html", "/start-up-nation-2026"],
  ["/consultanta-start-up-nation", "/consultanta-start-up-nation-2026"],
  ["/consultanta-start-up-nation/", "/consultanta-start-up-nation-2026"],
  ["/consultanta-start-up-nation.html", "/consultanta-start-up-nation-2026"],
  ["/consultanta-start-up-nation/index.html", "/consultanta-start-up-nation-2026"],
  ["/studii-de-caz", "/studii-de-caz-fonduri-europene"],
  ["/studii-de-caz/", "/studii-de-caz-fonduri-europene"],
  ["/studii-de-caz.html", "/studii-de-caz-fonduri-europene"],
  ["/studii-de-caz/index.html", "/studii-de-caz-fonduri-europene"]
]);

function main() {
  const problems = [];
  const redirects = parseRedirects();
  const state = localCanonicalAudit();
  const staticSources = new Map();

  for (const rule of redirects) {
    if (rule.status !== 301) problems.push(`Redirect is not permanent: line ${rule.line} ${rule.raw}`);
    if (!rule.dynamic) {
      if (staticSources.has(rule.source)) problems.push(`Duplicate redirect source: ${rule.source} on lines ${staticSources.get(rule.source)} and ${rule.line}`);
      staticSources.set(rule.source, rule.line);
    }
  }

  for (const [source, target] of REQUIRED_REDIRECTS) {
    const first = redirectFor(source, redirects);
    const trace = traceRedirect(source, redirects);
    if (!first) {
      problems.push(`Missing required redirect: ${source} -> ${target}`);
      continue;
    }
    if (first.status !== 301) problems.push(`Required redirect is not 301: ${source}`);
    if (trace.loop) problems.push(`Redirect loop: ${source}`);
    if (trace.chain.length !== 1 || trace.finalPath !== target) {
      problems.push(`Redirect is not direct: ${source} -> ${trace.chain.map((rule) => destinationPath(rule.resolvedDestination)).join(" -> ")} (expected ${target})`);
    }
  }

  for (const rule of redirects.filter((item) => !item.dynamic)) {
    const trace = traceRedirect(rule.source, redirects);
    if (trace.loop) problems.push(`Redirect loop: ${rule.source}`);
    if (trace.chain.length > 1) problems.push(`Redirect chain (${trace.chain.length} hops): ${rule.source} -> ${trace.finalPath}`);
  }

  for (const url of state.urls) {
    const pathname = new URL(url).pathname;
    if (pathname === "/") continue;
    const variants = [`${pathname}.html`, `${pathname}/`, `${pathname}/index.html`];
    for (const variant of variants) {
      const trace = traceRedirect(variant, redirects);
      if (trace.loop) problems.push(`Normalizer loop: ${variant}`);
      if (trace.chain.length !== 1 || trace.finalPath !== pathname) {
        problems.push(`Normalizer is not one hop: ${variant} -> ${trace.finalPath} (${trace.chain.length} hops)`);
      }
    }
  }

  const supportTrace = traceRedirect("/dr-12-afir-instalarea-tinerilor-fermieri", redirects);
  if (supportTrace.chain.length || supportTrace.loop) problems.push("Distinct DR12 support article must not redirect");
  for (const route of LEGACY_ROUTES) {
    if (!redirectFor(route, redirects)) problems.push(`Legacy folder has no direct redirect: ${route}`);
  }

  for (const problem of state.problems) {
    if (/Internal link points to redirect|Redirect source in sitemap|Canonical points to redirect/.test(problem)) problems.push(problem);
  }

  if (problems.length) {
    console.error(`Redirect verification failed (${problems.length}):`);
    for (const problem of [...new Set(problems)]) console.error(`- ${problem}`);
    process.exit(1);
  }
  console.log(`Redirect verification PASS: ${redirects.length} rules, ${REQUIRED_REDIRECTS.size} required mappings, 0 chains, 0 loops, 0 internal links to redirects.`);
}

main();
