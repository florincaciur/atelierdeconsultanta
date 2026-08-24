#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE = "https://atelierdeconsultanta.ro";
const notFoundHtml = fs.readFileSync(path.join(ROOT, "404.html"), "utf8");
const $ = cheerio.load(notFoundHtml, { decodeEntities: false });

assert.equal($("link[rel~='canonical']").length, 0, "documentul 404 nu trebuie să declare canonical");
const robots = $("meta[name='robots']").attr("content") || "";
assert.match(robots, /\bnoindex\b/iu, "documentul 404 trebuie să rămână noindex");
assert.match(robots, /\bfollow\b/iu, "navigația utilă din documentul 404 trebuie să poată fi urmărită");
assert.doesNotMatch(robots, /\bnofollow\b/iu, "documentul 404 nu trebuie să blocheze navigația utilă");
assert.equal($("h1").length, 1, "documentul 404 trebuie să aibă un singur H1");
assert.ok($("main a[href]").length > 0, "documentul 404 trebuie să ofere navigație utilă");

const wrangler = JSON.parse(fs.readFileSync(path.join(ROOT, "wrangler.jsonc"), "utf8"));
assert.equal(wrangler.assets?.not_found_handling, "404-page", "Cloudflare assets trebuie să folosească fallback 404, nu SPA 200");

const rules = fs.readFileSync(path.join(ROOT, "_redirects"), "utf8")
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .map((line) => {
    const [source, destination, status = "302"] = line.split(/\s+/u);
    return { source, destination, status: Number(status) };
  });
assert.ok(rules.length > 0, "graful de redirect nu poate fi gol");
assert.equal(new Set(rules.map((rule) => rule.source)).size, rules.length, "sursele de redirect trebuie să fie unice");
for (const rule of rules) assert.equal(rule.status, 301, `${rule.source}: mutările publice trebuie să fie permanente`);
assert.equal(rules.some((rule) => rule.source === "/*" && new URL(rule.destination, SITE).pathname === "/"), false, "fallback-ul global 404 către homepage este interzis");

async function origin404(request) {
  return new Response(request.method === "HEAD" ? null : notFoundHtml, {
    status: 404,
    headers: { "content-type": "text/html; charset=utf-8" }
  });
}

let direct404OriginUrl = "";
const direct404 = await handleRequest(new Request(`${SITE}/404`), async (request) => {
  direct404OriginUrl = request.url;
  return origin404(request);
});
assert.equal(direct404.status, 404, "/404 trebuie să emită HTTP 404, nu soft-404 200");
assert.equal(direct404.headers.get("location"), null, "/404 nu trebuie redirectat la homepage");
assert.equal(direct404.headers.get("x-robots-tag"), "noindex, follow", "/404 trebuie să aibă X-Robots-Tag coerent cu meta robots");
assert.equal(new URL(direct404OriginUrl).pathname, "/__faber-intentional-not-found__", "/404 trebuie rezolvat prin fallback-ul origin 404");
assert.doesNotMatch(await direct404.text(), /rel=["'][^"']*canonical/iu, "răspunsul /404 nu trebuie să conțină canonical");

let unknownOriginUrl = "";
const unknown = await handleRequest(new Request(`${SITE}/__task10-unknown-route__`), async (request) => {
  unknownOriginUrl = request.url;
  return origin404(request);
});
assert.equal(unknown.status, 404, "o rută necunoscută trebuie să păstreze statusul 404 al origin-ului");
assert.equal(unknown.headers.get("location"), null, "o rută necunoscută nu trebuie redirectată la homepage");
assert.equal(unknown.headers.get("x-robots-tag"), "noindex, follow", "orice 404 trebuie protejat prin X-Robots-Tag");
assert.equal(new URL(unknownOriginUrl).pathname, "/__task10-unknown-route__", "workerul nu trebuie să rescrie o rută necunoscută curată");
assert.doesNotMatch(await unknown.text(), /rel=["'][^"']*canonical/iu, "răspunsul rutei necunoscute nu trebuie să conțină canonical");

const head404 = await handleRequest(new Request(`${SITE}/404`, { method: "HEAD" }), origin404);
assert.equal(head404.status, 404, "HEAD /404 trebuie să emită 404");
assert.equal(await head404.text(), "", "HEAD /404 nu trebuie să emită body");

console.log(`Redirect/404 contract PASS: ${rules.length} permanent rules, real 404 responses and no 404 canonical/homepage fallback.`);
