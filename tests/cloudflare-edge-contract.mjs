import assert from "node:assert/strict";
import fs from "node:fs";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";

const SITE = "https://atelierdeconsultanta.ro";
const PUBLIC_ASSET_CACHE = "public, max-age=86400, must-revalidate";

function assertSecurityHeaders(response, label) {
  assert.equal(response.headers.get("strict-transport-security"), "max-age=15552000", `${label}: HSTS`);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff", `${label}: nosniff`);
  assert.equal(response.headers.get("referrer-policy"), "strict-origin-when-cross-origin", `${label}: referrer policy`);
  assert.equal(response.headers.get("x-frame-options"), "SAMEORIGIN", `${label}: frame policy`);
}

const publicAsset = await handleRequest(new Request(`${SITE}/assets/home.min.css`), async () => new Response("body{}", {
  headers: {
    "content-type": "text/css",
    "cache-control": PUBLIC_ASSET_CACHE
  }
}));
assert.equal(publicAsset.headers.get("cache-control"), PUBLIC_ASSET_CACHE, "explicit public asset cache policy must survive the domain worker");
assert.equal(publicAsset.headers.get("content-type"), "text/css", "origin MIME type must survive the domain worker");
assertSecurityHeaders(publicAsset, "public asset");

const publicHtml = await handleRequest(new Request(`${SITE}/contact`), async () => new Response("<!doctype html>", {
  headers: {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "public, max-age=0, must-revalidate"
  }
}));
assert.equal(publicHtml.headers.get("cache-control"), "public, max-age=0, must-revalidate", "public HTML revalidation policy must survive the domain worker");
assertSecurityHeaders(publicHtml, "public HTML");

const generatedWithoutPolicy = await handleRequest(new Request(`${SITE}/generated`), async () => new Response("generated"));
assert.equal(generatedWithoutPolicy.headers.get("cache-control"), "no-store", "responses without an explicit cache policy must fail closed");

const personalized = await handleRequest(new Request(`${SITE}/account`), async () => new Response("personalized", {
  headers: {
    "cache-control": "public, max-age=86400",
    "set-cookie": "session=private; Secure; HttpOnly"
  }
}));
assert.equal(personalized.headers.get("cache-control"), "no-store", "Set-Cookie responses must never preserve a public cache policy");

const authorized = await handleRequest(new Request(`${SITE}/account`, {
  headers: { authorization: "Bearer test" }
}), async () => new Response("authorized", {
  headers: { "cache-control": "public, max-age=86400" }
}));
assert.equal(authorized.headers.get("cache-control"), "no-store", "authorized requests must never preserve a public cache policy");

const posted = await handleRequest(new Request(`${SITE}/legacy-form`, {
  method: "POST",
  body: "field=value",
  headers: { "content-type": "application/x-www-form-urlencoded" }
}), async () => new Response("accepted", {
  headers: { "cache-control": "public, max-age=86400" }
}));
assert.equal(posted.headers.get("cache-control"), "no-store", "non-GET origin responses must never preserve a public cache policy");

const missing = await handleRequest(new Request(`${SITE}/missing`), async () => new Response("not found", {
  status: 404,
  headers: { "cache-control": "public, max-age=180" }
}));
assert.equal(missing.headers.get("cache-control"), "no-store", "404 responses must not be cached by the browser");
assert.equal(missing.headers.get("x-robots-tag"), "noindex, follow", "404 responses must remain non-indexable");

const api = await handleRequest(new Request(`${SITE}/api/contact-triage`), async () => {
  throw new Error("API request must not reach the static origin");
});
assert.equal(api.status, 405);
assert.equal(api.headers.get("cache-control"), "no-store", "form API responses must never be cached");
assertSecurityHeaders(api, "form API");

const redirect = await handleRequest(new Request("http://www.atelierdeconsultanta.ro/dr12-afir/"), async () => {
  throw new Error("redirect must not reach the static origin");
});
assert.equal(redirect.status, 301);
assert.equal(redirect.headers.get("location"), `${SITE}/dr12-afir`);
assert.equal(redirect.headers.get("cache-control"), "public, max-age=3600", "permanent canonical redirects remain cacheable");
assertSecurityHeaders(redirect, "canonical redirect");

const headersFile = fs.readFileSync(new URL("../_headers", import.meta.url), "utf8");
assert.match(headersFile, /\/assets\/\*[\s\S]*?Cache-Control: public, max-age=86400, must-revalidate/u, "mutable named assets need a bounded revalidation policy");
assert.doesNotMatch(headersFile, /Cache-Control:\s*public[^\r\n]*immutable/iu, "non-content-addressed public files must not be immutable for one year");
assert.match(headersFile, /\/robots\.txt[\s\S]*?Cache-Control: public, max-age=3600/u);
assert.match(headersFile, /\/sitemap\.xml[\s\S]*?Cache-Control: public, max-age=3600/u);
assert.match(headersFile, /\/release\.json[\s\S]*?Cache-Control: no-store/u);

const domainConfig = JSON.parse(fs.readFileSync(new URL("../wrangler.redirects.jsonc", import.meta.url), "utf8"));
assert.equal(domainConfig.workers_dev, false, "domain middleware must not expose an unmanaged workers.dev route");
assert.deepEqual(new Set(domainConfig.routes.map((route) => route.pattern)), new Set([
  "atelierdeconsultanta.ro/*",
  "www.atelierdeconsultanta.ro/*"
]));

const staticConfig = JSON.parse(fs.readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
assert.equal(staticConfig.assets.html_handling, "drop-trailing-slash");
assert.equal(staticConfig.assets.not_found_handling, "404-page");

console.log("Cloudflare edge cache/security contract passed.");
