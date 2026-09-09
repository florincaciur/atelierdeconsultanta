import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";
import { mapCaenToRev3 } from "../cloudflare/company/caen-rev3-mapper.mjs";
import {
  isValidRomanianCui,
  normalizeRomanianCui
} from "../cloudflare/company/cui.mjs";
import {
  COMPANY_CACHE_TTL_SECONDS,
  companyCacheKey,
  getCompanyData,
  handleCompanyLookupRequest
} from "../cloudflare/company/company-data-service.mjs";
import {
  fetchCompanyFromListaFirme,
  normalizeListaFirmeResponse
} from "../cloudflare/company/lista-firme-provider.mjs";

const require = createRequire(import.meta.url);
const client = require("../assets/company-data-service.js");
const VALID_CUI = "14837428";
const NOW = new Date("2026-09-07T00:00:00.000Z");

const rawCompany = {
  TaxCode: VALID_CUI,
  Name: "BORG DESIGN SRL",
  Status: "functiune",
  LegalForm: "SRL",
  Date: "2002-08-26",
  County: "BUCURESTI",
  City: "SECTORUL 5",
  NACE: { Code: "6210", DescriptionRO: "Activități de realizare a soft-ului la comandă" },
  NACERev: "3",
  Balance: [
    { Year: "2025", Turnover: "1500000", NetProfit: "120000", Employees: "4", FixedAssets: "400000", CurrentAssets: "600000", Debts: "250000" },
    { Year: "2023", Turnover: "1100000" },
    { Year: "2024", Turnover: "1350000" }
  ]
};

assert.equal(normalizeRomanianCui(` RO ${VALID_CUI} `), VALID_CUI, "RO and whitespace must be normalized");
assert.equal(isValidRomanianCui(VALID_CUI), true, "known Romanian CUI must validate mathematically");
assert.equal(isValidRomanianCui(`RO${VALID_CUI}`), true, "RO-prefixed CUI must validate");
for (const invalid of ["12345678", "FR14837428", "RO", "0", "12345678901"]) {
  assert.equal(isValidRomanianCui(invalid), false, `${invalid}: invalid CUI must be rejected`);
}
assert.equal(client.isValidCui(VALID_CUI), true, "browser and server validators must agree");
assert.equal(client.normalizeCui(` RO ${VALID_CUI} `), VALID_CUI, "browser normalization must remove RO and spaces");

const normalized = normalizeListaFirmeResponse(rawCompany, VALID_CUI, NOW.toISOString());
assert.equal(normalized.source, "ListaFirme");
assert.equal(normalized.fetchedAt, NOW.toISOString());
assert.equal(normalized.cui, VALID_CUI);
assert.equal(normalized.data.primaryCaen.rev3Code, "6210", "Rev. 3 CAEN maps directly");
assert.equal(normalized.data.financials[2023].turnover, 1100000, "2023 turnover maps by explicit Year");
assert.equal(normalized.data.financials[2024].turnover, 1350000, "2024 turnover maps by explicit Year");
assert.equal(normalized.data.financials[2025].turnover, 1500000, "2025 turnover maps by explicit Year");
assert.equal(normalized.data.financials[2025].netProfit, 120000, "2025 profit maps to number");
assert.equal(normalized.data.financials[2025].employees, 4, "2025 employees map to number");
assert.equal(normalized.data.financials[2025].totalDebts, 250000, "2025 debts map to number");
assert.equal(normalized.data.financials[2025].totalAssets, 1000000, "totalAssets = fixedAssets + currentAssets");
assert.ok(normalized.fieldsAvailable.includes("financials.2025.totalAssets"), "provenance lists calculated total assets");

const noFixed = normalizeListaFirmeResponse({
  ...rawCompany,
  Balance: rawCompany.Balance.map((entry) => entry.Year === "2025" ? { ...entry, FixedAssets: undefined } : entry)
}, VALID_CUI, NOW.toISOString());
assert.equal(noFixed.data.financials[2025].totalAssets, null, "missing fixed assets must leave total assets null");
const noCurrent = normalizeListaFirmeResponse({
  ...rawCompany,
  Balance: rawCompany.Balance.map((entry) => entry.Year === "2025" ? { ...entry, CurrentAssets: undefined } : entry)
}, VALID_CUI, NOW.toISOString());
assert.equal(noCurrent.data.financials[2025].totalAssets, null, "missing current assets must leave total assets null");

assert.deepEqual(mapCaenToRev3({ code: "6201", revision: "2" }), {
  code: null,
  originalCode: "6201",
  originalRevision: "2",
  requiresConfirmation: true
}, "Rev. 2 CAEN without an official one-to-one mapping must remain manual");
assert.equal(mapCaenToRev3({ code: "6201", revision: "2" }, { 6201: ["6210"] }).code, "6210", "separate correspondence adapter supports a future official one-to-one map");
assert.equal(mapCaenToRev3({ code: "6201", revision: "2" }, { 6201: ["6210", "6220"] }).code, null, "ambiguous CAEN mapping must not choose arbitrarily");

const clientMapping = client.mapCompanyDataToScoreCalculator(normalized);
assert.deepEqual(clientMapping.values, {
  caen: "6210",
  establishedAt: "2002-08-26",
  headquartersCounty: "outside",
  employees2025: 4,
  netProfit2025: 120000,
  turnover2023: 1100000,
  turnover2024: 1350000,
  turnover2025: 1500000,
  debts2025: 250000,
  assets2025: 1000000
}, "only public scoring fields are mapped");
for (const protectedField of ["grant", "ownContribution", "implementationCounty", "newJobs", "disadvantagedHire", "microenterprise", "activityHistory", "fixedAssets", "deMinimis", "siteRights", "annexes", "cashFlow"]) {
  assert.equal(Object.hasOwn(clientMapping.values, protectedField), false, `${protectedField} must remain user-controlled`);
}
const clientMissingAssets = client.mapCompanyDataToScoreCalculator(noCurrent);
assert.equal(Object.hasOwn(clientMissingAssets.values, "assets2025"), false);
assert.ok(clientMissingAssets.warnings.includes("Date financiare insuficiente pentru calculul activelor totale."));

let providerCalls = 0;
const providerPayload = await fetchCompanyFromListaFirme(VALID_CUI, {
  apiKey: "server-secret",
  now: NOW,
  fetchImpl: async (url, request) => {
    providerCalls += 1;
    assert.equal(url, "https://listafirme.ro/api/info-v3.asp", "provider endpoint is fixed and cannot be proxied");
    assert.equal(request.method, "POST");
    const body = new URLSearchParams(request.body);
    assert.equal(body.get("key"), "server-secret");
    const requested = JSON.parse(body.get("data"));
    assert.equal(requested.TaxCode, VALID_CUI);
    assert.equal(requested.Balance, "", "all balance years are explicitly requested");
    return Response.json(rawCompany);
  }
});
assert.equal(providerPayload.data.financials[2025].totalAssets, 1000000);
assert.equal(JSON.stringify(providerPayload).includes("server-secret"), false, "API key must never reach the browser response");

function memoryCache() {
  const entries = new Map();
  return {
    entries,
    async match(request) { return entries.get(request.url)?.clone() || null; },
    async put(request, response) { entries.set(request.url, response.clone()); }
  };
}

const cache = memoryCache();
providerCalls = 0;
const cachedOptions = {
  apiKey: "server-secret",
  cache,
  now: NOW,
  fetchImpl: async () => { providerCalls += 1; return Response.json(rawCompany); }
};
await getCompanyData(VALID_CUI, cachedOptions);
await getCompanyData(VALID_CUI, cachedOptions);
assert.equal(providerCalls, 1, "24-hour cache must prevent duplicate upstream calls");
await getCompanyData(VALID_CUI, { ...cachedOptions, forceRefresh: true });
assert.equal(providerCalls, 2, "forceRefresh remains an internal service option that bypasses cache");
assert.equal(companyCacheKey(VALID_CUI), `company:${VALID_CUI}`);
const cachedResponse = [...cache.entries.values()][0];
assert.equal(cachedResponse.headers.get("cache-control"), `public, max-age=${COMPANY_CACHE_TTL_SECONDS}`);

const cacheFailurePayload = await getCompanyData(VALID_CUI, {
  apiKey: "server-secret",
  cache: {
    async match() { throw new Error("cache read unavailable"); },
    async put() { throw new Error("cache write unavailable"); }
  },
  fetchImpl: async () => Response.json(rawCompany)
});
assert.equal(cacheFailurePayload.cui, VALID_CUI, "cache failures must not block provider data");

let invalidReachedProvider = false;
const invalidResponse = await handleCompanyLookupRequest(new Request("https://atelierdeconsultanta.ro/api/company/12345678"), {
  apiKey: "server-secret",
  cache: null,
  fetchImpl: async () => { invalidReachedProvider = true; return Response.json(rawCompany); }
});
assert.equal(invalidResponse.status, 400);
assert.equal(invalidReachedProvider, false, "invalid CUI must be rejected server-side before provider access");

const malformedPathResponse = await handleCompanyLookupRequest(new Request("https://atelierdeconsultanta.ro/api/company/%E0%A4%A"));
assert.equal(malformedPathResponse.status, 400, "malformed URL encoding must be rejected without crashing the Worker");

const missingResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`), {
  apiKey: "server-secret",
  cache: null,
  fetchImpl: async () => Response.json({ errorCode: "TAX_CODE_NOT_FOUND", error: "Tax code not found" })
});
assert.equal(missingResponse.status, 404, "unknown company must return 404");
assert.equal((await missingResponse.json()).error, "company_not_found");

const unavailableResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`), {
  apiKey: "server-secret",
  cache: null,
  fetchImpl: async () => { throw new Error("upstream down"); }
});
assert.equal(unavailableResponse.status, 503, "ListaFirme failure must preserve manual simulator fallback");

const unconfiguredResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`), { cache: null });
assert.equal(unconfiguredResponse.status, 503, "missing API key must fail closed without breaking the page");

const limitedResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`), {
  rateLimiter: { limit: async () => ({ success: false }) }
});
assert.equal(limitedResponse.status, 429);
assert.equal(limitedResponse.headers.get("retry-after"), "60");

const limiterUnavailableResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`), {
  rateLimiter: { limit: async () => { throw new Error("limiter unavailable"); } }
});
assert.equal(limiterUnavailableResponse.status, 503, "rate limiter failures must return the manual-fallback response instead of crashing");

const methodResponse = await handleCompanyLookupRequest(new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`, { method: "POST" }));
assert.equal(methodResponse.status, 405);

let originCalled = false;
const routedResponse = await handleRequest(
  new Request(`https://atelierdeconsultanta.ro/api/company/${VALID_CUI}`),
  async () => { originCalled = true; return new Response("origin"); },
  {
    LISTAFIRME_API_KEY: "server-secret",
    companyCache: null,
    companyNow: NOW,
    COMPANY_LOOKUP_RATE_LIMITER: { limit: async () => ({ success: true }) },
    listafirmeFetch: async () => Response.json(rawCompany)
  }
);
assert.equal(routedResponse.status, 200, "domain Worker must route company lookup internally");
assert.equal(originCalled, false, "company endpoint must not become an origin proxy");
assert.equal(routedResponse.headers.get("cache-control"), "no-store", "browser API response must never be cached");
assert.equal(routedResponse.headers.get("x-content-type-options"), "nosniff");

console.log("PASS company lookup provider, mapping, security, cache, rate limit and endpoint contract");
