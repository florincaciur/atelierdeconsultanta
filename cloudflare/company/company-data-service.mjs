"use strict";

import { isValidRomanianCui, normalizeRomanianCui, requireValidRomanianCui } from "./cui.mjs";
import {
  CompanyNotFoundError,
  CompanyProviderUnavailableError,
  fetchCompanyFromListaFirme
} from "./lista-firme-provider.mjs";

export const COMPANY_CACHE_TTL_SECONDS = 24 * 60 * 60;

export function companyCacheKey(cui) {
  return `company:${cui}`;
}

function cacheRequest(cui) {
  return new Request(`https://company-cache.internal/${encodeURIComponent(companyCacheKey(cui))}`);
}

function defaultCache() {
  if (typeof caches === "undefined") return null;
  const cloudflareCaches = /** @type {CacheStorage & {default?: Cache}} */ (caches);
  return cloudflareCaches.default || null;
}

async function cachedCompany(cache, cui) {
  if (!cache) return null;
  try {
    const response = await cache.match(cacheRequest(cui));
    if (!response) return null;
    return await response.json();
  } catch {
    return null;
  }
}

async function storeCompany(cache, cui, payload) {
  if (!cache) return;
  try {
    await cache.put(cacheRequest(cui), new Response(JSON.stringify(payload), {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": `public, max-age=${COMPANY_CACHE_TTL_SECONDS}`
      }
    }));
  } catch {
    // Cache-ul este o optimizare. O eroare de stocare nu invalidează datele
    // tocmai primite de la provider și nu trebuie să blocheze formularul.
  }
}

export async function getCompanyData(cuiValue, options = {}) {
  const cui = requireValidRomanianCui(cuiValue);
  const cache = options.cache === undefined ? defaultCache() : options.cache;
  if (!options.forceRefresh) {
    const cached = await cachedCompany(cache, cui);
    if (cached) return cached;
  }

  const provider = options.provider || fetchCompanyFromListaFirme;
  const payload = await provider(cui, options);
  await storeCompany(cache, cui, payload);
  return payload;
}

function jsonResponse(status, payload, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function routeCui(pathname) {
  const match = pathname.match(/^\/api\/company\/([^/]+)$/u);
  if (!match) return "";
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return "";
  }
}

export async function handleCompanyLookupRequest(request, options = {}) {
  if (request.method !== "GET") {
    return jsonResponse(405, { error: "method_not_allowed" }, { allow: "GET" });
  }

  const rawCui = routeCui(new URL(request.url).pathname);
  const cui = normalizeRomanianCui(rawCui);
  if (!isValidRomanianCui(cui)) {
    return jsonResponse(400, {
      error: "invalid_cui",
      message: "Introduceți un CUI românesc valid."
    });
  }

  const rateLimiter = options.rateLimiter;
  if (rateLimiter?.limit) {
    const actor = request.headers.get("cf-connecting-ip") || "anonymous";
    try {
      const result = await rateLimiter.limit({ key: `company-lookup:${actor}` });
      if (!result.success) {
        return jsonResponse(429, {
          error: "rate_limited",
          message: "Prea multe verificări într-un interval scurt. Încercați din nou în câteva momente."
        }, { "retry-after": "60" });
      }
    } catch {
      return jsonResponse(503, {
        error: "provider_unavailable",
        message: "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual."
      });
    }
  }

  try {
    const payload = await getCompanyData(cui, options);
    return jsonResponse(200, payload);
  } catch (error) {
    if (error instanceof CompanyNotFoundError || error?.code === "company_not_found") {
      return jsonResponse(404, {
        error: "company_not_found",
        message: "Nu am identificat o societate pentru CUI-ul introdus. Verificați CUI-ul și încercați din nou."
      });
    }
    if (error instanceof CompanyProviderUnavailableError || error?.code === "provider_unavailable") {
      return jsonResponse(503, {
        error: "provider_unavailable",
        message: "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual."
      });
    }
    return jsonResponse(503, {
      error: "provider_unavailable",
      message: "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual."
    });
  }
}
