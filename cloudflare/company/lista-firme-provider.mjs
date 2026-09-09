"use strict";

import { mapCaenToRev3 } from "./caen-rev3-mapper.mjs";
import { requireValidRomanianCui } from "./cui.mjs";

export const LISTAFIRME_INFO_ENDPOINT = "https://listafirme.ro/api/info-v3.asp";

export class CompanyNotFoundError extends Error {
  constructor(message = "Company not found") {
    super(message);
    this.name = "CompanyNotFoundError";
    this.code = "company_not_found";
  }
}

export class CompanyProviderUnavailableError extends Error {
  constructor(message = "Company provider unavailable") {
    super(message);
    this.name = "CompanyProviderUnavailableError";
    this.code = "provider_unavailable";
  }
}

export function numberOrNull(value) {
  if (value === null || typeof value === "undefined" || value === "") return null;
  const normalized = typeof value === "string" ? value.trim() : value;
  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function dateOrNull(value) {
  const raw = String(value ?? "").trim().replaceAll("/", "-");
  const match = raw.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/u);
  if (!match) return null;
  return `${match[1]}-${match[2].padStart(2, "0")}-${match[3].padStart(2, "0")}`;
}

function balanceForYear(balance, year) {
  if (!Array.isArray(balance)) return null;
  return balance.find((entry) => Number(entry?.Year) === year) || null;
}

function financialYear(balance, year) {
  const source = balanceForYear(balance, year);
  if (!source) {
    return year === 2025
      ? { turnover: null, netProfit: null, employees: null, fixedAssets: null, currentAssets: null, totalAssets: null, totalDebts: null }
      : { turnover: null };
  }
  const turnover = numberOrNull(source.Turnover);
  if (year !== 2025) return { turnover };

  const fixedAssets = numberOrNull(source.FixedAssets);
  const currentAssets = numberOrNull(source.CurrentAssets);
  const totalAssets = fixedAssets !== null && currentAssets !== null
    ? fixedAssets + currentAssets
    : null;
  return {
    turnover,
    netProfit: numberOrNull(source.NetProfit),
    employees: numberOrNull(source.Employees),
    fixedAssets,
    currentAssets,
    totalAssets,
    totalDebts: numberOrNull(source.Debts)
  };
}

function requestedNace(raw) {
  if (raw?.NACE && typeof raw.NACE === "object") {
    return {
      code: raw.NACE.Code,
      description: raw.NACE.DescriptionRO || raw.NACE.Description || null,
      revision: raw.NACERev
    };
  }
  const principal = Array.isArray(raw?.PrincipalNACE) ? raw.PrincipalNACE[0] : null;
  return {
    code: raw?.NACE || principal?.Code || null,
    description: null,
    revision: raw?.NACERev || principal?.Rev || null
  };
}

function availableFields(data) {
  const fields = [];
  const add = (path, value) => {
    if (value !== null && value !== "" && typeof value !== "undefined") fields.push(path);
  };
  add("name", data.name);
  add("establishedAt", data.establishedAt);
  add("primaryCaen.code", data.primaryCaen.code);
  add("primaryCaen.description", data.primaryCaen.description);
  add("primaryCaen.rev3Code", data.primaryCaen.rev3Code);
  add("registeredOffice.county", data.registeredOffice.county);
  add("registeredOffice.city", data.registeredOffice.city);
  add("status", data.status);
  add("legalForm", data.legalForm);
  for (const year of [2023, 2024, 2025]) {
    for (const [field, value] of Object.entries(data.financials[year])) add(`financials.${year}.${field}`, value);
  }
  return fields;
}

export function normalizeListaFirmeResponse(raw, cui, fetchedAt = new Date().toISOString()) {
  if (!raw || typeof raw !== "object") throw new CompanyProviderUnavailableError();
  if (raw.errorCode || raw.error) {
    if (raw.errorCode === "TAX_CODE_NOT_FOUND" || /tax code not found/iu.test(raw.error || "")) {
      throw new CompanyNotFoundError();
    }
    throw new CompanyProviderUnavailableError();
  }
  if (!raw.Name && !raw.TaxCode) throw new CompanyNotFoundError();

  const nace = requestedNace(raw);
  const rev3 = mapCaenToRev3(nace);
  const data = {
    name: raw.Name ? String(raw.Name).trim() : null,
    cui: requireValidRomanianCui(raw.TaxCode || cui),
    establishedAt: dateOrNull(raw.Date),
    primaryCaen: {
      code: nace.code ? String(nace.code).trim() : null,
      description: nace.description ? String(nace.description).trim() : null,
      revision: nace.revision ? String(nace.revision).trim() : null,
      rev3Code: rev3.code,
      requiresRev3Confirmation: rev3.requiresConfirmation
    },
    registeredOffice: {
      county: raw.County ? String(raw.County).trim() : null,
      city: raw.City ? String(raw.City).trim() : null
    },
    status: raw.Status ? String(raw.Status).trim() : (raw.Inactive === true ? "inactivă" : null),
    legalForm: raw.LegalForm ? String(raw.LegalForm).trim() : null,
    financials: {
      2023: financialYear(raw.Balance, 2023),
      2024: financialYear(raw.Balance, 2024),
      2025: financialYear(raw.Balance, 2025)
    }
  };
  return {
    data,
    source: "ListaFirme",
    fetchedAt,
    cui: data.cui,
    fieldsAvailable: availableFields(data)
  };
}

function requestPayload(cui) {
  return {
    TaxCode: cui,
    Name: "",
    Status: "",
    LegalForm: "",
    NACE: "info",
    PrincipalNACE: "",
    Date: "",
    County: "",
    City: "",
    Inactive: "",
    Balance: ""
  };
}

export async function fetchCompanyFromListaFirme(cuiValue, options = {}) {
  const cui = requireValidRomanianCui(cuiValue);
  const apiKey = String(options.apiKey || "").trim();
  if (!apiKey) throw new CompanyProviderUnavailableError("ListaFirme API key is not configured");
  const fetchImpl = options.fetchImpl || fetch;
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const body = new URLSearchParams({ key: apiKey, data: JSON.stringify(requestPayload(cui)) });

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await fetchImpl(LISTAFIRME_INFO_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body,
        signal: options.signal || AbortSignal.timeout(30_000)
      });
      if (!response.ok) throw new CompanyProviderUnavailableError();
      const raw = await response.json();
      if (raw?.errorCode === "API_BUSY_RETRY" && attempt < 2) {
        const delay = options.retryDelay || ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
        await delay(150 * (2 ** attempt));
        continue;
      }
      return normalizeListaFirmeResponse(raw, cui, now.toISOString());
    } catch (error) {
      if (error instanceof CompanyNotFoundError || error instanceof CompanyProviderUnavailableError) throw error;
      throw new CompanyProviderUnavailableError();
    }
  }
  throw new CompanyProviderUnavailableError();
}
