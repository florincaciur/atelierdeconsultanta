(function (scope) {
  "use strict";

  const CONTROL_WEIGHTS = "753217532";
  const AUTO_FIELD_NAMES = Object.freeze([
    "caen",
    "establishedAt",
    "headquartersCounty",
    "employees2025",
    "netProfit2025",
    "turnover2023",
    "turnover2024",
    "turnover2025",
    "assets2025",
    "debts2025"
  ]);
  const COUNTY_CODES = Object.freeze({
    bacau: "bc",
    botosani: "bt",
    iasi: "is",
    neamt: "nt",
    suceava: "sv",
    vaslui: "vs"
  });

  function normalizeCui(value) {
    if (typeof value !== "string" && typeof value !== "number") return "";
    const compact = String(value).trim().replace(/\s+/gu, "");
    const withoutPrefix = compact.replace(/^RO/iu, "");
    return /^\d+$/u.test(withoutPrefix) ? withoutPrefix : "";
  }

  function isValidCui(value) {
    const cui = normalizeCui(value);
    if (!/^\d{2,10}$/u.test(cui) || cui.startsWith("0")) return false;
    const base = cui.slice(0, -1).padStart(CONTROL_WEIGHTS.length, "0");
    let sum = 0;
    for (let index = 0; index < CONTROL_WEIGHTS.length; index += 1) {
      sum += Number(base[index]) * Number(CONTROL_WEIGHTS[index]);
    }
    const remainder = (sum * 10) % 11;
    return Number(cui.at(-1)) === (remainder === 10 ? 0 : remainder);
  }

  function numberOrNull(value) {
    if (value === null || value === "" || typeof value === "undefined") return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function countyCode(value) {
    const normalized = String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/gu, "")
      .trim()
      .toLowerCase();
    if (!normalized) return null;
    return COUNTY_CODES[normalized] || "outside";
  }

  function formatNumber(value) {
    const number = numberOrNull(value);
    return number === null ? "—" : new Intl.NumberFormat("ro-RO", { maximumFractionDigits: 2 }).format(number);
  }

  function financialYear(data, year) {
    return data?.financials?.[year] || data?.financials?.[String(year)] || {};
  }

  function setNumber(values, name, value) {
    const number = numberOrNull(value);
    if (number !== null) values[name] = number;
    return number;
  }

  function mapCompanyDataToScoreCalculator(company) {
    const data = company?.data || company || {};
    const year2023 = financialYear(data, 2023);
    const year2024 = financialYear(data, 2024);
    const year2025 = financialYear(data, 2025);
    const values = {};
    const warnings = [];

    if (data.primaryCaen?.rev3Code) values.caen = String(data.primaryCaen.rev3Code);
    else if (data.primaryCaen?.code) warnings.push("Codul CAEN necesită confirmarea încadrării în CAEN Rev. 3.");
    if (/^\d{4}-\d{2}-\d{2}$/u.test(String(data.establishedAt || ""))) values.establishedAt = data.establishedAt;
    const headquartersCounty = countyCode(data.registeredOffice?.county);
    if (headquartersCounty) values.headquartersCounty = headquartersCounty;

    setNumber(values, "employees2025", year2025.employees);
    setNumber(values, "netProfit2025", year2025.netProfit);
    setNumber(values, "turnover2023", year2023.turnover);
    setNumber(values, "turnover2024", year2024.turnover);
    setNumber(values, "turnover2025", year2025.turnover);
    setNumber(values, "debts2025", year2025.totalDebts);

    const fixedAssets = numberOrNull(year2025.fixedAssets);
    const currentAssets = numberOrNull(year2025.currentAssets);
    const totalAssets = fixedAssets !== null && currentAssets !== null
      ? fixedAssets + currentAssets
      : null;
    if (totalAssets !== null) values.assets2025 = totalAssets;
    else warnings.push("Date financiare insuficiente pentru calculul activelor totale.");

    const missingFinancials = [
      year2023.turnover,
      year2024.turnover,
      year2025.turnover,
      year2025.netProfit,
      year2025.employees,
      year2025.totalDebts,
      totalAssets
    ].some(function (value) { return numberOrNull(value) === null; });
    if (missingFinancials) warnings.push("Au fost identificate doar o parte dintre datele financiare. Completați manual câmpurile lipsă.");

    return {
      values: values,
      autoFields: Object.keys(values).filter(function (name) { return AUTO_FIELD_NAMES.includes(name); }),
      warnings: Array.from(new Set(warnings)),
      computed: { totalAssets: totalAssets }
    };
  }

  function CompanyLookupError(code, message) {
    const error = /** @type {Error & {code: string}} */ (new Error(message));
    error.name = "CompanyLookupError";
    error.code = code;
    return error;
  }

  async function lookupCompany(cuiValue, options) {
    const settings = options || {};
    const cui = normalizeCui(cuiValue);
    if (!isValidCui(cui)) throw CompanyLookupError("invalid_cui", "Introduceți un CUI românesc valid.");
    const fetchImpl = settings.fetchImpl || scope.fetch;
    let response;
    try {
      response = await fetchImpl(`/api/company/${encodeURIComponent(cui)}`, {
        method: "GET",
        headers: { accept: "application/json", "x-requested-with": "fetch" }
      });
    } catch {
      throw CompanyLookupError("provider_unavailable", "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual.");
    }
    let payload = {};
    try { payload = await response.json(); } catch { payload = {}; }
    if (!response.ok) {
      const code = payload.error || (response.status === 404 ? "company_not_found" : "provider_unavailable");
      const fallback = code === "company_not_found"
        ? "Nu am identificat o societate pentru CUI-ul introdus. Verificați CUI-ul și încercați din nou."
        : "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual.";
      throw CompanyLookupError(code, payload.message || fallback);
    }
    return payload;
  }

  const api = Object.freeze({
    AUTO_FIELD_NAMES: AUTO_FIELD_NAMES,
    formatNumber: formatNumber,
    isValidCui: isValidCui,
    lookupCompany: lookupCompany,
    mapCompanyDataToScoreCalculator: mapCompanyDataToScoreCalculator,
    normalizeCui: normalizeCui
  });

  scope.CompanyDataService = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
}(typeof window !== "undefined" ? window : globalThis));
