"use strict";

const CONTROL_WEIGHTS = "753217532";

export function normalizeRomanianCui(value) {
  if (typeof value !== "string" && typeof value !== "number") return "";
  const compact = String(value).trim().replace(/\s+/gu, "");
  const withoutPrefix = compact.replace(/^RO/iu, "");
  return /^\d+$/u.test(withoutPrefix) ? withoutPrefix : "";
}

export function isValidRomanianCui(value) {
  const cui = normalizeRomanianCui(value);
  if (!/^\d{2,10}$/u.test(cui) || cui.startsWith("0")) return false;

  const suppliedCheckDigit = Number(cui.at(-1));
  const base = cui.slice(0, -1).padStart(CONTROL_WEIGHTS.length, "0");
  let sum = 0;
  for (let index = 0; index < CONTROL_WEIGHTS.length; index += 1) {
    sum += Number(base[index]) * Number(CONTROL_WEIGHTS[index]);
  }

  const remainder = (sum * 10) % 11;
  const expectedCheckDigit = remainder === 10 ? 0 : remainder;
  return suppliedCheckDigit === expectedCheckDigit;
}

export function requireValidRomanianCui(value) {
  const cui = normalizeRomanianCui(value);
  if (!isValidRomanianCui(cui)) {
    const error = /** @type {Error & {code: string}} */ (new Error("CUI invalid"));
    error.code = "invalid_cui";
    throw error;
  }
  return cui;
}
