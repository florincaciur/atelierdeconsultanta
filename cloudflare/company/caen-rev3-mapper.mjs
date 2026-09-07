"use strict";

// Nu există în repository un nomenclator oficial Rev. 2 → Rev. 3. Tabelul este
// intenționat gol: o conversie ambiguă trebuie confirmată de utilizator.
export const CAEN_REV2_TO_REV3 = Object.freeze({});

function normalizeCode(value) {
  const digits = String(value ?? "").replace(/\D/gu, "");
  return digits.length === 3 ? `0${digits}` : digits;
}

function normalizeRevision(value) {
  const match = String(value ?? "").match(/[23]/u);
  return match ? match[0] : "";
}

export function mapCaenToRev3({ code, revision }, correspondence = CAEN_REV2_TO_REV3) {
  const originalCode = normalizeCode(code);
  const originalRevision = normalizeRevision(revision);
  if (originalCode.length !== 4) {
    return { code: null, originalCode, originalRevision, requiresConfirmation: true };
  }
  if (originalRevision === "3") {
    return { code: originalCode, originalCode, originalRevision, requiresConfirmation: false };
  }

  const candidates = Array.isArray(correspondence[originalCode])
    ? correspondence[originalCode].map(normalizeCode).filter((entry) => entry.length === 4)
    : [];
  if (candidates.length === 1) {
    return { code: candidates[0], originalCode, originalRevision, requiresConfirmation: false };
  }
  return { code: null, originalCode, originalRevision, requiresConfirmation: true };
}
