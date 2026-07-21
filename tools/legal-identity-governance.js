"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG_PATH = path.join(ROOT, "config", "legal-identity.json");
const HUMAN_REVIEW = "DE_VALIDAT_UMAN";
const NOT_APPLICABLE = "NU_SE_APLICA";
const REQUIRED_FIELD_IDS = Object.freeze([
  "brandName",
  "websiteUrl",
  "legalName",
  "legalForm",
  "taxIdentifier",
  "tradeRegisterNumber",
  "registeredOffice",
  "publicWorkplaceAddress",
  "personalDataController",
  "contractingEntity",
  "invoicingEntity",
  "publicPhone",
  "publicEmail",
  "officialProfileUrls",
  "contactHours",
  "serviceArea"
]);
const SURFACES = Object.freeze([
  "footer",
  "contact",
  "about",
  "terms",
  "privacy",
  "automated_emails",
  "contracts_invoices",
  "jsonld_organization",
  "jsonld_professional_service",
  "google_business_profile",
  "bing_places"
]);
const FIELD_STATES = Object.freeze(["pending", "approved", "revoked", "not_applicable"]);
const NOT_APPLICABLE_FIELDS = new Set(["tradeRegisterNumber", "publicWorkplaceAddress", "officialProfileUrls"]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function isIsoDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/u.test(String(value || ""))
    && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function missing(value) {
  if (Array.isArray(value)) return !value.length || value.some((item) => missing(item));
  return !String(value ?? "").trim() || String(value).includes(HUMAN_REVIEW);
}

function fieldApproved(field) {
  if (!field) return false;
  if (field.status === "not_applicable") {
    return field.approvedValue === NOT_APPLICABLE
      && !missing(field.internalSource)
      && !missing(field.approvedBy)
      && isIsoDate(field.approvedAt);
  }
  return field.status === "approved"
    && !missing(field.approvedValue)
    && field.approvedValue !== NOT_APPLICABLE
    && !missing(field.internalSource)
    && !missing(field.approvedBy)
    && isIsoDate(field.approvedAt);
}

function approvalApproved(approval) {
  return approval?.state === "approved"
    && !missing(approval.approvedBy)
    && isIsoDate(approval.approvedAt)
    && !missing(approval.internalSource);
}

function validateField(id, field) {
  const errors = [];
  const where = `fields.${id}`;
  if (!field || typeof field !== "object" || Array.isArray(field)) return [`${where}: câmp invalid`];
  for (const property of ["label", "status", "approvedValue", "candidateValues", "internalSource", "approvedBy", "approvedAt", "surfaces", "notes"]) {
    if (!Object.hasOwn(field, property)) errors.push(`${where}: lipsește ${property}`);
  }
  if (!FIELD_STATES.includes(field.status)) errors.push(`${where}: status invalid (${field.status})`);
  if (!Array.isArray(field.candidateValues)) errors.push(`${where}: candidateValues trebuie să fie listă`);
  if (!Array.isArray(field.surfaces) || !field.surfaces.length) errors.push(`${where}: surfaces trebuie să fie listă nevidă`);
  for (const surface of field.surfaces || []) {
    if (!SURFACES.includes(surface)) errors.push(`${where}: suprafață invalidă (${surface})`);
  }
  if (new Set(field.surfaces || []).size !== (field.surfaces || []).length) errors.push(`${where}: suprafețe duplicate`);
  if (!isIsoDate(field.approvedAt) && field.approvedAt !== HUMAN_REVIEW) errors.push(`${where}: approvedAt trebuie să fie dată ISO sau ${HUMAN_REVIEW}`);
  if (field.status === "pending" && (field.approvedValue !== HUMAN_REVIEW || field.approvedBy !== HUMAN_REVIEW || field.approvedAt !== HUMAN_REVIEW)) {
    errors.push(`${where}: un câmp pending nu poate conține o valoare sau aprobare pretinsă`);
  }
  if (field.status === "approved" && !fieldApproved(field)) errors.push(`${where}: aprobarea este incompletă`);
  if (field.status === "not_applicable") {
    if (!NOT_APPLICABLE_FIELDS.has(id)) errors.push(`${where}: not_applicable nu este permis pentru acest câmp`);
    if (!fieldApproved(field)) errors.push(`${where}: neaplicabilitatea trebuie aprobată explicit`);
  }
  if (field.status === "revoked" && field.approvedValue !== HUMAN_REVIEW) errors.push(`${where}: o valoare revocată nu poate rămâne aprobată`);
  if (id === "publicPhone" && field.status === "approved" && !/^\+[1-9]\d{7,14}$/u.test(String(field.approvedValue))) {
    errors.push(`${where}: telefonul canonic trebuie să fie în format E.164`);
  }
  if (id === "publicEmail" && field.status === "approved" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(String(field.approvedValue))) {
    errors.push(`${where}: email invalid`);
  }
  if (id === "websiteUrl" && field.status === "approved" && !/^https:\/\//iu.test(String(field.approvedValue))) {
    errors.push(`${where}: websiteUrl trebuie să fie HTTPS`);
  }
  if (id === "officialProfileUrls" && field.status === "approved") {
    if (!Array.isArray(field.approvedValue) || !field.approvedValue.length || field.approvedValue.some((url) => !/^https:\/\//iu.test(url))) {
      errors.push(`${where}: profilurile oficiale trebuie să fie o listă nevidă de URL-uri HTTPS`);
    }
  }
  return errors;
}

function publicationIssues(config) {
  const issues = [];
  if (config?.approvalState !== "approved") issues.push("decizia de business nu a închis fișa juridică");
  if (config?.publicationState !== "approved") issues.push("publicationState este blocked");
  for (const id of REQUIRED_FIELD_IDS) {
    if (!fieldApproved(config?.fields?.[id])) issues.push(`${id} nu are valoare aprobată`);
  }
  if (!approvalApproved(config?.approvals?.businessDecision)) issues.push("lipsește aprobarea explicită a decidentului");
  if (!approvalApproved(config?.approvals?.legalReview)) issues.push("lipsește avizul juristului pentru textele legale");
  if (missing(config?.approvals?.legalReview?.scope)) issues.push("scope-ul avizului juridic nu este confirmat");
  if (config?.fields?.publicEmail?.approvedValue === "atelier.consultanta@gmail.com"
    && !approvalApproved(config?.approvals?.operationalEmailOwnerConfirmation)) {
    issues.push("proprietarul nu a confirmat explicit Gmail ca adresă operațională");
  }
  return [...new Set(issues)];
}

function validateConfig(config) {
  const errors = [];
  if (!config || typeof config !== "object" || Array.isArray(config)) return ["config invalid"];
  if (config.schemaVersion !== 1) errors.push("schemaVersion trebuie să fie 1");
  if (config.humanReviewToken !== HUMAN_REVIEW) errors.push(`humanReviewToken trebuie să fie ${HUMAN_REVIEW}`);
  if (!["pending", "approved", "revoked"].includes(config.approvalState)) errors.push("approvalState invalid");
  if (!["blocked", "approved"].includes(config.publicationState)) errors.push("publicationState invalid");
  if (config.notLegalOpinion !== true) errors.push("fișa trebuie marcată explicit ca nefiind opinie juridică");
  if (!config.fields || typeof config.fields !== "object" || Array.isArray(config.fields)) errors.push("fields lipsește");
  const fieldIds = Object.keys(config.fields || {});
  for (const id of REQUIRED_FIELD_IDS) {
    if (!Object.hasOwn(config.fields || {}, id)) errors.push(`lipsește câmpul obligatoriu ${id}`);
    else errors.push(...validateField(id, config.fields[id]));
  }
  for (const id of fieldIds) {
    if (!REQUIRED_FIELD_IDS.includes(id)) errors.push(`câmp juridic necontrolat: ${id}`);
  }
  const surfaceCoverage = new Set(fieldIds.flatMap((id) => config.fields[id]?.surfaces || []));
  for (const surface of SURFACES) {
    if (!surfaceCoverage.has(surface)) errors.push(`suprafața obligatorie nu este acoperită în fișă: ${surface}`);
  }
  for (const approvalId of ["businessDecision", "legalReview", "operationalEmailOwnerConfirmation"]) {
    const approval = config.approvals?.[approvalId];
    if (!approval || typeof approval !== "object") {
      errors.push(`lipsește approvals.${approvalId}`);
      continue;
    }
    if (!FIELD_STATES.includes(approval.state)) errors.push(`approvals.${approvalId}: state invalid`);
    if (!isIsoDate(approval.approvedAt) && approval.approvedAt !== HUMAN_REVIEW) errors.push(`approvals.${approvalId}: approvedAt invalid`);
    if (approval.state === "approved" && !approvalApproved(approval)) errors.push(`approvals.${approvalId}: aprobare incompletă`);
  }
  const channels = config.approvedContactChannels;
  if (!channels || typeof channels !== "object" || Array.isArray(channels)) {
    errors.push("approvedContactChannels lipsește");
  } else {
    const validPhone = (value) => /^\+[1-9]\d{7,14}$/u.test(String(value || ""));
    const additional = Array.isArray(channels.additionalPhones) ? channels.additionalPhones : [];
    const whatsapp = Array.isArray(channels.whatsappPhones) ? channels.whatsappPhones : [];
    const allPhones = [channels.primaryPhone, ...additional];
    if (channels.primaryPhone !== config.fields?.publicPhone?.approvedValue) errors.push("telefonul primar diferă de publicPhone");
    if (!allPhones.every(validPhone) || new Set(allPhones).size !== allPhones.length) errors.push("canalele telefonice trebuie să fie E.164 și unice");
    if (!whatsapp.length || whatsapp.some((phone) => !allPhones.includes(phone))) errors.push("canalele WhatsApp trebuie să fie telefoane publice aprobate");
    if (!isIsoDate(channels.approvedAt) || missing(channels.approvedBy) || missing(channels.internalSource)) errors.push("approvedContactChannels nu are aprobare nominală completă");
  }
  if (config.publicationState === "approved" || config.approvalState === "approved") {
    errors.push(...publicationIssues(config).map((issue) => `publicare juridică nepermisă: ${issue}`));
  }
  if (config.approvalState !== "approved" && config.publicationState !== "blocked") {
    errors.push("publicationState trebuie să rămână blocked până la aprobarea completă");
  }
  return errors;
}

function loadLegalIdentity(file = CONFIG_PATH) {
  const config = readJson(file);
  const errors = validateConfig(config);
  if (errors.length) throw new Error(`Fișa juridică este invalidă:\n- ${errors.join("\n- ")}`);
  return config;
}

function isPublicationApproved(config) {
  return validateConfig(config).length === 0 && publicationIssues(config).length === 0;
}

function approvedIdentity(config) {
  if (!isPublicationApproved(config)) return null;
  return Object.fromEntries(REQUIRED_FIELD_IDS.map((id) => [id, config.fields[id].approvedValue]));
}

module.exports = {
  CONFIG_PATH,
  HUMAN_REVIEW,
  NOT_APPLICABLE,
  REQUIRED_FIELD_IDS,
  ROOT,
  SURFACES,
  approvedIdentity,
  fieldApproved,
  isIsoDate,
  isPublicationApproved,
  loadLegalIdentity,
  publicationIssues,
  validateConfig,
  validateField
};
