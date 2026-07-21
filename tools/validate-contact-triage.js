#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const PUBLICATION_GATE = process.argv.includes("--publication-gate");
const PENDING = "DE_VALIDAT_UMAN";

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function validDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(value) && Number.isFinite(Date.parse(`${value}T00:00:00Z`));
}

const errors = [];
const config = readJson("config/contact-triage.json");
const schema = readJson("config/contact-triage-payload.schema.json");
const legalIdentity = readJson("config/legal-identity.json");

if (config.schemaVersion !== "1.0.0") errors.push("schemaVersion trebuie să fie 1.0.0");
if (config.payloadSchema !== "./contact-triage-payload.schema.json") errors.push("lipsește referința la schema payload-ului");
if (config.endpoint !== "/api/contact-triage") errors.push("endpointul trebuie să fie /api/contact-triage");
if (config.transport?.destinationSecret !== "CONTACT_FORM_FORWARD_URL") errors.push("destinația trebuie configurată exclusiv prin CONTACT_FORM_FORWARD_URL");
if (config.transport?.crmDetectedInRepository !== false) errors.push("configurația nu trebuie să pretindă existența unui CRM nedetectat");
if (!schema.anyOf || schema.anyOf.length !== 2) errors.push("schema nu exprimă alternativa email OR telefon");
if (schema.required?.includes("email") || schema.required?.includes("phone")) errors.push("emailul și telefonul nu pot fi obligatorii individual");
if (!config.privacyNotice?.copy) errors.push("lipsește textul confirmării de citire");
if (config.privacyNotice?.marketingConsentIncluded !== false) errors.push("confirmarea de citire nu poate include acord de marketing");
if (config.antiSpam?.honeypot !== true || config.antiSpam?.sameOriginCheck !== true) errors.push("protecția anti-spam minimă nu este activă");
if (Array.isArray(config.antiSpam?.sensitiveAnalyticsFields) && config.antiSpam.sensitiveAnalyticsFields.length) errors.push("analytics nu poate primi câmpuri sensibile");

if (PUBLICATION_GATE) {
  if (config.privacyNotice?.copyState !== "approved") errors.push("textul informării nu are copyState=approved");
  if (!config.privacyNotice?.approvedBy || config.privacyNotice.approvedBy === PENDING) errors.push("lipsește persoana care a aprobat textul juridic");
  if (!validDate(config.privacyNotice?.approvedAt)) errors.push("lipsește data aprobării textului juridic");
  if (legalIdentity.approvals?.legalReview?.state !== "approved") errors.push("fișa juridică nu are avizul juridic aprobat");
}

if (errors.length) {
  console.error(`Contact triage validation FAILED (${errors.length}):`);
  errors.forEach((error) => console.error(`- ${error}`));
  process.exit(1);
}

console.log(`Contact triage validation PASS (${PUBLICATION_GATE ? "publication gate" : "structural"}).`);
