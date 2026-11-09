"use strict";

const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROUTE = "/politica-de-confidentialitate";
const FILE = "politica-de-confidentialitate.html";
const BLOCK = /(<!-- PRIVACY_POLICY_START -->)[\s\S]*?(<!-- PRIVACY_POLICY_END -->)/u;
const DATE = /<time datetime="\d{4}-\d{2}-\d{2}" data-privacy-revision>[^<]*<\/time>/u;

function loadPrivacyPolicy(root) {
  return JSON.parse(fs.readFileSync(path.join(root, "config/privacy-policy.json"), "utf8"));
}

function renderPrivacyPolicy(html, root, identity) {
  const { modifiedAt } = loadPrivacyPolicy(root);
  if (!BLOCK.test(html) || !DATE.test(html)) throw new Error("Lipsește blocul politicii de confidențialitate sau marcajul datei.");
  const sections = fs.readFileSync(path.join(root, "tools/templates/privacy-policy.html.template"), "utf8").replace(/\r\n/gu, "\n").trimEnd();
  const eol = html.includes("\r\n") ? "\r\n" : "\n";
  const values = {
    CONTROLLER: identity.personalDataController,
    BRAND: identity.brandName,
    CONTRACTOR: identity.contractingEntity,
    EMAIL: identity.publicEmail
  };
  const copy = sections.replace(/\{\{([A-Z]+)\}\}/gu, (_, key) => {
    if (!Object.hasOwn(values, key)) throw new Error(`Câmp necunoscut în politica de confidențialitate: ${key}`);
    return String(values[key]).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
  });
  const date = new Intl.DateTimeFormat("ro-RO", { dateStyle: "long", timeZone: "UTC" }).format(new Date(modifiedAt));
  return html.replace(BLOCK, (_, start, end) => [start, copy.replaceAll("\n", eol), end].join(eol))
    .replace(DATE, `<time datetime="${modifiedAt}" data-privacy-revision>${date}</time>`);
}

function privacyPolicyDigest(html) {
  const match = html.match(BLOCK);
  if (!match) throw new Error("Lipsește conținutul politicii de confidențialitate.");
  // Hash the public copy and destinations. Tracking attributes can be regenerated.
  const $ = require("cheerio").load(match[0]);
  const text = $("body").text().replace(/\s+/gu, " ").trim();
  const links = $("a[href]").map((_, link) => $(link).attr("href")).get();
  return createHash("sha256").update(JSON.stringify({ text, links })).digest("hex");
}

function validatePrivacyPublication(root) {
  const { approval, modifiedAt } = loadPrivacyPolicy(root);
  const html = fs.readFileSync(path.join(root, FILE), "utf8");
  if (!approval?.approvedBy || !/^\d{4}-\d{2}-\d{2}$/u.test(approval.approvedAt) ||
      approval.approvedAt > modifiedAt || approval.digest !== privacyPolicyDigest(html) ||
      approval.redirect !== "/gdpr") {
    throw new Error("Publicare blocată: aprobarea textului exact și a migrării /gdpr nu este consemnată.");
  }
}

module.exports = { FILE, ROUTE, loadPrivacyPolicy, privacyPolicyDigest, renderPrivacyPolicy, validatePrivacyPublication };
