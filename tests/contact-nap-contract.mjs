#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import * as cheerio from "cheerio";

const require = createRequire(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST_MODE = process.argv.includes("--dist");
const PUBLIC_ROOT = DIST_MODE ? path.join(REPO_ROOT, "dist") : REPO_ROOT;
const { canonicalContactIdentity, renderFooterContact } = require("../tools/canonical-contact");
const { approvedPrivacyNotice } = require("../tools/contact-triage-form");
const { findPublicHtmlFiles } = require("../tools/sync-global-header");
const { approvedIdentity, isPublicationApproved, loadLegalIdentity } = require("../tools/legal-identity-governance");
const { ORGANIZATION_ID, organizationSchema } = require("../tools/schema-helpers");

const legalConfig = loadLegalIdentity();
const identity = approvedIdentity(legalConfig);
const contact = canonicalContactIdentity(legalConfig);
const triageConfig = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "config", "contact-triage.json"), "utf8"));
const approvedPhones = contact.phones.map((phone) => phone.value);
const approvedWhatsappUrls = contact.whatsappPhones.map((phone) => phone.whatsappHref);
const approvedProfiles = new Set(identity?.officialProfileUrls || []);
const socialHosts = new Set(["instagram.com", "www.instagram.com", "facebook.com", "www.facebook.com", "linkedin.com", "www.linkedin.com", "x.com", "twitter.com", "www.twitter.com", "tiktok.com", "www.tiktok.com", "youtube.com", "www.youtube.com"]);
const legacyEmail = "atelier.consultanță@gmail.com";

assert(isPublicationApproved(legalConfig), "Identitatea juridică trebuie să fie aprobată pentru publicare.");
assert(identity, "Identitatea juridică aprobată trebuie să poată fi derivată.");
assert.deepEqual(approvedPhones, ["+40769828338", "+40753326229"], "Ordinea canalelor telefonice aprobate s-a schimbat.");
assert.deepEqual(approvedWhatsappUrls, ["https://wa.me/40769828338", "https://wa.me/40753326229"], "Canalele WhatsApp trebuie derivate din registrul aprobat.");
assert.equal(identity.publicEmail, "atelier.consultanta@gmail.com");
assert.equal(triageConfig.privacyNotice.copyState, "approved");
assert.equal(triageConfig.privacyNotice.marketingConsentIncluded, false);
assert.deepEqual(triageConfig.antiSpam.sensitiveAnalyticsFields, [], "Câmpurile sensibile nu pot fi trimise în analytics.");
assert.equal(approvedPrivacyNotice(triageConfig, legalConfig).state, "approved");
assert.throws(
  () => approvedPrivacyNotice({ ...triageConfig, privacyNotice: { ...triageConfig.privacyNotice, marketingConsentIncluded: true } }, legalConfig),
  /nu este aprobată/u,
  "Generatorul trebuie să refuze combinarea confirmării cu marketingul."
);
assert.throws(
  () => approvedPrivacyNotice(triageConfig, { ...legalConfig, publicationState: "pending_validation" }),
  /nu este aprobată/u,
  "Generatorul trebuie să refuze publicarea fără aprobarea juridică."
);

function read(relativePath) {
  return fs.readFileSync(path.join(PUBLIC_ROOT, ...relativePath.split("/")), "utf8");
}

function routeFile(route) {
  const slug = route.replace(/^\//u, "");
  const candidates = route === "/" ? ["index.html"] : [`${slug}/index.html`, `${slug}.html`];
  const match = candidates.find((relativePath) => fs.existsSync(path.join(PUBLIC_ROOT, ...relativePath.split("/"))));
  assert(match, `${route}: lipsește sursa HTML publică.`);
  return match;
}

function graphNodes($) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    const parsed = JSON.parse($(script).html());
    nodes.push(...(Array.isArray(parsed?.["@graph"]) ? parsed["@graph"] : [parsed]));
  });
  return nodes;
}

function normalizedPhone(value) {
  const digits = String(value || "").replace(/\D/gu, "");
  return digits.startsWith("40") ? `+${digits}` : String(value || "");
}

const publicFiles = findPublicHtmlFiles(PUBLIC_ROOT);
assert(publicFiles.length >= 100, "Auditul NAP trebuie să acopere întregul site public.");
let managedFooters = 0;
let organizationNodes = 0;

for (const relativePath of publicFiles) {
  const html = read(relativePath);
  assert(!html.includes(legacyEmail), `${relativePath}: emailul FABER conține o diacritică necanonică.`);
  const $ = cheerio.load(html, { decodeEntities: false });

  $("a[href^='tel:']").each((_, anchor) => {
    const value = $(anchor).attr("href").slice(4);
    assert(approvedPhones.includes(value), `${relativePath}: telefon public neaprobat ${value}.`);
  });
  $("a[href^='mailto:']").each((_, anchor) => {
    const value = $(anchor).attr("href").slice(7).split("?")[0];
    if (/atelier|faber/iu.test(value)) assert.equal(value, identity.publicEmail, `${relativePath}: email FABER necanonic.`);
  });

  for (const whatsappUrl of approvedWhatsappUrls) {
    const anchors = $(`a[href='${whatsappUrl}']`);
    assert.equal(anchors.length, 1, `${relativePath}: canalul ${whatsappUrl} trebuie să apară exact o dată în dialogul global.`);
    assert.equal(anchors.attr("target"), "_blank", `${relativePath}: WhatsApp trebuie deschis într-un tab separat.`);
    const rel = new Set((anchors.attr("rel") || "").split(/\s+/u));
    assert(rel.has("noopener") && rel.has("noreferrer"), `${relativePath}: linkul WhatsApp trebuie izolat cu noopener+noreferrer.`);
  }

  $("a[href]").each((_, anchor) => {
    const href = $(anchor).attr("href");
    let url;
    try { url = new URL(href); } catch { return; }
    if (socialHosts.has(url.hostname)) assert(approvedProfiles.has(url.href), `${relativePath}: profil social neaprobat ${url.href}.`);
  });

  if (html.includes("<!-- CANONICAL_CONTACT_START -->")) {
    managedFooters += 1;
    const block = html.match(/<!-- CANONICAL_CONTACT_START -->[\s\S]*?<!-- CANONICAL_CONTACT_END -->/u)?.[0];
    assert.equal(block, renderFooterContact(legalConfig), `${relativePath}: footerul nu folosește canalele canonice în ordinea aprobată.`);
  }

  for (const node of graphNodes($).filter((candidate) => candidate?.["@id"] === ORGANIZATION_ID)) {
    organizationNodes += 1;
    const canonicalOrganization = organizationSchema();
    assert.equal(node.name, canonicalOrganization.name, `${relativePath}: brand Organization divergent.`);
    for (const field of ["legalName", "email", "taxID"]) {
      if (node[field] !== undefined) assert.deepEqual(node[field], canonicalOrganization[field], `${relativePath}: ${field} Organization divergent.`);
    }
    if (node.address !== undefined) assert.deepEqual(node.address, canonicalOrganization.address, `${relativePath}: adresă Organization divergentă.`);
    if (node.sameAs !== undefined) assert.deepEqual(node.sameAs, canonicalOrganization.sameAs, `${relativePath}: profiluri Organization divergente.`);
    const contactPointPhones = [node.contactPoint].flat().filter(Boolean).flatMap((point) => [point.telephone].flat().filter(Boolean));
    const schemaPhones = [...[node.telephone].flat().filter(Boolean), ...contactPointPhones].map(normalizedPhone);
    for (const phone of schemaPhones) assert(approvedPhones.includes(phone), `${relativePath}: telefon Organization neaprobat ${phone}.`);
  }
}

assert(managedFooters >= 100, "Auditul trebuie să găsească footerele gestionate sitewide.");
assert(organizationNodes >= 100, "Auditul trebuie să valideze entitatea Organization sitewide.");

const contactFile = routeFile("/contact");
const contactPage = cheerio.load(read(contactFile), { decodeEntities: false });
const contactForm = contactPage("#contact-triage-form");
assert.equal(contactForm.length, 1, "/contact trebuie să conțină un singur formular canonic.");
assert.equal(contactForm.attr("action"), triageConfig.endpoint);
assert.equal(contactForm.attr("method"), "post");
assert.equal(contactForm.attr("data-clarity-mask"), "true");
assert.equal(contactForm.attr("data-legal-copy-state"), "approved");
assert.equal(contactForm.find("[name='privacy_notice_acknowledged'][required]").length, 1);
assert.equal(contactForm.find("[name='privacy_notice_acknowledged'][checked]").length, 0, "Confirmarea de confidențialitate nu poate fi prebifată.");
assert.equal(contactForm.find("[name*='marketing'], [name*='newsletter']").length, 0, "Procesarea solicitării nu poate fi combinată cu marketingul.");
assert.match(contactPage("[data-legal-copy-note]").text(), /nu reprezintă acord/iu);
assert.match(contactPage("[data-legal-copy-note]").text(), /newsletter|marketing/iu);
for (const phone of contact.phones) assert(contactPage(`main a[href='${phone.href}']`).length >= 1, `/contact: lipsește ${phone.href}.`);
assert(contactPage(`main a[href='${contact.email.href}']`).length >= 1, "/contact: lipsește emailul canonic.");

const legacyFile = routeFile("/idei-afaceri-fonduri-europene");
const legacyPage = cheerio.load(read(legacyFile), { decodeEntities: false });
const legacyForm = legacyPage("form[action^='https://formsubmit.co/']");
assert.equal(legacyForm.length, 1, `${legacyFile}: formularul legacy trebuie păstrat funcțional până la aprobarea migrării.`);
assert.equal(legacyForm.attr("action"), `https://formsubmit.co/${identity.publicEmail}`);
assert.equal(legacyForm.attr("method")?.toLowerCase(), "post");
assert.equal(legacyForm.attr("data-clarity-mask"), "true");
assert.equal(legacyForm.find("[name='email'][required]").length, 1);
assert.equal(legacyForm.find("[name='phone'][required]").length, 0);
assert.equal(legacyForm.find("[name='gdpr'][required]").length, 1);
assert.equal(legacyForm.find("[name='gdpr'][checked]").length, 0, "Confirmarea formularului legacy nu poate fi prebifată.");
assert.equal(legacyForm.find("[name*='marketing'], [name*='newsletter']").length, 0);

const adminFile = path.join(PUBLIC_ROOT, "admin", "index.html");
if (fs.existsSync(adminFile)) assert(!fs.readFileSync(adminFile, "utf8").includes(legacyEmail), "/admin: placeholderul de email trebuie să fie canonic.");
const worker = fs.readFileSync(path.join(REPO_ROOT, "cloudflare", "domain-seo-redirects.mjs"), "utf8");
assert.doesNotMatch(worker, /console\.(?:log|debug)\s*\(/u, "Workerul formularului nu poate jurnaliza payloaduri sensibile.");

console.log(`Contact/NAP contract PASS (${DIST_MODE ? "dist" : "source"}): ${publicFiles.length} fișiere, ${managedFooters} footere, ${organizationNodes} entități Organization, 2 formulare validate.`);
