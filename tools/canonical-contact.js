"use strict";

const { approvedIdentity, fieldApproved, loadLegalIdentity, HUMAN_REVIEW } = require("./legal-identity-governance");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;");
}

function approvalApproved(approval) {
  return approval?.state === "approved"
    && approval.approvedBy
    && approval.approvedBy !== HUMAN_REVIEW
    && /^\d{4}-\d{2}-\d{2}$/u.test(String(approval.approvedAt || ""))
    && approval.internalSource
    && approval.internalSource !== HUMAN_REVIEW;
}

function formatPhoneDisplay(phone) {
  const value = String(phone || "");
  const romanianMobile = value.match(/^\+40(\d{3})(\d{3})(\d{3})$/u);
  if (romanianMobile) return `0${romanianMobile[1]} ${romanianMobile[2]} ${romanianMobile[3]}`;
  return value;
}

function canonicalContactIdentity(config = loadLegalIdentity()) {
  const phoneField = config.fields?.publicPhone;
  const emailField = config.fields?.publicEmail;
  const businessApproved = approvalApproved(config.approvals?.businessDecision);
  const phoneApproved = businessApproved && fieldApproved(phoneField);
  const emailOwnerApproved = String(emailField?.approvedValue || "").toLowerCase() !== "atelier.consultanta@gmail.com"
    || approvalApproved(config.approvals?.operationalEmailOwnerConfirmation);
  const emailApproved = businessApproved && fieldApproved(emailField) && emailOwnerApproved;

  const approvedPhones = phoneApproved
    ? [phoneField.approvedValue, ...(config.approvedContactChannels?.additionalPhones || [])]
      .filter((value, index, values) => /^\+[1-9]\d{7,14}$/u.test(String(value)) && values.indexOf(value) === index)
      .map((value) => ({ href: `tel:${value}`, value, display: formatPhoneDisplay(value) }))
    : [];
  return {
    state: phoneApproved || emailApproved ? "partially_or_fully_approved" : "pending",
    phone: approvedPhones[0] || null,
    phones: approvedPhones,
    email: emailApproved ? {
      href: `mailto:${emailField.approvedValue}`,
      value: emailField.approvedValue,
      display: emailField.approvedValue
    } : null
  };
}

function contactAnchor(contact, type, className = "") {
  const analytics = type === "phone"
    ? ' data-analytics-event="contact_phone" data-analytics-component="contact_link" data-analytics-cta-id="phone_contact"'
    : ' data-analytics-event="contact_email" data-analytics-component="contact_link" data-analytics-cta-id="email_contact"';
  const classAttribute = className ? ` class="${escapeHtml(className)}"` : "";
  return `<a${classAttribute} href="${escapeHtml(contact.href)}"${analytics}>${escapeHtml(contact.display)}</a>`;
}

function renderContactChannels(config = loadLegalIdentity()) {
  const contact = canonicalContactIdentity(config);
  const cards = [];
  for (const [index, phone] of contact.phones.entries()) {
    const label = index === 0 ? "Telefon principal" : "Telefon și WhatsApp";
    cards.push(`<a class="core-contact-channel" href="${escapeHtml(phone.href)}"><strong>${label} · ${escapeHtml(phone.display)}</strong><span>Apelează direct folosind numărul public confirmat.</span></a>`);
  }
  if (contact.email) {
    cards.push(`<a class="core-contact-channel" href="${escapeHtml(contact.email.href)}"><strong>${escapeHtml(contact.email.display)}</strong><span>Trimite un email folosind adresa operațională confirmată.</span></a>`);
  }

  if (!cards.length) {
    return `<section class="core-contact-channels core-contact-channels--pending" id="contact-direct" aria-labelledby="contact-direct-title" data-canonical-contact-state="pending">
      <div><h2 id="contact-direct-title">Contact direct</h2><p>Telefonul și adresa de email vor fi afișate după confirmarea proprietarului. Până atunci, poți folosi formularul de mai sus.</p></div>
    </section>`;
  }

  return `<section class="core-contact-channels" id="contact-direct" aria-label="Canale directe de contact" data-canonical-contact-state="approved">
      ${cards.join("\n      ")}
    </section>`;
}

function renderFooterContact(config = loadLegalIdentity()) {
  const contact = canonicalContactIdentity(config);
  const links = [];
  for (const phone of contact.phones) links.push(contactAnchor(phone, "phone"));
  if (contact.email) links.push(contactAnchor(contact.email, "email"));
  const content = links.length
    ? `<span class="footer-contact-direct" aria-label="Contact direct"> · ${links.join(" · ")}</span>`
    : "";
  return `<!-- CANONICAL_CONTACT_START -->${content}<!-- CANONICAL_CONTACT_END -->`;
}

function renderLegalIdentityPanel(config = loadLegalIdentity(), options = {}) {
  const identity = approvedIdentity(config);
  if (!identity) return "";
  const contact = canonicalContactIdentity(config);
  const phoneLinks = contact.phones.map((phone) => contactAnchor(phone, "phone")).join(" · ");
  const profileLinks = identity.officialProfileUrls.map((url) => `<a href="${escapeHtml(url)}" rel="me noopener noreferrer">Instagram oficial</a>`).join(" · ");
  const titleId = options.titleId || "canonical-legal-identity-title";
  const title = options.title || "Date juridice și de contact";
  const kicker = options.kicker || "Date aprobate la 22.07.2026";
  const extraClass = options.className ? ` ${escapeHtml(options.className)}` : "";
  const sectionId = options.sectionId ? ` id="${escapeHtml(options.sectionId)}"` : "";
  return `<!-- CANONICAL_LEGAL_IDENTITY_START -->
<section${sectionId} class="core-section canonical-legal-identity${extraClass}" aria-labelledby="${escapeHtml(titleId)}" data-canonical-legal-identity="approved">
  <span class="core-kicker">${escapeHtml(kicker)}</span>
  <h2 id="${escapeHtml(titleId)}">${escapeHtml(title)}</h2>
  <dl class="core-fact-strip">
    <div><dt>Denumire juridică</dt><dd>${escapeHtml(identity.legalName)} · CUI ${escapeHtml(identity.taxIdentifier)} · ONRC ${escapeHtml(identity.tradeRegisterNumber)}</dd></div>
    <div><dt>Sediu social</dt><dd>${escapeHtml(identity.registeredOffice)}</dd></div>
    <div><dt>Puncte de lucru publice</dt><dd>${escapeHtml(identity.publicWorkplaceAddress)}</dd></div>
    <div><dt>Operator date</dt><dd>${escapeHtml(identity.personalDataController)}</dd></div>
    <div><dt>Contact</dt><dd>${phoneLinks} · ${contact.email ? contactAnchor(contact.email, "email") : ""}</dd></div>
    <div><dt>Program și arie</dt><dd>${escapeHtml(identity.contactHours)} · ${escapeHtml(identity.serviceArea)}</dd></div>
    <div><dt>Profil oficial</dt><dd>${profileLinks}</dd></div>
  </dl>
</section>
<!-- CANONICAL_LEGAL_IDENTITY_END -->`;
}

module.exports = {
  canonicalContactIdentity,
  formatPhoneDisplay,
  renderLegalIdentityPanel,
  renderContactChannels,
  renderFooterContact
};
