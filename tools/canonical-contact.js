"use strict";

const { fieldApproved, loadLegalIdentity, HUMAN_REVIEW } = require("./legal-identity-governance");

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

  return {
    state: phoneApproved || emailApproved ? "partially_or_fully_approved" : "pending",
    phone: phoneApproved ? {
      href: `tel:${phoneField.approvedValue}`,
      value: phoneField.approvedValue,
      display: formatPhoneDisplay(phoneField.approvedValue)
    } : null,
    email: emailApproved ? {
      href: `mailto:${emailField.approvedValue}`,
      value: emailField.approvedValue,
      display: emailField.approvedValue
    } : null
  };
}

function contactAnchor(contact, type, className = "") {
  const analytics = type === "phone"
    ? ' data-analytics-event="phone_click" data-analytics-component="contact_link" data-analytics-cta-id="phone_contact"'
    : ' data-analytics-event="email_click" data-analytics-component="contact_link" data-analytics-cta-id="email_contact"';
  const classAttribute = className ? ` class="${escapeHtml(className)}"` : "";
  return `<a${classAttribute} href="${escapeHtml(contact.href)}"${analytics}>${escapeHtml(contact.display)}</a>`;
}

function renderContactChannels(config = loadLegalIdentity()) {
  const contact = canonicalContactIdentity(config);
  const cards = [];
  if (contact.phone) {
    cards.push(`<a class="core-contact-channel" href="${escapeHtml(contact.phone.href)}"><strong>Telefon · ${escapeHtml(contact.phone.display)}</strong><span>Apelează direct folosind numărul public canonic confirmat.</span></a>`);
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
  if (contact.phone) links.push(contactAnchor(contact.phone, "phone"));
  if (contact.email) links.push(contactAnchor(contact.email, "email"));
  const content = links.length
    ? `<span class="footer-contact-direct" aria-label="Contact direct"> · ${links.join(" · ")}</span>`
    : "";
  return `<!-- CANONICAL_CONTACT_START -->${content}<!-- CANONICAL_CONTACT_END -->`;
}

module.exports = {
  canonicalContactIdentity,
  formatPhoneDisplay,
  renderContactChannels,
  renderFooterContact
};
