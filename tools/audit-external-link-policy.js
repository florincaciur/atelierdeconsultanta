#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { findPublicHtmlFiles } = require("./sync-global-header");

const ROOT = path.resolve(__dirname, "..");
const SITE_HOSTS = new Set(["atelierdeconsultanta.ro", "www.atelierdeconsultanta.ro"]);
const policy = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "external-link-policy.json"), "utf8"));
const allowedHosts = new Set(policy.allowedExactHosts.map((host) => host.toLowerCase()));
const approvedChannels = new Set(policy.approvedChannelUrls);

function hostAllowed(host) {
  const normalized = host.toLowerCase();
  return allowedHosts.has(normalized) || policy.allowedHostSuffixes.some((suffix) => normalized.endsWith(suffix));
}

const issues = [];
for (const relativePath of findPublicHtmlFiles()) {
  const file = path.join(ROOT, ...relativePath.split("/"));
  const $ = cheerio.load(fs.readFileSync(file, "utf8"));
  if (policy.scanPolicy.skipNoindexPages && /noindex/iu.test($("meta[name='robots']").attr("content") || "")) continue;
  $("a[href]").each((_, anchor) => {
    const href = String($(anchor).attr("href") || "").trim();
    if (!/^https?:\/\//iu.test(href)) return;
    let url;
    try { url = new URL(href); } catch { issues.push(`${relativePath}: URL extern invalid ${href}`); return; }
    if (SITE_HOSTS.has(url.hostname.toLowerCase())) return;
    if (policy.scanPolicy.requireHttps && url.protocol !== "https:") issues.push(`${relativePath}: link extern fără HTTPS ${href}`);
    if (!hostAllowed(url.hostname)) issues.push(`${relativePath}: domeniu extern neaprobat ${url.hostname}`);
    if (["wa.me", "www.instagram.com"].includes(url.hostname.toLowerCase()) && !approvedChannels.has(`${url.origin}${url.pathname}${url.pathname.endsWith("/") ? "" : ""}`)) {
      const normalized = `${url.origin}${url.pathname}`;
      if (!approvedChannels.has(normalized) && !approvedChannels.has(`${normalized}/`)) issues.push(`${relativePath}: canal extern neaprobat ${href}`);
    }
  });
}

if (issues.length) {
  console.error(`Politica linkurilor externe a eșuat (${issues.length}):`);
  issues.slice(0, 100).forEach((issue) => console.error(`- ${issue}`));
  process.exit(1);
}

console.log("Politica linkurilor externe PASS: numai instituții publice și canale FABER aprobate.");
