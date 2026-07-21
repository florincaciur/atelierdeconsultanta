"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CONFIG = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "breadcrumbs.json"), "utf8"));
const PROGRAMS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs || [];
const HUBS = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "program-family-hubs.json"), "utf8")).hubs || [];

function normalizeRoute(value) {
  const raw = String(value || "/").trim();
  let pathname = raw;
  try {
    pathname = new URL(raw, SITE).pathname;
  } catch {
    pathname = raw.split(/[?#]/u)[0];
  }
  pathname = `/${pathname.replace(/^\/+/, "")}`
    .replace(/\/index\.html$/iu, "")
    .replace(/\.html$/iu, "")
    .replace(/\/+$/u, "");
  return pathname || "/";
}

function canonicalUrl(route) {
  return `${SITE}${normalizeRoute(route)}`;
}

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function loadIntentRows() {
  const reportsDirectory = path.join(ROOT, "reports");
  const candidates = fs.existsSync(reportsDirectory)
    ? fs.readdirSync(reportsDirectory)
      .filter((name) => /^content-intent-inventory-.*\.json$/u.test(name))
      .sort()
      .reverse()
    : [];
  if (!candidates.length) return [];
  try {
    return JSON.parse(fs.readFileSync(path.join(reportsDirectory, candidates[0]), "utf8")).rows || [];
  } catch {
    return [];
  }
}

const INTENT_ROWS = loadIntentRows();
const INTENT_BY_ROUTE = new Map(INTENT_ROWS.map((row) => [normalizeRoute(row.route), row]));
const PROGRAM_BY_ROUTE = new Map(PROGRAMS.map((program) => [normalizeRoute(program.pageUrl || program.slug), program]));
const HUB_BY_ROUTE = new Map(HUBS.map((hub) => [normalizeRoute(hub.route), hub]));
const SECTION_BY_ROUTE = new Map(Object.values(CONFIG.sections || {}).map((section) => [normalizeRoute(section.route), section]));

function labelFromSlug(route) {
  const slug = normalizeRoute(route).split("/").filter(Boolean).pop() || "Acasă";
  return slug
    .replace(/-/gu, " ")
    .replace(/\b\p{L}/gu, (letter) => letter.toLocaleUpperCase("ro-RO"));
}

function shortenLabel(value) {
  let label = cleanText(value)
    .replace(/\s+[|–—-]\s+FABER.*$/iu, "")
    .replace(/^Ghid:\s*/iu, "");
  const colon = label.indexOf(":");
  if (colon >= 10 && colon <= 58) label = label.slice(0, colon);
  if (label.length <= 84) return label;
  const words = label.split(" ");
  const shortened = [];
  while (words.length && [...shortened, words[0]].join(" ").length <= 76) shortened.push(words.shift());
  return `${shortened.join(" ")}…`;
}

function labelForRoute(route, fallback = "", options = {}) {
  const normalized = normalizeRoute(route);
  if (normalized === "/") return CONFIG.home.label;
  if (options.asParent && SECTION_BY_ROUTE.has(normalized)) {
    return SECTION_BY_ROUTE.get(normalized).parentLabel;
  }
  if (CONFIG.labels?.[normalized]) return CONFIG.labels[normalized];
  const hub = HUB_BY_ROUTE.get(normalized);
  if (hub?.label) return cleanText(hub.label);
  const program = PROGRAM_BY_ROUTE.get(normalized);
  if (program?.shortName) return shortenLabel(program.shortName);
  const row = INTENT_BY_ROUTE.get(normalized);
  return shortenLabel(row?.h1 || fallback || labelFromSlug(normalized));
}

function parentForRoute(route) {
  const normalized = normalizeRoute(route);
  if (normalized === "/") return null;
  if (Object.prototype.hasOwnProperty.call(CONFIG.parents || {}, normalized)) {
    return normalizeRoute(CONFIG.parents[normalized]);
  }

  const program = PROGRAM_BY_ROUTE.get(normalized);
  const programParent = program?.discovery?.parentHub && normalizeRoute(program.discovery.parentHub);
  if (programParent && programParent !== normalized) return programParent;

  const row = INTENT_BY_ROUTE.get(normalized);
  const typeParent = row?.type && CONFIG.typeParents?.[row.type];
  if (typeParent && normalizeRoute(typeParent) !== normalized) return normalizeRoute(typeParent);

  if (row?.type === "hub" && row.parent && row.parent !== "ROOT") {
    const inventoryParent = normalizeRoute(row.parent);
    if (inventoryParent !== normalized) return inventoryParent;
  }
  return "/";
}

function breadcrumbRouteEntries(route, currentName = "") {
  const normalized = normalizeRoute(route);
  if (normalized === "/") return [];
  const lineage = [];
  const seen = new Set([normalized]);
  let parent = parentForRoute(normalized);

  while (parent && parent !== "/" && !seen.has(parent) && lineage.length < 5) {
    lineage.unshift(parent);
    seen.add(parent);
    parent = parentForRoute(parent);
  }

  return ["/", ...lineage, normalized].map((entryRoute, index, entries) => ({
    route: entryRoute,
    name: entryRoute === normalized
      ? labelForRoute(entryRoute, currentName)
      : labelForRoute(entryRoute, "", { asParent: true }),
    current: index === entries.length - 1
  }));
}

function breadcrumbItemsForRoute(route, currentName = "") {
  return breadcrumbRouteEntries(route, currentName).map((entry) => ({
    name: entry.name,
    item: canonicalUrl(entry.route)
  }));
}

function knownRoutes() {
  return [...new Set([
    ...INTENT_BY_ROUTE.keys(),
    ...PROGRAM_BY_ROUTE.keys(),
    ...Object.keys(CONFIG.parents || {}).map(normalizeRoute),
    ...Object.keys(CONFIG.labels || {}).map(normalizeRoute)
  ])].sort();
}

module.exports = {
  SITE,
  breadcrumbItemsForRoute,
  breadcrumbRouteEntries,
  canonicalUrl,
  knownRoutes,
  labelForRoute,
  normalizeRoute,
  parentForRoute
};
