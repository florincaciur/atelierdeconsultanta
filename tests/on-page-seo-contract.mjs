#!/usr/bin/env node

import assert from "node:assert/strict";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, "..");
const { auditSite } = require("../tools/on-page-seo-audit");
const result = auditSite(ROOT);
const failures = [...result.globalErrors, ...result.pages.flatMap((page) => page.errors.map((error) => `${page.route}: ${error}`))];

assert.equal(result.routes, 104, "contractul trebuie să acopere toate rutele canonice din sitemap");
assert.equal(failures.length, 0, `contract on-page eșuat:\n- ${failures.join("\n- ")}`);
console.log(`On-page SEO contract PASS: ${result.routes} rute, ${result.programRoutes} programe, title/meta/H1/heading/canonical/robots/OG/Twitter.`);
