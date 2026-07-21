import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handleRequest } from "../cloudflare/domain-seo-redirects.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENDPOINT = "https://atelierdeconsultanta.ro/api/crm/qualified-lead";
const SECRET = "test-webhook-secret-2026";

function request(payload, token = SECRET) {
  return new Request(ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });
}

function environment(overrides = {}) {
  return {
    CRM_ANALYTICS_WEBHOOK_SECRET: SECRET,
    ANALYTICS_EVENT_FORWARD_URL: "https://analytics.example.test/events",
    ...overrides
  };
}

const base = {
  lead_correlation_id: "test-lead-001",
  page_path: "/dr12-afir",
  page_type: "program",
  program_slug: "dr12-afir",
  program_family: "afir-agricultura",
  form_version: "short_v1",
  source_channel: "chatgpt",
  experiment_id: "contact_copy_a"
};

const forwarded = [];
let response = await handleRequest(request(base), async () => { throw new Error("origin must not receive CRM webhooks"); }, environment({
  analyticsForwardFetch: async (url, options) => {
    forwarded.push({ url, body: JSON.parse(options.body) });
    return new Response(null, { status: 204 });
  }
}));
assert.equal(response.status, 202);
assert.deepEqual(await response.json(), { success: true });
assert.equal(forwarded.length, 1);
assert.equal(forwarded[0].body.event, "qualified_lead");
assert.equal(forwarded[0].body.lead_correlation_id, "test-lead-001");
assert.equal(forwarded[0].body.program_slug, "dr12-afir");
assert.deepEqual(Object.keys(forwarded[0].body).sort(), ["event", ...Object.keys(base)].sort());

response = await handleRequest(request(base, "wrong-secret"), async () => new Response(null, { status: 500 }), environment());
assert.equal(response.status, 401, "wrong CRM secret must fail");

response = await handleRequest(request({ ...base, email: "must-not-enter-analytics@example.com" }), async () => new Response(null, { status: 500 }), environment({
  analyticsForwardFetch: async () => new Response(null, { status: 204 })
}));
assert.equal(response.status, 422, "PII/additional fields must be rejected, not silently forwarded");

response = await handleRequest(request(base), async () => new Response(null, { status: 500 }), {
  CRM_ANALYTICS_WEBHOOK_SECRET: SECRET
});
assert.equal(response.status, 503, "unconfigured server analytics destination must block qualified_lead");

const schema = JSON.parse(await fs.readFile(path.join(ROOT, "config", "qualified-lead.schema.json"), "utf8"));
assert.equal(schema.additionalProperties, false);
assert.deepEqual(schema.required, ["lead_correlation_id"]);
const dashboard = JSON.parse(await fs.readFile(path.join(ROOT, "config", "funnel-dashboard.json"), "utf8"));
assert.deepEqual(dashboard.steps.map((step) => step.event), [
  "cta_view",
  "cta_click",
  "form_start",
  "step_1_complete",
  "form_submit",
  "qualified_lead"
]);

console.log("CRM funnel contract passed: authenticated qualified_lead forwarding contains only non-PII fields.");
