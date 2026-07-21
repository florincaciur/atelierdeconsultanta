"use strict";

const CANONICAL_HOST = "atelierdeconsultanta.ro";
const HSTS_VALUE = "max-age=15552000";
const CONTACT_ENDPOINT = "/api/contact-triage";
const QUALIFIED_LEAD_ENDPOINT = "/api/crm/qualified-lead";
const MAX_CONTACT_BODY_BYTES = 64 * 1024;
const MAX_ANALYTICS_BODY_BYTES = 16 * 1024;
const APPLICANT_TYPES = new Set([
  "societate",
  "pfa_ii_if",
  "ferma_exploatatie",
  "startup",
  "ong",
  "institutie_publica",
  "alta"
]);

function permanentRedirect(destination) {
  return new Response(null, {
    status: 301,
    headers: {
      location: destination,
      "cache-control": "public, max-age=3600"
    }
  });
}

function isLegacySearchPlaceholder(url) {
  return url.pathname === "/"
    && (url.searchParams.has("s") || /search_term_string/iu.test(url.search));
}

function secured(response) {
  const output = new Response(response.body, response);
  output.headers.set("strict-transport-security", HSTS_VALUE);
  output.headers.set("x-content-type-options", "nosniff");
  output.headers.set("cache-control", "no-store");
  return output;
}

function wantsJson(request) {
  return /application\/json/iu.test(request.headers.get("accept") || "")
    || request.headers.get("x-requested-with") === "fetch";
}

function responseBody(request, status, payload) {
  if (wantsJson(request)) {
    return secured(new Response(JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json; charset=utf-8" }
    }));
  }

  const successful = status >= 200 && status < 300;
  const title = successful ? "Solicitarea a fost trimisă" : "Solicitarea nu a fost trimisă";
  const message = successful
    ? "Următorul pas este citirea contextului și stabilirea informațiilor care mai trebuie verificate. Confirmarea nu reprezintă un verdict de eligibilitate și nu promite un termen de răspuns."
    : "Verifică răspunsurile obligatorii și completează o adresă de email sau un număr de telefon. Valorile nu sunt repetate în această pagină pentru a evita expunerea lor.";
  const errors = Array.isArray(payload.errors) && payload.errors.length
    ? `<p>Câmpuri de verificat: ${payload.errors.map((error) => error.label).join(", ")}.</p>`
    : "";
  const html = `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${title} | FABER</title></head><body style="font-family:Arial,sans-serif;max-width:720px;margin:10vh auto;padding:24px;line-height:1.6;color:#172033"><main><h1>${title}</h1><p>${message}</p>${errors}<p><a href="/contact">Înapoi la formular</a></p></main></body></html>`;
  return secured(new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" }
  }));
}

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isAffirmative(value) {
  return value === true || ["true", "1", "on", "yes"].includes(clean(value).toLowerCase());
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(value) && value.length <= 254;
}

function validPhone(value) {
  const digits = value.replace(/\D/gu, "");
  return digits.length >= 7 && digits.length <= 16;
}

function lengthError(errors, field, label, value, minimum, maximum, required = false) {
  if (!value && required) {
    errors.push({ field, label, code: "required" });
    return;
  }
  if (value && (value.length < minimum || value.length > maximum)) {
    errors.push({ field, label, code: "invalid_length" });
  }
}

export function validateContactPayload(input, now = Date.now()) {
  const payload = {
    schema_version: clean(input.schema_version) || "1.0.0",
    lead_id: clean(input.lead_id),
    applicant_type: clean(input.applicant_type),
    location: clean(input.location),
    investment: clean(input.investment),
    email: clean(input.email),
    phone: clean(input.phone),
    privacy_notice_acknowledged: isAffirmative(input.privacy_notice_acknowledged),
    program_slug: clean(input.program_slug) || "unknown",
    caen_or_so: clean(input.caen_or_so) || "Nu știu încă",
    budget_estimate: clean(input.budget_estimate) || "Nu știu încă",
    extended_description: clean(input.extended_description),
    documents_summary: clean(input.documents_summary),
    expenses_summary: clean(input.expenses_summary),
    contact_preference: clean(input.contact_preference) || "no_preference",
    page_url: clean(input.page_url) || "/contact",
    referrer_path: clean(input.referrer_path),
    program_context: clean(input.program_context),
    program_family: clean(input.program_family),
    source_channel: clean(input.source_channel),
    utm_source: clean(input.utm_source),
    utm_medium: clean(input.utm_medium),
    utm_campaign: clean(input.utm_campaign),
    utm_term: clean(input.utm_term),
    utm_content: clean(input.utm_content),
    landing_referrer: clean(input.landing_referrer),
    landing_page_path: clean(input.landing_page_path),
    form_started_at: clean(input.form_started_at),
    website: clean(input.website)
  };
  const errors = [];

  if (payload.schema_version !== "1.0.0") {
    errors.push({ field: "schema_version", label: "versiune formular", code: "unsupported_version" });
  }
  if (payload.lead_id.length > 100) {
    errors.push({ field: "lead_id", label: "identificator solicitare", code: "invalid_length" });
  }
  if (!APPLICANT_TYPES.has(payload.applicant_type)) {
    errors.push({ field: "applicant_type", label: "tip solicitant", code: "invalid_choice" });
  }
  lengthError(errors, "location", "județ / localitate", payload.location, 2, 120, true);
  lengthError(errors, "investment", "investiție", payload.investment, 5, 300, true);

  if (!payload.email && !payload.phone) {
    errors.push({ field: "contact", label: "email sau telefon", code: "one_required" });
  } else {
    if (payload.email && !validEmail(payload.email)) errors.push({ field: "email", label: "email", code: "invalid_email" });
    if (payload.phone && !validPhone(payload.phone)) errors.push({ field: "phone", label: "telefon", code: "invalid_phone" });
  }

  if (!payload.privacy_notice_acknowledged) {
    errors.push({ field: "privacy_notice_acknowledged", label: "confirmarea citirii informării", code: "required" });
  }

  lengthError(errors, "program_slug", "program", payload.program_slug, 1, 100);
  lengthError(errors, "caen_or_so", "CAEN / SO", payload.caen_or_so, 0, 120);
  lengthError(errors, "budget_estimate", "buget", payload.budget_estimate, 0, 160);
  lengthError(errors, "extended_description", "descriere extinsă", payload.extended_description, 0, 3000);
  lengthError(errors, "documents_summary", "documente", payload.documents_summary, 0, 1000);
  lengthError(errors, "expenses_summary", "cheltuieli", payload.expenses_summary, 0, 1500);
  if (!/^(?:unknown|[a-z0-9]+(?:-[a-z0-9]+)*)$/u.test(payload.program_slug)) {
    errors.push({ field: "program_slug", label: "program", code: "invalid_choice" });
  }
  if (!payload.page_url.startsWith("/") || payload.page_url.length > 300) {
    errors.push({ field: "page_url", label: "pagina sursă", code: "invalid_path" });
  }
  if (payload.referrer_path && (!payload.referrer_path.startsWith("/") || payload.referrer_path.length > 300)) {
    errors.push({ field: "referrer_path", label: "pagina anterioară", code: "invalid_path" });
  }
  if (payload.program_context.length > 100) {
    errors.push({ field: "program_context", label: "context program", code: "invalid_length" });
  }
  lengthError(errors, "program_family", "familie program", payload.program_family, 0, 100);
  lengthError(errors, "source_channel", "canal sursă", payload.source_channel, 0, 80);
  lengthError(errors, "utm_source", "utm_source", payload.utm_source, 0, 160);
  lengthError(errors, "utm_medium", "utm_medium", payload.utm_medium, 0, 160);
  lengthError(errors, "utm_campaign", "utm_campaign", payload.utm_campaign, 0, 200);
  lengthError(errors, "utm_term", "utm_term", payload.utm_term, 0, 200);
  lengthError(errors, "utm_content", "utm_content", payload.utm_content, 0, 200);
  lengthError(errors, "landing_referrer", "referrer inițial", payload.landing_referrer, 0, 500);
  if (payload.landing_page_path && (!payload.landing_page_path.startsWith("/") || payload.landing_page_path.length > 300)) {
    errors.push({ field: "landing_page_path", label: "pagina inițială", code: "invalid_path" });
  }
  if (!["no_preference", "email", "phone"].includes(payload.contact_preference)) {
    errors.push({ field: "contact_preference", label: "preferință de contact", code: "invalid_choice" });
  }
  if (payload.contact_preference === "email" && !payload.email) {
    errors.push({ field: "contact_preference", label: "preferință de contact", code: "email_missing" });
  }
  if (payload.contact_preference === "phone" && !payload.phone) {
    errors.push({ field: "contact_preference", label: "preferință de contact", code: "phone_missing" });
  }

  let timingSuspicious = false;
  if (payload.form_started_at) {
    const startedAt = Number(payload.form_started_at);
    const elapsed = now - startedAt;
    timingSuspicious = !Number.isFinite(startedAt) || elapsed < 1500 || elapsed > 24 * 60 * 60 * 1000;
  }

  return {
    payload,
    errors,
    spam: Boolean(payload.website) || timingSuspicious,
    valid: errors.length === 0
  };
}

async function readContactInput(request) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_CONTACT_BODY_BYTES) throw new Error("payload_too_large");
  const contentType = request.headers.get("content-type") || "";
  if (/application\/json/iu.test(contentType)) return request.json();
  if (/multipart\/form-data|application\/x-www-form-urlencoded/iu.test(contentType)) {
    return Object.fromEntries((await request.formData()).entries());
  }
  throw new Error("unsupported_media_type");
}

function contactForwardPayload(payload, now = new Date()) {
  return {
    schema_version: payload.schema_version,
    lead_id: payload.lead_id || crypto.randomUUID(),
    submitted_at: now.toISOString(),
    applicant_type: payload.applicant_type,
    location: payload.location,
    investment: payload.investment,
    email: payload.email || "—",
    phone: payload.phone || "—",
    privacy_notice_acknowledged: "true",
    privacy_notice_version: "pending_legal_approval",
    program_slug: payload.program_slug,
    caen_or_so: payload.caen_or_so,
    budget_estimate: payload.budget_estimate,
    extended_description: payload.extended_description || "—",
    documents_summary: payload.documents_summary || "—",
    expenses_summary: payload.expenses_summary || "—",
    contact_preference: payload.contact_preference,
    page_url: payload.page_url,
    referrer_path: payload.referrer_path || "—",
    program_context: payload.program_context || "—",
    program_family: payload.program_family || "—",
    source_channel: payload.source_channel || "direct",
    utm_source: payload.utm_source || "—",
    utm_medium: payload.utm_medium || "—",
    utm_campaign: payload.utm_campaign || "—",
    utm_term: payload.utm_term || "—",
    utm_content: payload.utm_content || "—",
    landing_referrer: payload.landing_referrer || "—",
    landing_page_path: payload.landing_page_path || payload.page_url,
    _subject: "Solicitare triere FABER",
    _template: "table"
  };
}

function secureEquals(left, right) {
  left = typeof left === "string" ? left : "";
  right = typeof right === "string" ? right : "";
  let mismatch = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    mismatch |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return mismatch === 0;
}

function qualifiedLeadPayload(input) {
  const allowedKeys = new Set([
    "lead_correlation_id",
    "page_path",
    "page_type",
    "program_slug",
    "program_family",
    "form_version",
    "source_channel",
    "experiment_id"
  ]);
  const payload = {
    lead_correlation_id: clean(input.lead_correlation_id),
    page_path: clean(input.page_path),
    page_type: clean(input.page_type),
    program_slug: clean(input.program_slug),
    program_family: clean(input.program_family),
    form_version: clean(input.form_version),
    source_channel: clean(input.source_channel),
    experiment_id: clean(input.experiment_id)
  };
  const errors = [];
  for (const key of Object.keys(input)) if (!allowedKeys.has(key)) errors.push(key);
  if (!/^[a-zA-Z0-9._:-]{8,100}$/u.test(payload.lead_correlation_id)) errors.push("lead_correlation_id");
  if (payload.page_path && (!payload.page_path.startsWith("/") || payload.page_path.length > 300)) errors.push("page_path");
  for (const key of ["page_type", "program_slug", "program_family", "form_version", "source_channel", "experiment_id"]) {
    if (payload[key].length > 100 || (payload[key] && !/^[a-zA-Z0-9_./:-]+$/u.test(payload[key]))) errors.push(key);
  }
  return { payload, errors };
}

export async function handleQualifiedLeadRequest(request, options = {}) {
  if (request.method !== "POST") return secured(new Response(null, { status: 405, headers: { allow: "POST" } }));
  const expectedSecret = options.webhookSecret || "";
  const providedSecret = (request.headers.get("authorization") || "").replace(/^Bearer\s+/iu, "");
  if (!expectedSecret || !secureEquals(providedSecret, expectedSecret)) {
    return responseBody(request, 401, { success: false, message: "Webhook CRM neautorizat." });
  }
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_ANALYTICS_BODY_BYTES || !/application\/json/iu.test(request.headers.get("content-type") || "")) {
    return responseBody(request, 415, { success: false, message: "Format webhook neacceptat." });
  }
  let input;
  try {
    input = await request.json();
  } catch {
    return responseBody(request, 400, { success: false, message: "JSON invalid." });
  }
  const checked = qualifiedLeadPayload(input || {});
  if (checked.errors.length) {
    return responseBody(request, 422, { success: false, message: "Payload analytics invalid.", fields: checked.errors });
  }
  if (!options.analyticsForwardUrl) {
    return responseBody(request, 503, { success: false, message: "Destinația analytics server-side nu este configurată." });
  }
  try {
    const destination = new URL(options.analyticsForwardUrl);
    if (destination.protocol !== "https:") throw new Error("analytics_forward_must_use_https");
    const forwardFetch = options.forwardFetch || fetch;
    const body = { event: "qualified_lead" };
    for (const [key, value] of Object.entries(checked.payload)) if (value) body[key] = value;
    const forwarded = await forwardFetch(destination.toString(), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body)
    });
    if (!forwarded.ok) throw new Error("analytics_forward_failed");
    return responseBody(request, 202, { success: true });
  } catch {
    return responseBody(request, 502, { success: false, message: "Destinația analytics nu a confirmat evenimentul." });
  }
}

function sameOriginAllowed(request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).hostname === CANONICAL_HOST;
  } catch {
    return false;
  }
}

export async function handleContactTriageRequest(request, options = {}) {
  if (request.method !== "POST") {
    return secured(new Response(null, { status: 405, headers: { allow: "POST" } }));
  }
  if (!sameOriginAllowed(request)) {
    return responseBody(request, 403, { success: false, message: "Originea solicitării nu este permisă." });
  }

  let input;
  try {
    input = await readContactInput(request);
  } catch (error) {
    const status = error.message === "payload_too_large" ? 413 : 415;
    return responseBody(request, status, { success: false, message: "Formatul solicitării nu este acceptat." });
  }

  const checked = validateContactPayload(input, options.now ?? Date.now());
  if (checked.spam) {
    return responseBody(request, 200, { success: true });
  }
  if (!checked.valid) {
    return responseBody(request, 422, {
      success: false,
      message: "Verifică răspunsurile obligatorii.",
      errors: checked.errors
    });
  }

  const forwardUrl = options.forwardUrl;
  if (!forwardUrl) {
    return responseBody(request, 503, {
      success: false,
      message: "Canalul de trimitere nu este configurat încă. Valorile au rămas în formular; încearcă din nou după configurare."
    });
  }
  try {
    const parsed = new URL(forwardUrl);
    if (parsed.protocol !== "https:") throw new Error("forward_url_must_use_https");
    const forwardFetch = options.forwardFetch || fetch;
    const forwarded = await forwardFetch(parsed.toString(), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(contactForwardPayload(checked.payload, options.submittedAt || new Date()))
    });
    if (!forwarded.ok) throw new Error("forward_failed");
    const leadId = checked.payload.lead_id || "generated-server-side";
    return responseBody(request, 200, { success: true, leadId });
  } catch {
    return responseBody(request, 502, {
      success: false,
      message: "Canalul de trimitere nu a confirmat solicitarea. Valorile au rămas în formular; încearcă din nou."
    });
  }
}

export async function handleRequest(request, originFetch = fetch, environment = {}) {
  const url = new URL(request.url);

  // This rule comes first so the historical HTTP SearchAction URL resolves in
  // one hop to the canonical homepage, without carrying the obsolete query.
  if (isLegacySearchPlaceholder(url)) {
    return permanentRedirect(`https://${CANONICAL_HOST}/`);
  }

  if (url.protocol === "http:") {
    url.protocol = "https:";
    url.hostname = CANONICAL_HOST;
    url.port = "";
    return permanentRedirect(url.toString());
  }

  if (url.hostname !== CANONICAL_HOST) {
    url.protocol = "https:";
    url.hostname = CANONICAL_HOST;
    url.port = "";
    return permanentRedirect(url.toString());
  }

  if (url.hostname === CANONICAL_HOST && url.pathname === CONTACT_ENDPOINT) {
    return handleContactTriageRequest(request, {
      forwardUrl: environment.CONTACT_FORM_FORWARD_URL,
      forwardFetch: environment.forwardFetch,
      now: environment.now,
      submittedAt: environment.submittedAt
    });
  }

  if (url.hostname === CANONICAL_HOST && url.pathname === QUALIFIED_LEAD_ENDPOINT) {
    return handleQualifiedLeadRequest(request, {
      webhookSecret: environment.CRM_ANALYTICS_WEBHOOK_SECRET,
      analyticsForwardUrl: environment.ANALYTICS_EVENT_FORWARD_URL,
      forwardFetch: environment.analyticsForwardFetch || environment.forwardFetch
    });
  }

  const response = await originFetch(request);
  return secured(response);
}

export default {
  fetch(request, env) {
    return handleRequest(request, fetch, env);
  }
};
