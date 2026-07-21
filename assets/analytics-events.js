(function (window, document) {
  "use strict";

  if (window.__faberAnalyticsEventsInitialized) return;
  window.__faberAnalyticsEventsInitialized = true;
  window.dataLayer = window.dataLayer || [];

  var CLARITY_PROJECT_ID = "wnvzyco6rq";
  var CLARITY_SRC = "https://www.clarity.ms/tag/" + CLARITY_PROJECT_ID;
  var FORM_VERSION = "short_v1";
  var FUNNEL_EVENTS = new Set([
    "cta_view",
    "cta_click",
    "form_start",
    "step_1_complete",
    "field_error",
    "form_submit",
    "contact_whatsapp",
    "contact_phone",
    "contact_email",
    "qualified_lead"
  ]);
  var SUPPORTING_EVENTS = new Set([
    "nav_click",
    "program_menu_click",
    "whatsapp_dialog_open",
    "calculator_start",
    "calculator_complete",
    "calculator_result_to_dr12",
    "calculator_result_to_dr14",
    "source_document_click",
    "next_step_click",
    "carousel_interaction",
    "program_card_click"
  ]);
  var LEGACY_ALIASES = Object.freeze({
    eligibility_cta_click: "cta_click",
    contact_page_click: "cta_click",
    whatsapp_number_click: "contact_whatsapp",
    phone_click: "contact_phone",
    email_click: "contact_email",
    form_submit_success: "form_submit",
    form_validation_error: "field_error"
  });
  var PAYLOAD_KEYS = [
    "page_path",
    "page_type",
    "cta_id",
    "cta_copy_variant",
    "program_slug",
    "program_family",
    "form_version",
    "step",
    "field_name_generic",
    "device_category",
    "source_channel",
    "experiment_id",
    "error_type",
    "lead_correlation_id"
  ];
  var GENERIC_FIELDS = new Set([
    "applicant_type",
    "location",
    "investment",
    "contact_method",
    "email",
    "phone",
    "privacy_notice",
    "program",
    "caen_or_so",
    "budget_estimate",
    "extended_description",
    "documents_summary",
    "expenses_summary",
    "contact_preference",
    "form"
  ]);
  var TAG_PREFIX = "faber_event_";
  var trackedOnce = new Set();
  var startedForms = new WeakSet();
  var calculatorStarted = new WeakSet();
  var programContext = { slug: "", family: "" };

  function clarityQueue() {
    if (typeof window.clarity === "function") return window.clarity;
    var queue = function () {
      (queue.q = queue.q || []).push(arguments);
    };
    queue.__faberQueue = true;
    window.clarity = queue;
    return queue;
  }

  function loadClarity() {
    if (window.__faberClarityLoaded) return;
    if (typeof window.clarity === "function" && !window.clarity.__faberQueue) {
      window.__faberClarityLoaded = true;
      return;
    }
    if (document.querySelector('script[src^="https://www.clarity.ms/tag/"]')) {
      window.__faberClarityLoaded = true;
      return;
    }
    window.__faberClarityLoaded = true;
    clarityQueue();
    try {
      var script = document.createElement("script");
      script.async = true;
      script.src = CLARITY_SRC;
      script.setAttribute("data-faber-clarity-loader", "");
      var firstScript = document.getElementsByTagName("script")[0];
      if (firstScript && firstScript.parentNode) firstScript.parentNode.insertBefore(script, firstScript);
      else (document.head || document.documentElement).appendChild(script);
    } catch (_) {}
  }

  function scheduleClarity() {
    window.setTimeout(loadClarity, 1500);
  }

  clarityQueue();
  if (document.readyState === "complete") scheduleClarity();
  else window.addEventListener("load", scheduleClarity, { once: true });
  ["pointerdown", "keydown", "scroll"].forEach(function (eventName) {
    window.addEventListener(eventName, loadClarity, { once: true, passive: true });
  });

  function cleanToken(value, maximum) {
    if (typeof value !== "string") return "";
    return value
      .trim()
      .slice(0, maximum || 120)
      .toLowerCase()
      .replace(/[^a-z0-9_./:\-]/g, "_")
      .replace(/_+/g, "_");
  }

  function currentPath() {
    var path = typeof window.location.pathname === "string" ? window.location.pathname : "/";
    return path.startsWith("/") ? cleanToken(path, 300) || "/" : "/";
  }

  function deviceCategory() {
    var width = Number(window.innerWidth) || 1024;
    if (width < 768) return "mobile";
    if (width < 1100) return "tablet";
    return "desktop";
  }

  function pageType() {
    var body = document.body;
    var explicit = body && body.getAttribute("data-analytics-page-type");
    if (explicit) return cleanToken(explicit);
    var path = currentPath();
    if (path === "/") return "home";
    if (path === "/contact") return "contact";
    if (/calculator|instrumente|verificare-eligibilitate/.test(path)) return "tool";
    if (body && body.getAttribute("data-program-id")) return "program";
    if (/blog|ghid|intrebari|cheltuieli|documente|conditii|greseli/.test(path)) return "content";
    return "page";
  }

  var attribution = window.FaberAttribution && typeof window.FaberAttribution.getCrmAttribution === "function"
    ? window.FaberAttribution.getCrmAttribution()
    : { source_channel: "direct" };

  function bodyProgramContext() {
    var body = document.body;
    return {
      slug: programContext.slug || cleanToken(body && (body.getAttribute("data-analytics-program-slug") || body.getAttribute("data-program-id")) || ""),
      family: programContext.family || cleanToken(body && body.getAttribute("data-analytics-program-family") || "")
    };
  }

  function safePayload(input) {
    input = input && typeof input === "object" ? input : {};
    var context = bodyProgramContext();
    var payload = {
      page_path: currentPath(),
      page_type: cleanToken(input.page_type || input.pageType || pageType()),
      cta_id: cleanToken(input.cta_id || input.ctaId || ""),
      cta_copy_variant: cleanToken(input.cta_copy_variant || input.ctaCopyVariant || ""),
      program_slug: cleanToken(input.program_slug || input.programSlug || context.slug),
      program_family: cleanToken(input.program_family || input.programFamily || context.family),
      form_version: cleanToken(input.form_version || input.formVersion || ""),
      step: cleanToken(input.step || ""),
      field_name_generic: cleanToken(input.field_name_generic || input.fieldNameGeneric || ""),
      device_category: deviceCategory(),
      source_channel: cleanToken(input.source_channel || input.sourceChannel || attribution.source_channel || "direct"),
      experiment_id: cleanToken(input.experiment_id || input.experimentId || ""),
      error_type: cleanToken(input.error_type || input.errorType || ""),
      lead_correlation_id: cleanToken(input.lead_correlation_id || input.leadCorrelationId || "", 100)
    };
    if (!GENERIC_FIELDS.has(payload.field_name_generic)) delete payload.field_name_generic;
    PAYLOAD_KEYS.forEach(function (key) {
      if (!payload[key]) delete payload[key];
    });
    return payload;
  }

  function closestContext(element) {
    return element && element.closest ? element.closest("[data-program-id], [data-analytics-program-slug]") : null;
  }

  function payloadFromElement(element) {
    var context = closestContext(element);
    return safePayload({
      cta_id: element.getAttribute("data-analytics-cta-id") || "",
      cta_copy_variant: element.getAttribute("data-analytics-copy-variant") || "default",
      program_slug: element.getAttribute("data-analytics-program-slug") || (context && (context.getAttribute("data-analytics-program-slug") || context.getAttribute("data-program-id"))) || "",
      program_family: element.getAttribute("data-analytics-program-family") || (context && context.getAttribute("data-analytics-program-family")) || "",
      form_version: element.getAttribute("data-analytics-form-version") || "",
      step: element.getAttribute("data-analytics-step") || "",
      experiment_id: element.getAttribute("data-analytics-experiment-id") || ""
    });
  }

  function emitBrowserEvent(name, payload) {
    var snapshot = Object.assign({ event: name }, payload);
    try {
      window.dataLayer = window.dataLayer || [];
      window.dataLayer.push(snapshot);
    } catch (_) {}
    if (/(?:^|[?&])analytics_debug=1(?:&|$)/.test(window.location.search || "")) {
      window.__faberAnalyticsDebug = window.__faberAnalyticsDebug || [];
      window.__faberAnalyticsDebug.push(Object.assign({ timestamp: new Date().toISOString() }, snapshot));
    }
    try {
      document.dispatchEvent(new CustomEvent("faber:analytics-event", {
        detail: { name: name, payload: Object.assign({}, payload) }
      }));
    } catch (_) {}
  }

  function canonicalEventName(name) {
    return LEGACY_ALIASES[name] || name;
  }

  function track(name, input) {
    name = canonicalEventName(name);
    if (!FUNNEL_EVENTS.has(name) && !SUPPORTING_EVENTS.has(name)) return false;
    var payload = safePayload(input);
    var clarity = clarityQueue();
    PAYLOAD_KEYS.forEach(function (key) {
      if (payload[key]) clarity("set", TAG_PREFIX + key, payload[key]);
    });
    clarity("event", name);
    emitBrowserEvent(name, payload);
    return true;
  }

  function trackOnce(name, input, key) {
    name = canonicalEventName(name);
    var onceKey = key || name;
    if (trackedOnce.has(onceKey)) return false;
    if (!track(name, input)) return false;
    trackedOnce.add(onceKey);
    return true;
  }

  function closestForm(node) {
    return node && node.closest ? node.closest("form[data-analytics-form]") : null;
  }

  function formPayload(form, extra) {
    return Object.assign({
      cta_id: form.getAttribute("data-analytics-form") || "public_form",
      form_version: form.getAttribute("data-analytics-form-version") || FORM_VERSION
    }, extra || {});
  }

  function startForm(form) {
    if (!form || startedForms.has(form)) return false;
    startedForms.add(form);
    return track("form_start", formPayload(form, { step: "1" }));
  }

  function genericFieldName(field) {
    if (!field || !field.getAttribute) return "form";
    var explicit = cleanToken(field.getAttribute("data-analytics-field") || "");
    if (GENERIC_FIELDS.has(explicit)) return explicit;
    var name = cleanToken(field.getAttribute("name") || "");
    if (name === "privacy_notice_acknowledged") return "privacy_notice";
    if (name === "program_slug") return "program";
    return GENERIC_FIELDS.has(name) ? name : "form";
  }

  function inferredErrorType(field) {
    if (!field || !field.validity) return "validation";
    if (field.validity.valueMissing) return "required";
    if (field.validity.typeMismatch) return "format";
    if (field.validity.tooShort || field.validity.tooLong) return "length";
    if (field.validity.patternMismatch) return "pattern";
    if (field.validity.customError) return "custom";
    return "validation";
  }

  function fieldError(form, field, errorType) {
    if (!form) return false;
    return track("field_error", formPayload(form, {
      step: "1",
      field_name_generic: genericFieldName(field),
      error_type: cleanToken(errorType || inferredErrorType(field))
    }));
  }

  function stepOneComplete(form) {
    if (!form) return false;
    var formId = form.getAttribute("data-analytics-form") || "public_form";
    return trackOnce("step_1_complete", formPayload(form, { step: "1" }), "step_1_complete:" + formId);
  }

  function formSubmit(form, leadCorrelationId) {
    if (!form) return false;
    var formId = form.getAttribute("data-analytics-form") || "public_form";
    return trackOnce("form_submit", formPayload(form, {
      step: "2",
      lead_correlation_id: leadCorrelationId || ""
    }), "form_submit:" + formId + ":" + cleanToken(leadCorrelationId || "confirmed", 100));
  }

  function observeCtas() {
    var elements = Array.prototype.slice.call(document.querySelectorAll('[data-analytics-cta-view="true"]'));
    if (!elements.length || typeof window.IntersectionObserver !== "function") return;
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting || entry.intersectionRatio < 0.5) return;
        var element = entry.target;
        var ctaId = element.getAttribute("data-analytics-cta-id") || "cta";
        trackOnce("cta_view", payloadFromElement(element), "cta_view:" + currentPath() + ":" + ctaId);
        observer.unobserve(element);
      });
    }, { threshold: [0.5] });
    elements.forEach(function (element) { observer.observe(element); });
  }

  document.addEventListener("click", function (event) {
    var target = event.target && event.target.closest ? event.target.closest("[data-analytics-event]") : null;
    if (target) {
      var names = (target.getAttribute("data-analytics-event") || "").trim().split(/\s+/);
      names.forEach(function (name) { if (name) track(name, payloadFromElement(target)); });
    }

    var calculatorAction = event.target && event.target.closest ? event.target.closest("[data-calculator-action]") : null;
    if (calculatorAction) {
      var calculator = calculatorAction.closest("[data-analytics-calculator]");
      if (calculator && !calculatorStarted.has(calculator)) {
        calculatorStarted.add(calculator);
        trackOnce("calculator_start", {
          cta_id: calculator.getAttribute("data-analytics-calculator") || "calculator"
        });
      }
    }
  }, true);

  ["pointerdown", "keydown", "input", "change"].forEach(function (eventName) {
    document.addEventListener(eventName, function (event) {
      startForm(closestForm(event.target));
    }, true);
  });

  document.addEventListener("invalid", function (event) {
    fieldError(closestForm(event.target), event.target);
  }, true);

  document.addEventListener("faber:whatsapp-dialog-open", function () {
    track("whatsapp_dialog_open", { cta_id: "eligibility_dialog" });
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", observeCtas, { once: true });
  else observeCtas();

  window.FaberAnalytics = Object.freeze({
    events: Object.freeze(Array.from(FUNNEL_EVENTS).concat(Array.from(SUPPORTING_EVENTS))),
    funnelEvents: Object.freeze(Array.from(FUNNEL_EVENTS)),
    payloadKeys: Object.freeze(PAYLOAD_KEYS.slice()),
    track: track,
    trackOnce: trackOnce,
    fieldError: fieldError,
    formValidationError: function (form, field, errorType) { return fieldError(form, field, errorType); },
    stepOneComplete: stepOneComplete,
    formSubmit: formSubmit,
    formSubmitSuccess: function (form, details) {
      var leadId = details && (details.lead_correlation_id || details.leadCorrelationId);
      return formSubmit(form, leadId || "");
    },
    setProgramContext: function (slug, family) {
      programContext.slug = cleanToken(slug || "");
      programContext.family = cleanToken(family || "");
    },
    getCrmAttribution: function () { return Object.assign({}, attribution); },
    calculatorComplete: function () {
      return trackOnce("calculator_complete", { cta_id: "calculator_soc" });
    }
  });
  try { document.dispatchEvent(new CustomEvent("faber:analytics-ready")); } catch (_) {}
})(window, document);
