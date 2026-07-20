(function (window, document) {
  "use strict";

  if (window.__faberAnalyticsEventsInitialized) return;
  window.__faberAnalyticsEventsInitialized = true;

  var CLARITY_PROJECT_ID = "wnvzyco6rq";
  var CLARITY_SRC = "https://www.clarity.ms/tag/" + CLARITY_PROJECT_ID;
  var EVENT_NAMES = new Set([
    "nav_click",
    "program_menu_click",
    "eligibility_cta_click",
    "whatsapp_dialog_open",
    "whatsapp_number_click",
    "contact_page_click",
    "form_start",
    "form_submit_attempt",
    "form_submit_success",
    "form_validation_error",
    "calculator_start",
    "calculator_complete",
    "calculator_result_to_dr12",
    "calculator_result_to_dr14",
    "source_document_click",
    "next_step_click",
    "phone_click",
    "email_click"
  ]);
  var PAYLOAD_KEYS = [
    "route",
    "component_type",
    "cta_id",
    "destination_route",
    "program_category",
    "status"
  ];
  var TAG_PREFIX = "faber_event_";
  var trackedOnce = new Set();
  var startedForms = new WeakSet();
  var formAttempts = new WeakMap();
  var formValidationReports = new WeakMap();
  var calculatorStarted = new WeakSet();

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
    } catch (_) {
      // Analytics must never block the page when the third-party script is unavailable.
    }
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

  function cleanToken(value) {
    if (typeof value !== "string") return "";
    return value
      .trim()
      .slice(0, 160)
      .replace(/[^a-zA-Z0-9_./:\-]/g, "_")
      .replace(/_+/g, "_");
  }

  function normalizeRoute(value, allowExternal) {
    if (typeof value !== "string" || !value.trim()) return "";
    try {
      var url = new URL(value, window.location.origin);
      if (!/^https?:$/.test(url.protocol)) return "";
      var pathname = url.pathname.replace(/\/{2,}/g, "/") || "/";
      if (url.origin === window.location.origin) return cleanToken(pathname);
      return allowExternal ? cleanToken(url.hostname + pathname) : "";
    } catch (_) {
      return "";
    }
  }

  function currentRoute() {
    return normalizeRoute(window.location.pathname || "/", false) || "/";
  }

  function allowedStatus(value) {
    return value === "success" || value === "error" ? value : "";
  }

  function safePayload(input) {
    input = input && typeof input === "object" ? input : {};
    var payload = {
      route: currentRoute(),
      component_type: cleanToken(input.component_type || input.componentType || ""),
      cta_id: cleanToken(input.cta_id || input.ctaId || ""),
      destination_route: normalizeRoute(input.destination_route || input.destinationRoute || "", true),
      program_category: cleanToken(input.program_category || input.programCategory || ""),
      status: allowedStatus(input.status)
    };

    PAYLOAD_KEYS.forEach(function (key) {
      if (!payload[key]) delete payload[key];
    });
    return payload;
  }

  function payloadFromElement(element) {
    return safePayload({
      component_type: element.getAttribute("data-analytics-component") || "",
      cta_id: element.getAttribute("data-analytics-cta-id") || "",
      destination_route: element.getAttribute("data-analytics-target") || "",
      program_category: element.getAttribute("data-analytics-program-category") || "",
      status: element.getAttribute("data-analytics-status") || ""
    });
  }

  function emitBrowserEvent(name, payload) {
    try {
      document.dispatchEvent(new CustomEvent("faber:analytics-event", {
        detail: { name: name, payload: Object.assign({}, payload) }
      }));
    } catch (_) {}
  }

  function track(name, input) {
    if (!EVENT_NAMES.has(name)) return false;
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
    var onceKey = key || name;
    if (trackedOnce.has(onceKey)) return false;
    if (!track(name, input)) return false;
    trackedOnce.add(onceKey);
    return true;
  }

  function closestForm(node) {
    return node && node.closest ? node.closest("form[data-analytics-form]") : null;
  }

  function formPayload(form, status) {
    return {
      component_type: form.getAttribute("data-analytics-component") || "public_form",
      cta_id: form.getAttribute("data-analytics-form") || "public_form",
      status: status || ""
    };
  }

  function startForm(form) {
    if (!form || startedForms.has(form)) return;
    startedForms.add(form);
    track("form_start", formPayload(form));
  }

  function submitAttempt(form, timestamp, source) {
    if (!form) return;
    var previous = formAttempts.get(form) || { clickTime: -Infinity, token: 0 };
    var now = Number(timestamp) || Date.now();
    if (source === "submit" && now - previous.clickTime < 1000) return;
    var state = {
      clickTime: source === "click" ? now : previous.clickTime,
      token: previous.token + 1
    };
    formAttempts.set(form, state);
    track("form_submit_attempt", formPayload(form));
  }

  function formValidationError(form) {
    if (!form) return;
    var attempt = formAttempts.get(form);
    if (!attempt) return;
    if (formValidationReports.get(form) === attempt.token) return;
    formValidationReports.set(form, attempt.token);
    track("form_validation_error", formPayload(form, "error"));
  }

  function formSubmitSuccess(form) {
    if (!form) return;
    trackOnce(
      "form_submit_success",
      formPayload(form, "success"),
      "form_submit_success:" + (form.getAttribute("data-analytics-form") || "public_form")
    );
  }

  document.addEventListener("click", function (event) {
    var target = event.target && event.target.closest
      ? event.target.closest("[data-analytics-event]")
      : null;
    if (target) {
      var names = (target.getAttribute("data-analytics-event") || "").trim().split(/\s+/);
      names.forEach(function (name) {
        if (name) track(name, payloadFromElement(target));
      });
    }

    var submitter = event.target && event.target.closest
      ? event.target.closest('button[type="submit"], input[type="submit"]')
      : null;
    if (submitter) {
      var form = closestForm(submitter);
      if (form) submitAttempt(form, event.timeStamp, "click");
    }

    var calculatorAction = event.target && event.target.closest
      ? event.target.closest("[data-calculator-action]")
      : null;
    if (calculatorAction) {
      var calculator = calculatorAction.closest("[data-analytics-calculator]");
      if (calculator && !calculatorStarted.has(calculator)) {
        calculatorStarted.add(calculator);
        trackOnce("calculator_start", {
          component_type: calculator.getAttribute("data-analytics-component") || "calculator",
          cta_id: calculator.getAttribute("data-analytics-calculator") || "calculator"
        });
      }
    }
  }, true);

  document.addEventListener("focusin", function (event) {
    startForm(closestForm(event.target));
  }, true);

  document.addEventListener("input", function (event) {
    var form = closestForm(event.target);
    if (form) {
      startForm(form);
    }

    var calculator = event.target && event.target.closest
      ? event.target.closest("[data-analytics-calculator]")
      : null;
    if (calculator && !calculatorStarted.has(calculator)) {
      calculatorStarted.add(calculator);
      trackOnce("calculator_start", {
        component_type: calculator.getAttribute("data-analytics-component") || "calculator",
        cta_id: calculator.getAttribute("data-analytics-calculator") || "calculator"
      });
    }
  }, true);

  document.addEventListener("submit", function (event) {
    var form = closestForm(event.target);
    if (form) submitAttempt(form, event.timeStamp, "submit");
  }, true);

  document.addEventListener("invalid", function (event) {
    formValidationError(closestForm(event.target));
  }, true);

  document.addEventListener("faber:whatsapp-dialog-open", function () {
    track("whatsapp_dialog_open", {
      component_type: "whatsapp_dialog",
      cta_id: "eligibility_dialog"
    });
  });

  window.FaberAnalytics = Object.freeze({
    events: Object.freeze(Array.from(EVENT_NAMES)),
    payloadKeys: Object.freeze(PAYLOAD_KEYS.slice()),
    track: track,
    trackOnce: trackOnce,
    formValidationError: formValidationError,
    formSubmitSuccess: formSubmitSuccess,
    calculatorComplete: function () {
      return trackOnce("calculator_complete", {
        component_type: "calculator_so",
        cta_id: "calculator_soc",
        status: "success"
      });
    }
  });
})(window, document);
