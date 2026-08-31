(function () {
  "use strict";

  var form = document.getElementById("contact-triage-form");
  if (!form) return;

  var stepOne = form.querySelector('[data-form-step="1"]');
  var stepTwo = form.querySelector('[data-form-step="2"]');
  var summary = form.querySelector("[data-form-summary]");
  var summaryList = form.querySelector("[data-summary-list]");
  var alertBox = form.querySelector("[data-form-alert]");
  var alertMessage = form.querySelector("[data-form-alert-message]");
  var retryButton = form.querySelector("[data-retry-submit]");
  var errorSummary = form.querySelector("[data-error-summary]");
  var errorSummaryList = form.querySelector("[data-error-summary-list]");
  var success = document.querySelector("[data-form-success]");
  var email = form.elements.email;
  var phone = form.elements.phone;
  var contactError = form.querySelector("[data-contact-method-error]");
  var submitButton = form.querySelector("[data-final-submit]");
  var submitLabel = form.querySelector("[data-submit-label]");
  var submitSpinner = form.querySelector("[data-submit-spinner]");
  var submitStatus = form.querySelector("[data-submit-status]");
  var lastDetailed = false;
  var isSubmitting = false;

  function randomId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    return "lead-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
  }

  function setHidden(name, value) {
    var field = form.elements[name];
    if (field) field.value = value;
  }

  function scrollBehavior() {
    return document.documentElement.classList.contains("im-motion-off") || (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) ? "auto" : "smooth";
  }

  function scrollToPanel(element) {
    if (!element) return;
    element.scrollIntoView({ behavior: scrollBehavior(), block: "start" });
    var heading = element.querySelector("h2, [tabindex='-1'], strong");
    if (heading && typeof heading.focus === "function") {
      if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
      heading.focus({ preventScroll: true });
    }
  }

  function clearAlert() {
    if (!alertBox) return;
    alertBox.hidden = true;
    if (alertMessage) alertMessage.textContent = "";
    if (retryButton) retryButton.hidden = true;
  }

  function showAlert(message, allowRetry) {
    if (!alertBox) return;
    if (alertMessage) alertMessage.textContent = message;
    if (retryButton) retryButton.hidden = !allowRetry;
    alertBox.hidden = false;
    alertBox.focus({ preventScroll: true });
    alertBox.scrollIntoView({ behavior: "auto", block: "center" });
  }

  function clearErrorSummary() {
    if (!errorSummary) return;
    errorSummary.hidden = true;
    if (errorSummaryList) errorSummaryList.textContent = "";
  }

  function showOnly(section, shouldScroll) {
    [stepOne, stepTwo, summary].forEach(function (item) {
      if (item) item.hidden = item !== section;
    });
    clearAlert();
    clearErrorSummary();
    if (shouldScroll !== false) scrollToPanel(section);
  }

  function setFieldError(field, message) {
    if (!field) return;
    var error = form.querySelector('[data-field-error-for="' + field.id + '"]');
    if (message) {
      field.setAttribute("aria-invalid", "true");
      if (error) {
        error.textContent = message;
        error.removeAttribute("aria-hidden");
        error.hidden = false;
      }
      return;
    }
    field.removeAttribute("aria-invalid");
    if (error) {
      error.textContent = "";
      error.setAttribute("aria-hidden", "true");
      error.hidden = true;
    }
  }

  function clearContactError() {
    [email, phone].forEach(function (field) { field.removeAttribute("aria-invalid"); });
    if (contactError) {
      contactError.setAttribute("aria-hidden", "true");
      contactError.hidden = true;
    }
  }

  function showContactError(message) {
    [email, phone].forEach(function (field) { field.setAttribute("aria-invalid", "true"); });
    if (contactError) {
      contactError.textContent = message;
      contactError.removeAttribute("aria-hidden");
      contactError.hidden = false;
    }
  }

  function phoneLooksValid(value) {
    var digits = String(value || "").replace(/\D/g, "");
    return digits.length >= 7 && digits.length <= 16;
  }

  function contactMethodError() {
    var emailValue = email.value.trim();
    var phoneValue = phone.value.trim();
    var message = "";

    if (!emailValue && !phoneValue) message = "Completează o adresă de email sau un număr de telefon.";
    else if (phoneValue && !phoneLooksValid(phoneValue)) message = "Numărul de telefon pare incomplet.";

    email.setCustomValidity(message);
    phone.setCustomValidity(message);
    return message;
  }

  function requiredFieldError(field, emptyMessage, shortMessage) {
    if (field.validity.valueMissing) return emptyMessage;
    if (field.validity.tooShort) return shortMessage || emptyMessage;
    if (field.validity.typeMismatch) return "Introdu o adresă de email într-un format valid.";
    return "Verifică valoarea introdusă.";
  }

  function collectStepOneErrors() {
    var errors = [];
    var applicant = form.elements.applicant_type;
    var location = form.elements.location;
    var investment = form.elements.investment;
    var privacy = form.elements.privacy_notice_acknowledged;

    [applicant, location, investment, privacy].forEach(function (field) { setFieldError(field, ""); });
    clearContactError();

    if (!applicant.checkValidity()) {
      errors.push({ field: applicant, message: requiredFieldError(applicant, "Alege tipul solicitantului.") });
    }
    if (!location.checkValidity()) {
      errors.push({ field: location, message: requiredFieldError(location, "Completează județul sau localitatea.", "Introdu cel puțin 2 caractere pentru localitate.") });
    }
    if (!investment.checkValidity()) {
      errors.push({ field: investment, message: requiredFieldError(investment, "Descrie pe scurt investiția.", "Descrierea investiției trebuie să aibă cel puțin 5 caractere.") });
    }

    var methodMessage = contactMethodError();
    if (methodMessage) {
      errors.push({ field: email, message: methodMessage, contactGroup: true });
    } else if (email.value.trim() && email.validity.typeMismatch) {
      errors.push({ field: email, message: "Introdu o adresă de email într-un format valid.", contactGroup: true });
    }

    if (!privacy.checkValidity()) {
      errors.push({ field: privacy, message: "Confirmă că ai citit informarea privind prelucrarea datelor." });
    }
    return errors;
  }

  function renderErrorSummary(errors) {
    if (!errorSummary || !errorSummaryList) return;
    errorSummaryList.textContent = "";
    errors.forEach(function (error) {
      var item = document.createElement("li");
      var link = document.createElement("a");
      link.href = "#" + error.field.id;
      link.textContent = error.message;
      link.setAttribute("data-error-target", error.field.id);
      item.appendChild(link);
      errorSummaryList.appendChild(item);
      if (error.contactGroup) showContactError(error.message);
      else setFieldError(error.field, error.message);
    });
    errorSummary.hidden = false;
  }

  function validateStepOne() {
    clearAlert();
    var errors = collectStepOneErrors();
    if (!errors.length) {
      clearErrorSummary();
      if (window.FaberAnalytics) window.FaberAnalytics.stepOneComplete(form);
      return true;
    }

    if (window.FaberAnalytics) {
      errors.forEach(function (error) {
        window.FaberAnalytics.fieldError(form, error.field, error.errorType || (error.contactGroup ? "one_required" : "validation"));
      });
    }
    if (stepOne.hidden) showOnly(stepOne);
    renderErrorSummary(errors);
    window.requestAnimationFrame(function () {
      errors[0].field.focus({ preventScroll: true });
      errors[0].field.scrollIntoView({ behavior: "auto", block: "center" });
    });
    return false;
  }

  function selectedText(select) {
    if (!select || select.selectedIndex < 0) return "—";
    return select.options[select.selectedIndex].textContent.trim();
  }

  function valueOrDash(field) {
    var value = field && String(field.value || "").trim();
    return value || "—";
  }

  function addSummaryRow(label, value) {
    var row = document.createElement("div");
    var term = document.createElement("dt");
    var description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    row.appendChild(term);
    row.appendChild(description);
    summaryList.appendChild(row);
  }

  function renderSummary(includeDetails) {
    summaryList.textContent = "";
    addSummaryRow("Tip solicitant", selectedText(form.elements.applicant_type));
    addSummaryRow("Județ / localitate", valueOrDash(form.elements.location));
    addSummaryRow("Investiție", valueOrDash(form.elements.investment));
    addSummaryRow("Email", valueOrDash(email));
    addSummaryRow("Telefon", valueOrDash(phone));
    addSummaryRow("Program vizat", selectedText(form.elements.program_slug));
    if (form.elements.calculator_so_result && form.elements.calculator_so_result.value) {
      addSummaryRow("Rezultat SO orientativ", form.elements.calculator_so_result.value + " SO");
    }
    addSummaryRow("CAEN / SO", valueOrDash(form.elements.caen_or_so));
    addSummaryRow("Buget / cofinanțare", valueOrDash(form.elements.budget_estimate));

    if (includeDetails) {
      addSummaryRow("Descriere extinsă", valueOrDash(form.elements.extended_description));
      addSummaryRow("Documente disponibile", valueOrDash(form.elements.documents_summary));
      addSummaryRow("Cheltuieli", valueOrDash(form.elements.expenses_summary));
      addSummaryRow("Preferință de contact", selectedText(form.elements.contact_preference));
    }
  }

  function openSummary(includeDetails) {
    if (!validateStepOne()) return;
    lastDetailed = includeDetails;
    renderSummary(includeDetails);
    showOnly(summary);
  }

  function prefillProgram() {
    var select = form.elements.program_slug;
    if (!select) return;
    var params = new URLSearchParams(window.location.search);
    if (!params.toString() && window.location.hash.length > 1) {
      params = new URLSearchParams(window.location.hash.slice(1).replace(/^\?/, ""));
    }
    var requested = params.get("program_slug") || params.get("program") || params.get("programSlug") || "";
    var requestedSource = params.get("source_page") || "";
    var requestedSo = params.get("so_result") || "";
    var referrerPath = "";

    try {
      if (document.referrer) {
        var referrer = new URL(document.referrer);
        if (referrer.origin === window.location.origin) referrerPath = referrer.pathname.replace(/\/$/, "") || "/";
      }
    } catch (_) {}

    var matching = Array.prototype.find.call(select.options, function (option) {
      var route = (option.getAttribute("data-page-url") || "").replace(/\/$/, "");
      return requested && (option.value === requested || route === requested.replace(/\/$/, ""));
    });
    if (!matching && referrerPath) {
      matching = Array.prototype.find.call(select.options, function (option) {
        var canonical = (option.getAttribute("data-page-url") || "").replace(/\/$/, "");
        var aliases = (option.getAttribute("data-page-aliases") || "").split("|").map(function (route) {
          return route.replace(/\/$/, "");
        });
        return canonical === referrerPath || aliases.includes(referrerPath);
      });
    }
    if (matching) {
      select.value = matching.value;
      setHidden("program_context", matching.value);
      setHidden("program_family", matching.getAttribute("data-program-family") || "");
      if (window.FaberAnalytics) {
        window.FaberAnalytics.setProgramContext(matching.value, matching.getAttribute("data-program-family") || "");
      }
      var optional = select.closest("details");
      if (optional) optional.open = true;
    }
    setHidden("referrer_path", referrerPath);
    var sourcePage = /^\/(?!\/)[^?#]{0,299}$/u.test(requestedSource) ? requestedSource : referrerPath;
    setHidden("source_page", sourcePage || "/");
    if (/^[1-9][0-9]{0,9}$/u.test(requestedSo) && Number(requestedSo) <= 1000000000) {
      setHidden("calculator_so_result", requestedSo);
    }
  }

  function syncProgramContext() {
    var select = form.elements.program_slug;
    if (!select || select.selectedIndex < 0) return;
    var option = select.options[select.selectedIndex];
    var slug = option.value === "unknown" ? "" : option.value;
    var family = option.getAttribute("data-program-family") || "";
    setHidden("program_context", slug);
    setHidden("program_family", family);
    if (window.FaberAnalytics) window.FaberAnalytics.setProgramContext(slug, family);
  }

  function syncAttribution() {
    var source = window.FaberAttribution && typeof window.FaberAttribution.getCrmAttribution === "function"
      ? window.FaberAttribution
      : window.FaberAnalytics;
    if (!source || typeof source.getCrmAttribution !== "function") return;
    var values = source.getCrmAttribution();
    ["source_channel", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "landing_referrer", "landing_page_path"].forEach(function (name) {
      setHidden(name, values[name] || "");
    });
    syncProgramContext();
  }

  function setLoading(loading) {
    isSubmitting = loading;
    form.setAttribute("aria-busy", loading ? "true" : "false");
    if (submitButton) {
      submitButton.disabled = loading;
      submitButton.setAttribute("aria-disabled", loading ? "true" : "false");
    }
    if (submitLabel) submitLabel.textContent = loading ? "Se trimite…" : "Trimite solicitarea";
    if (submitSpinner) submitSpinner.hidden = !loading;
    if (submitStatus) submitStatus.textContent = loading ? "Solicitarea se trimite. Așteaptă confirmarea." : "";
  }

  async function submitForm() {
    if (isSubmitting || !validateStepOne()) return;

    setLoading(true);
    clearAlert();

    try {
      var response = await fetch(form.action, {
        method: "POST",
        headers: { Accept: "application/json", "X-Requested-With": "fetch" },
        body: new FormData(form),
        credentials: "same-origin"
      });
      var data = {};
      try { data = await response.json(); } catch (_) {}

      if (!response.ok || data.success !== true) {
        throw new Error(data.message || "Solicitarea nu a putut fi trimisă.");
      }

      if (window.FaberAnalytics && data.leadId) {
        window.FaberAnalytics.formSubmitSuccess(form, { leadCorrelationId: data.leadId });
      }
      setLoading(false);
      form.hidden = true;
      success.hidden = false;
      success.focus({ preventScroll: true });
      success.scrollIntoView({ behavior: scrollBehavior(), block: "center" });
    } catch (error) {
      setLoading(false);
      showAlert(error.message || "Solicitarea nu a putut fi trimisă. Valorile au fost păstrate; folosește butonul de reîncercare.", true);
    }
  }

  form.classList.add("contact-triage--enhanced");
  form.noValidate = true;
  form.setAttribute("aria-busy", "false");
  form.querySelectorAll(".contact-progressive-actions").forEach(function (actions) { actions.hidden = false; });
  setHidden("lead_id", randomId());
  setHidden("form_started_at", String(Date.now()));
  setHidden("page_url", window.location.pathname);
  prefillProgram();
  document.addEventListener("faber:attribution-ready", syncAttribution, { once: true });
  document.addEventListener("faber:analytics-ready", syncAttribution, { once: true });
  syncAttribution();
  showOnly(stepOne, !form.closest("#homepage-contact"));

  [email, phone].forEach(function (field) {
    field.addEventListener("input", function () {
      contactMethodError();
      clearContactError();
      clearErrorSummary();
    });
  });

  if (form.elements.program_slug) form.elements.program_slug.addEventListener("change", syncProgramContext);

  [form.elements.applicant_type, form.elements.location, form.elements.investment, form.elements.privacy_notice_acknowledged].forEach(function (field) {
    field.addEventListener(field.type === "checkbox" || field.tagName === "SELECT" ? "change" : "input", function () {
      setFieldError(field, "");
      clearErrorSummary();
    });
  });

  if (errorSummary) {
    errorSummary.addEventListener("click", function (event) {
      var link = event.target.closest("[data-error-target]");
      if (!link) return;
      event.preventDefault();
      var target = document.getElementById(link.getAttribute("data-error-target"));
      if (target) {
        target.focus({ preventScroll: true });
        target.scrollIntoView({ behavior: "auto", block: "center" });
      }
    });
  }

  if (retryButton) retryButton.addEventListener("click", submitForm);

  form.addEventListener("click", function (event) {
    var button = event.target.closest("[data-action]");
    if (!button) return;
    var action = button.getAttribute("data-action");
    if (action === "review-short") openSummary(false);
    if (action === "add-details" && validateStepOne()) showOnly(stepTwo);
    if (action === "back-to-step-1") showOnly(stepOne);
    if (action === "review-full") openSummary(true);
    if (action === "edit-form") showOnly(lastDetailed ? stepTwo : stepOne);
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    submitForm();
  });
})();
