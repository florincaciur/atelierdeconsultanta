(function (scope) {
  "use strict";

  const PUBLIC_DATA_MESSAGE = "Datele publice disponibile au fost completate automat. Verificați informațiile și completați datele privind investiția și angajamentele asumate. Criteriile care necesită declarații sau documente rămân «De verificat».";

  function setText(root, selector, value, fallback) {
    const node = root.querySelector(selector);
    if (node) node.textContent = value || fallback || "—";
  }

  function displayDate(value) {
    const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})$/u);
    return match ? `${match[3]}.${match[2]}.${match[1]}` : "—";
  }

  function removeIndicator(field) {
    field?.removeAttribute("data-company-autofilled");
    const wrapper = field?.closest(".micro2-field");
    wrapper?.querySelector(".micro2-auto-badge")?.remove();
    wrapper?.querySelector(".micro2-auto-formatted")?.remove();
  }

  function clearPreviousAutomaticValues(form) {
    form.querySelectorAll("[data-company-autofilled='true']").forEach(function (field) {
      field.value = "";
      removeIndicator(field);
    });
  }

  function addIndicator(field, calculated, value) {
    const wrapper = field.closest(".micro2-field");
    const label = wrapper?.querySelector("label");
    if (!label) return;
    const badge = document.createElement("span");
    badge.className = "micro2-auto-badge";
    badge.textContent = "Completat automat";
    badge.title = calculated
      ? "Valoare calculată: Active imobilizate + Active circulante."
      : "Date preluate din surse publice pe baza CUI-ului.";
    label.appendChild(badge);
    if (["netProfit2025", "turnover2023", "turnover2024", "turnover2025", "assets2025", "debts2025"].includes(field.name)) {
      const formatted = document.createElement("small");
      formatted.className = "micro2-auto-formatted";
      formatted.textContent = `${scope.CompanyDataService.formatNumber(value)} lei`;
      wrapper.appendChild(formatted);
    }
    field.dataset.companyAutofilled = "true";
  }

  function applyMapping(form, mapping) {
    clearPreviousAutomaticValues(form);
    for (const [name, value] of Object.entries(mapping.values)) {
      const field = form.elements.namedItem(name);
      if (!field || !scope.CompanyDataService.AUTO_FIELD_NAMES.includes(name)) continue;
      field.value = String(value);
      addIndicator(field, name === "assets2025", value);
    }
    form.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function renderCompany(root, payload, mapping) {
    const data = payload.data;
    const summary = root.querySelector("[data-company-summary]");
    if (summary) summary.hidden = false;
    setText(root, "[data-company-name]", data.name);
    setText(root, "[data-company-cui]", payload.cui);
    const caen = [data.primaryCaen?.code, data.primaryCaen?.description].filter(Boolean).join(" – ");
    setText(root, "[data-company-caen]", caen);
    setText(root, "[data-company-established]", displayDate(data.establishedAt));
    setText(root, "[data-company-county]", data.registeredOffice?.county);
    setText(root, "[data-company-city]", data.registeredOffice?.city);
    setText(root, "[data-company-status]", data.status);
    setText(root, "[data-company-legal-form]", data.legalForm);
    setText(root, "[data-company-source]", payload.source || "ListaFirme");
    setText(root, "[data-company-success-message]", PUBLIC_DATA_MESSAGE);

    const warning = root.querySelector("[data-company-warning]");
    if (warning) {
      warning.textContent = mapping.warnings.join(" ");
      warning.hidden = mapping.warnings.length === 0;
    }
  }

  function setStatus(root, state, message) {
    const status = root.querySelector("[data-company-lookup-status]");
    if (!status) return;
    status.dataset.state = state;
    status.textContent = message;
  }

  function resetLookup(root, form) {
    clearPreviousAutomaticValues(form);
    const summary = root.querySelector("[data-company-summary]");
    const warning = root.querySelector("[data-company-warning]");
    if (summary) summary.hidden = true;
    if (warning) warning.hidden = true;
    setStatus(root, "idle", "");
    const input = root.querySelector("[data-company-cui-input]");
    if (input) input.value = "";
  }

  function initRoot(root) {
    const service = scope.CompanyDataService;
    const form = root.querySelector("[data-micro-apel-2-form]");
    const input = root.querySelector("[data-company-cui-input]");
    const button = root.querySelector("[data-company-lookup-button]");
    const lookupCard = root.querySelector("[data-company-lookup]");
    if (!service || !form || !input || !button || !lookupCard) return;
    let loading = false;

    form.addEventListener("input", function (event) {
      const field = event.target;
      if (field?.dataset?.companyAutofilled === "true") removeIndicator(field);
    });

    const verify = async function () {
      if (loading) return;
      const normalized = service.normalizeCui(input.value);
      input.value = normalized;
      if (!service.isValidCui(normalized)) {
        input.setAttribute("aria-invalid", "true");
        setStatus(root, "error", "Introduceți un CUI românesc valid.");
        return;
      }

      input.removeAttribute("aria-invalid");
      loading = true;
      button.disabled = true;
      lookupCard.setAttribute("aria-busy", "true");
      const summary = root.querySelector("[data-company-summary]");
      const warning = root.querySelector("[data-company-warning]");
      if (summary) summary.hidden = true;
      if (warning) warning.hidden = true;
      clearPreviousAutomaticValues(form);
      form.dispatchEvent(new Event("input", { bubbles: true }));
      setStatus(root, "loading", "Se verifică datele societății...");
      try {
        const payload = await service.lookupCompany(normalized);
        const mapping = service.mapCompanyDataToScoreCalculator(payload);
        applyMapping(form, mapping);
        renderCompany(root, payload, mapping);
        setStatus(root, "success", "Date publice verificate");
      } catch (error) {
        const message = error?.code === "company_not_found"
          ? "Nu am identificat o societate pentru CUI-ul introdus. Verificați CUI-ul și încercați din nou."
          : (error?.message || "Datele firmei nu pot fi preluate momentan. Formularul poate fi completat manual.");
        setStatus(root, "error", message);
      } finally {
        loading = false;
        button.disabled = false;
        lookupCard.removeAttribute("aria-busy");
      }
    };

    button.addEventListener("click", verify);
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        verify();
      }
    });
    form.addEventListener("reset", function () { setTimeout(function () { resetLookup(root, form); }, 0); });
  }

  function init() {
    if (typeof document === "undefined") return;
    document.querySelectorAll("[data-micro-apel-2-simulator]").forEach(initRoot);
  }

  const api = Object.freeze({ applyMapping: applyMapping, init: init });
  scope.MicroApel2CompanyLookup = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
    else init();
  }
}(typeof window !== "undefined" ? window : globalThis));
