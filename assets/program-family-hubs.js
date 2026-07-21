(function programFamilyHubFilters() {
  "use strict";

  const FILTER_FIELDS = Object.freeze({
    solicitant: "applicantTypes",
    regiune: "regions",
    investitie: "investmentTypes",
    status: "status"
  });

  function fieldFor(controls, name) {
    return controls.querySelector(`select[name="${name}"]`);
  }

  function selectedValue(controls, name) {
    const field = fieldFor(controls, name);
    return field instanceof HTMLSelectElement ? field.value : "";
  }

  function allowedValue(field, value) {
    return [...field.options].some((option) => option.value === value) ? value : "";
  }

  function valuesForCard(card, field) {
    return String(card.dataset[field] || "").split(/\s+/u).filter(Boolean);
  }

  function init(root) {
    const controls = root.querySelector("[data-program-hub-filters]");
    const reset = root.querySelector("[data-program-filters-reset]");
    const cards = [...root.querySelectorAll("[data-program-card]")];
    const live = root.querySelector("[data-program-results-status]");
    const empty = root.querySelector("[data-program-empty]");
    if (!controls || !reset || !cards.length || !live || !empty) return;

    const url = new URL(window.location.href);
    for (const name of Object.keys(FILTER_FIELDS)) {
      const field = fieldFor(controls, name);
      if (!(field instanceof HTMLSelectElement)) continue;
      field.value = allowedValue(field, url.searchParams.get(name) || "");
    }

    function updateUrl() {
      const next = new URL(window.location.href);
      for (const name of Object.keys(FILTER_FIELDS)) {
        const value = selectedValue(controls, name);
        if (value) next.searchParams.set(name, value);
        else next.searchParams.delete(name);
      }
      window.history.replaceState({}, "", `${next.pathname}${next.search}${next.hash}`);
    }

    function applyFilters({ announce = true } = {}) {
      let visible = 0;
      for (const card of cards) {
        const matches = Object.entries(FILTER_FIELDS).every(([name, dataField]) => {
          const selected = selectedValue(controls, name);
          return !selected || valuesForCard(card, dataField).includes(selected);
        });
        card.hidden = !matches;
        if (matches) visible += 1;
      }
      empty.hidden = visible !== 0;
      live.textContent = `${visible} ${visible === 1 ? "program afișat" : "programe afișate"} din ${cards.length}.`;
      if (announce) updateUrl();
    }

    controls.addEventListener("change", () => applyFilters());
    reset.addEventListener("click", () => {
      for (const name of Object.keys(FILTER_FIELDS)) {
        const field = fieldFor(controls, name);
        if (field instanceof HTMLSelectElement) field.value = "";
      }
      applyFilters();
    });
    window.addEventListener("popstate", () => {
      const current = new URL(window.location.href);
      for (const name of Object.keys(FILTER_FIELDS)) {
        const field = fieldFor(controls, name);
        if (field instanceof HTMLSelectElement) field.value = allowedValue(field, current.searchParams.get(name) || "");
      }
      applyFilters({ announce: false });
    });
    applyFilters({ announce: false });
  }

  document.querySelectorAll("[data-program-family-hub]").forEach(init);
})();
