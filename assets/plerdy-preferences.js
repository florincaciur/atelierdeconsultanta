(() => {
  "use strict";

  const storageKey = "faber-plerdy-consent-v1";
  const template = document.getElementById("plerdy-installation");
  const vendorScript = template.content.querySelector("script[data-plerdy_code]");
  const preferences = template.content.querySelector("details").cloneNode(true);
  const summary = preferences.querySelector("summary");
  const status = preferences.querySelector('[role="status"]');

  function readChoice() {
    try {
      return JSON.parse(localStorage.getItem(storageKey))?.choice;
    } catch {
      return undefined;
    }
  }

  function startPlerdy() {
    if (window.__plerdyCode) return;
    const script = document.createElement("script");
    script.setAttribute("data-plerdy_code", vendorScript.getAttribute("data-plerdy_code"));
    script.text = vendorScript.text;
    document.head.append(script);
  }

  function applyChoice(choice) {
    if (choice === "granted") startPlerdy();
    else if (window.__plerdyCode) window.location.reload();
    preferences.open = choice !== "granted" && choice !== "denied";
    status.textContent = choice === "granted" ? "Plerdy este activat." :
      choice === "denied" ? "Plerdy este refuzat." : "";
  }

  for (const button of preferences.querySelectorAll("[data-plerdy-choice]")) {
    button.addEventListener("click", () => {
      const choice = button.dataset.plerdyChoice;
      try {
        localStorage.setItem(storageKey, JSON.stringify({ choice, updatedAt: new Date().toISOString() }));
      } catch {
        if (choice === "granted" || window.__plerdyCode) {
          status.textContent = "Browserul nu a putut salva preferința pentru Plerdy.";
          return;
        }
      }
      applyChoice(choice);
      summary.focus();
    });
  }

  const footer = document.querySelector('footer[role="contentinfo"]') || [...document.querySelectorAll("footer")].at(-1);
  if (footer) footer.before(preferences);
  else document.body.append(preferences);
  applyChoice(readChoice());
  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) applyChoice(readChoice());
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) applyChoice(readChoice());
  });
})();
