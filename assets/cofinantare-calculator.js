(() => {
  "use strict";

  const calculator = document.getElementById("cofinantare-form");
  const inputs = [...calculator.querySelectorAll("input")];
  const results = document.getElementById("cofinantare-rezultate");
  const status = document.getElementById("cofinantare-status");
  const euros = new Intl.NumberFormat("ro-RO", { style: "currency", currency: "EUR" });

  calculator.querySelector("button").addEventListener("click", () => {
    const invalid = inputs.find(input => !input.validity.valid);
    if (invalid) {
      invalid.focus();
      invalid.reportValidity();
      return;
    }
    const amount = Object.fromEntries(inputs.map(input => [input.name, Math.round(input.valueAsNumber * 100)]));
    const base = amount.eligible + amount.eligibleVat;
    const gross = base + amount.ineligible + amount.excludedVat + amount.recoverableVat;
    const grant = Math.min(amount.cap, Math.floor(base * amount.intensity / 10000));
    const values = {
      base,
      grant,
      ownEligible: base - grant,
      gross,
      afterGrant: gross - grant,
      netOwn: gross - grant - amount.recoverableVat
    };
    for (const output of results.querySelectorAll("[data-cofinantare]")) {
      output.textContent = euros.format(values[output.dataset.cofinantare] / 100);
    }
    results.hidden = false;
    status.textContent = `Grant estimat ${euros.format(grant / 100)}. Cost propriu după recuperarea TVA ${euros.format(values.netOwn / 100)}.`;
  });

  calculator.addEventListener("input", () => {
    if (results.hidden) return;
    results.hidden = true;
    status.textContent = "Valorile s-au schimbat. Calculează din nou contribuția.";
  });
  calculator.hidden = false;
})();
