(function () {
  "use strict";

  function numberValue(id) {
    var element = document.getElementById(id);
    if (!element) return 0;
    var value = Number(String(element.value || "0").replace(",", "."));
    return Number.isFinite(value) ? value : 0;
  }

  function text(id, value) {
    var element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function currency(value) {
    return new Intl.NumberFormat("ro-RO", {
      maximumFractionDigits: 0,
      style: "currency",
      currency: "EUR"
    }).format(Math.max(0, value || 0));
  }

  function percent(value) {
    return new Intl.NumberFormat("ro-RO", {
      maximumFractionDigits: 1,
      style: "percent"
    }).format(Math.max(0, value || 0) / 100);
  }

  function updateCofinantare() {
    var total = numberValue("cofinantare-total");
    var grant = numberValue("cofinantare-procent");
    var ineligible = numberValue("cofinantare-neeligibil");
    var eligible = Math.max(0, total - ineligible);
    var grantValue = eligible * (grant / 100);
    var own = total - grantValue;
    text("cofinantare-result", "Grant orientativ: " + currency(grantValue) + " | contributie proprie estimata: " + currency(own) + " | procent grant: " + percent(grant));
  }

  function updateDigitalizare() {
    var software = numberValue("digitalizare-software");
    var hardware = numberValue("digitalizare-hardware");
    var services = numberValue("digitalizare-servicii");
    var security = numberValue("digitalizare-security");
    var total = software + hardware + services + security;
    var servicesShare = total ? (services + security) / total : 0;
    var message = "Buget orientativ: " + currency(total) + ". ";
    message += servicesShare > 0.45
      ? "Verifica plafoanele pentru servicii si securitate in apelul activ."
      : "Structura pare echilibrata pentru o analiza initiala.";
    text("digitalizare-result", message);
  }

  function updateStartup() {
    var caen = document.getElementById("startup-caen");
    var cofinantare = numberValue("startup-cofinantare");
    var jobs = numberValue("startup-jobs");
    var budget = numberValue("startup-budget");
    var risks = [];
    if (caen && !caen.value.trim()) risks.push("cod CAEN necompletat");
    if (budget <= 0) risks.push("buget lipsa");
    if (cofinantare < 0) risks.push("cofinantare invalida");
    if (jobs < 0) risks.push("locuri de munca invalide");
    text("startup-result", risks.length
      ? "Verificare initiala: completeaza " + risks.join(", ") + "."
      : "Verificare initiala: datele sunt suficiente pentru o discutie de eligibilitate, fara garantie de aprobare.");
  }

  function updateEligibility() {
    var checked = document.querySelectorAll(".eligibility-check:checked").length;
    var total = document.querySelectorAll(".eligibility-check").length;
    var missing = total - checked;
    text("eligibility-result", missing
      ? "Ai " + missing + " puncte de clarificat inainte de depunere."
      : "Checklistul initial este complet. Urmeaza verificarea ghidului si a documentelor.");
  }

  function bind(inputs, callback) {
    inputs.forEach(function (id) {
      var element = document.getElementById(id);
      if (element) element.addEventListener("input", callback);
      if (element) element.addEventListener("change", callback);
    });
    callback();
  }

  document.addEventListener("DOMContentLoaded", function () {
    bind(["cofinantare-total", "cofinantare-procent", "cofinantare-neeligibil"], updateCofinantare);
    bind(["digitalizare-software", "digitalizare-hardware", "digitalizare-servicii", "digitalizare-security"], updateDigitalizare);
    bind(["startup-caen", "startup-budget", "startup-cofinantare", "startup-jobs"], updateStartup);
    document.querySelectorAll(".eligibility-check").forEach(function (element) {
      element.addEventListener("change", updateEligibility);
    });
    updateEligibility();
  });
})();
