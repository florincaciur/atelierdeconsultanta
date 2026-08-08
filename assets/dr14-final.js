(function () {
  "use strict";

  function formatEur(value) {
    return new Intl.NumberFormat("ro-RO", { maximumFractionDigits: 0 }).format(Math.max(0, value)) + " EUR";
  }

  function initTabs(root) {
    var tabs = Array.from(root.querySelectorAll("[data-dr14-tab]"));
    var panels = Array.from(root.querySelectorAll("[data-dr14-panel]"));
    function activate(tab, focus) {
      var key = tab.getAttribute("data-dr14-tab");
      tabs.forEach(function (item) {
        var active = item === tab;
        item.setAttribute("aria-selected", String(active));
        item.tabIndex = active ? 0 : -1;
      });
      panels.forEach(function (panel) {
        panel.hidden = panel.getAttribute("data-dr14-panel") !== key;
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (tab, index) {
      tab.addEventListener("click", function () { activate(tab, false); });
      tab.addEventListener("keydown", function (event) {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        var targetIndex = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
        activate(tabs[targetIndex], true);
      });
    });
  }

  function initCalculator(root) {
    var number = root.querySelector("[data-dr14-cost]");
    var range = root.querySelector("[data-dr14-cost-range]");
    var grantOutput = root.querySelector("[data-dr14-grant]");
    var privateOutput = root.querySelector("[data-dr14-private]");
    var rateOutput = root.querySelector("[data-dr14-rate]");
    var message = root.querySelector("[data-dr14-cap-message]");
    function render(raw, source) {
      var cost = Math.max(0, Math.min(500000, Number(raw) || 0));
      var grant = Math.min(cost * .85, 50000);
      var own = Math.max(0, cost - grant);
      var rate = cost ? (grant / cost) * 100 : 0;
      if (source !== number) number.value = String(Math.round(cost));
      if (source !== range) range.value = String(Math.min(100000, Math.round(cost / 500) * 500));
      grantOutput.textContent = formatEur(grant);
      privateOutput.textContent = formatEur(own);
      rateOutput.textContent = new Intl.NumberFormat("ro-RO", { maximumFractionDigits: 1 }).format(rate) + "%";
      message.textContent = grant >= 50000
        ? "Plafonul de 50.000 EUR este atins. Diferența peste grant și cheltuielile neeligibile rămân la beneficiar."
        : "La " + formatEur(cost).replace(" EUR", "") + " EUR eligibili, plafonul de 50.000 EUR nu este atins.";
    }
    number.addEventListener("input", function () { render(number.value, number); });
    range.addEventListener("input", function () { render(range.value, range); });
    render(number.value, number);
  }

  var scoreModels = {
    simple: [
      ["Localizarea exploatației", [["Fără punctaj", 0], ["Zonă montană / constrângeri specifice", 10]]],
      ["Vârsta solicitantului", [["Peste 40 de ani", 0], ["Între 35 și 40 de ani", 25], ["Până la 35 de ani inclusiv", 35]]],
      ["Membru al unei forme asociative", [["Nu", 0], ["Membru", 5], ["Cooperativă / grup de producători eligibil", 15]]],
      ["Teren agricol în proprietate", [["Fără punctaj", 0], ["Punctaj maxim, proporția cerută", 25]]],
      ["Pregătire agricolă", [["Fără punctaj", 0], ["Studii medii", 5], ["Calificare profesională", 10], ["Studii superioare", 15]]]
    ],
    vegetal: [
      ["Spații protejate", [["Nu", 0], ["Înființare spații protejate noi", 20], ["Modernizare spații protejate existente", 30]]],
      ["Vârsta solicitantului", [["Peste 40 de ani", 0], ["Între 35 și 40 de ani", 20], ["Până la 35 de ani inclusiv", 30]]],
      ["Membru al unei forme asociative", [["Nu", 0], ["Membru", 5], ["Cooperativă / grup de producători eligibil", 15]]],
      ["Teren agricol în proprietate", [["Fără punctaj", 0], ["Punctaj maxim, proporția cerută", 15]]],
      ["Pregătire agricolă", [["Fără punctaj", 0], ["Studii medii", 5], ["Calificare profesională", 7], ["Studii superioare", 10]]]
    ],
    zootehnic: [
      ["Localizarea exploatației", [["Fără punctaj", 0], ["Zonă montană / constrângeri specifice", 15]]],
      ["Rase autohtone", [["Nu", 0], ["Exploatația include rase autohtone", 10], ["Exploatație exclusiv cu rase autohtone", 20]]],
      ["Vârsta solicitantului", [["Peste 40 de ani", 0], ["Între 35 și 40 de ani", 15], ["Până la 35 de ani inclusiv", 20]]],
      ["Membru al unei forme asociative", [["Nu", 0], ["Membru", 5], ["Cooperativă / grup de producători eligibil", 15]]],
      ["Teren agricol în proprietate", [["Fără punctaj", 0], ["Punctaj maxim, proporția cerută", 15]]],
      ["Pregătire agricolă", [["Fără punctaj", 0], ["Studii medii", 5], ["Calificare profesională", 10], ["Studii superioare", 15]]]
    ]
  };
  scoreModels.alte = scoreModels.simple;

  function initScore(root) {
    var componentButtons = Array.from(root.querySelectorAll("[data-score-component]"));
    var criteria = root.querySelector("[data-score-criteria]");
    var totalOutput = root.querySelector("[data-score-total]");
    var bar = root.querySelector("[data-score-bar]");
    var message = root.querySelector("[data-score-message]");
    var reset = root.querySelector("[data-score-reset]");
    var active = "simple";

    function updateTotal() {
      var total = Array.from(criteria.querySelectorAll("select")).reduce(function (sum, select) { return sum + Number(select.value || 0); }, 0);
      totalOutput.value = String(total);
      totalOutput.textContent = String(total);
      bar.style.width = Math.min(100, total) + "%";
      message.textContent = total >= 80 ? "Atinge pragul etapei I, sub rezerva documentelor." : total >= 40 ? "Atinge pragul etapei II, sub rezerva documentelor." : "Sub pragul minim de 40 de puncte.";
    }

    function render() {
      criteria.textContent = "";
      scoreModels[active].forEach(function (criterion, index) {
        var wrapper = document.createElement("label");
        wrapper.className = "dr14-score__criterion";
        var title = document.createElement("strong");
        title.textContent = criterion[0];
        var select = document.createElement("select");
        select.setAttribute("aria-label", criterion[0]);
        criterion[1].forEach(function (option) {
          var node = document.createElement("option");
          node.value = String(option[1]);
          node.textContent = option[0] + " (" + option[1] + " p)";
          select.appendChild(node);
        });
        var points = document.createElement("b");
        points.textContent = "0 p";
        select.addEventListener("change", function () { points.textContent = select.value + " p"; updateTotal(); });
        wrapper.append(title, select, points);
        criteria.appendChild(wrapper);
      });
      updateTotal();
    }

    componentButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        active = button.getAttribute("data-score-component");
        componentButtons.forEach(function (item) { item.setAttribute("aria-pressed", String(item === button)); });
        render();
      });
    });
    reset.addEventListener("click", render);
    render();
  }

  function initDossier(root) {
    var checks = Array.from(root.querySelectorAll("[data-dossier-check]"));
    var bar = root.querySelector("[data-dossier-progress]");
    var count = root.querySelector("[data-dossier-count]");
    function update() {
      var done = checks.filter(function (check) { return check.checked; }).length;
      bar.style.width = (done / checks.length * 100) + "%";
      count.textContent = done + " din " + checks.length + " verificate";
    }
    checks.forEach(function (check) { check.addEventListener("change", update); });
    update();
  }

  document.querySelectorAll("[data-dr14-tabs]").forEach(initTabs);
  document.querySelectorAll("[data-dr14-calculator]").forEach(initCalculator);
  document.querySelectorAll("[data-dr14-score]").forEach(initScore);
  document.querySelectorAll("[data-dr14-dossier]").forEach(initDossier);
}());
