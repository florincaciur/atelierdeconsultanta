(function () {
  function number(value) {
    var parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function selected(form, name) {
    var checked = form.querySelector('input[name="' + name + '"]:checked');
    return checked ? checked.value : "";
  }

  function checked(form, name) {
    var input = form.querySelector('[name="' + name + '"]');
    return !!(input && input.checked);
  }

  function value(form, name) {
    var input = form.querySelector('[name="' + name + '"]');
    return input ? input.value : "";
  }

  function selectPoints(form, name) {
    return number(value(form, name));
  }

  function proportional(form, name, maxPoints) {
    return Math.round(clamp(number(value(form, name)), 0, 100) * maxPoints) / 100;
  }

  function setText(root, selector, text) {
    var el = root.querySelector(selector);
    if (el) el.textContent = text;
  }

  function format(points) {
    return points.toLocaleString("ro-RO", { maximumFractionDigits: 1 });
  }

  function thresholds(kind, component) {
    if (kind === "dr12") return { first: 75, min: 45, label: "DR 12" };
    if (component === "legumicol") return { first: 60, min: 40, label: "DR 14 legumicol" };
    return { first: 85, min: 40, label: "DR 14" };
  }

  function dr12(form) {
    var component = selected(form, "dr12-component") || "zootehnic";
    var breakdown = [];

    var education = selectPoints(form, "dr12-education");
    breakdown.push({ label: "Calificare in domeniul proiectului", points: education, max: 15 });

    var association = selectPoints(form, "dr12-association");
    breakdown.push({ label: "Structura asociativa", points: association, max: 15 });

    if (component === "zootehnic") {
      var building = checked(form, "dr12-zoo-building") ? 20 : 0;
      var terrainZoo = proportional(form, "dr12-terrain", 5);
      breakdown.push({ label: "Proprietate exploatatie zootehnica", points: building + terrainZoo, max: 25 });
    } else {
      breakdown.push({ label: "Teren agricol in proprietate", points: proportional(form, "dr12-terrain", 25), max: 25 });
    }

    breakdown.push({ label: "Tehnologii moderne / agricultura de precizie", points: checked(form, "dr12-precision") ? 15 : 0, max: 15 });
    breakdown.push({ label: "Managementul riscului prin asigurare", points: proportional(form, "dr12-insurance", 10), max: 10 });
    breakdown.push({ label: "Prima accesare FEADR investitii agro-alimentare", points: checked(form, "dr12-first-feadr") ? 20 : 0, max: 20 });

    return { component: component, breakdown: breakdown };
  }

  function dr14(form) {
    var component = selected(form, "dr14-component") || "zootehnic";
    var breakdown = [];

    if (component === "zootehnic") {
      breakdown.push({ label: "Zona montana", points: checked(form, "dr14-mountain") ? 20 : 0, max: 20 });
      breakdown.push({ label: "Rase autohtone", points: checked(form, "dr14-autochthonous") ? 20 : 0, max: 20 });
      breakdown.push({ label: "Vechime exploatatie", points: selectPoints(form, "dr14-age-zoo"), max: 20 });
      breakdown.push({ label: "Forma asociativa", points: checked(form, "dr14-association") ? 20 : 0, max: 20 });
      breakdown.push({ label: "Teren agricol in proprietate", points: proportional(form, "dr14-terrain", 20), max: 20 });
    } else if (component === "legumicol") {
      breakdown.push({ label: "Investitii in spatii protejate", points: selectPoints(form, "dr14-protected"), max: 30 });
      breakdown.push({ label: "Vechime exploatatie", points: selectPoints(form, "dr14-age-legume"), max: 30 });
      breakdown.push({ label: "Forma asociativa", points: checked(form, "dr14-association") ? 20 : 0, max: 20 });
      breakdown.push({ label: "Teren agricol in proprietate", points: proportional(form, "dr14-terrain", 20), max: 20 });
    } else {
      breakdown.push({ label: "Zona montana", points: checked(form, "dr14-mountain") ? 15 : 0, max: 15 });
      breakdown.push({ label: "Vechime exploatatie", points: selectPoints(form, "dr14-age-simple"), max: 35 });
      breakdown.push({ label: "Forma asociativa", points: checked(form, "dr14-association") ? 20 : 0, max: 20 });
      breakdown.push({ label: "Teren agricol in proprietate", points: proportional(form, "dr14-terrain", 30), max: 30 });
    }

    return { component: component, breakdown: breakdown };
  }

  function render(root, result, kind) {
    var score = Math.round(result.breakdown.reduce(function (sum, item) { return sum + item.points; }, 0) * 10) / 10;
    var threshold = thresholds(kind, result.component);
    var statusClass = score >= threshold.first ? "is-strong" : score >= threshold.min ? "is-ok" : "is-low";
    var statusText = score >= threshold.first
      ? "Peste pragul primei etape. Proiectul arata competitiv, daca documentele confirma criteriile bifate."
      : score >= threshold.min
        ? "Peste pragul minim. Poate fi depus in etapa potrivita, dar merita cautate puncte suplimentare."
        : "Sub pragul minim. Inainte de depunere trebuie regandite criteriile sau componenta proiectului.";

    setText(root, "[data-score-total]", format(score));
    setText(root, "[data-score-first]", threshold.first + "p");
    setText(root, "[data-score-min]", threshold.min + "p");

    var status = root.querySelector("[data-score-status]");
    if (status) {
      status.className = "scorecalc-status " + statusClass;
      status.textContent = statusText;
    }

    var list = root.querySelector("[data-score-breakdown]");
    if (list) {
      list.innerHTML = "";
      result.breakdown.forEach(function (item) {
        var row = document.createElement("div");
        var pct = item.max ? clamp(item.points / item.max * 100, 0, 100) : 0;
        row.className = "scorecalc-row";
        row.innerHTML =
          '<div class="scorecalc-row-line"><strong>' + item.label + '</strong><span>' +
          format(item.points) + '/' + item.max + 'p</span></div>' +
          '<div class="scorecalc-bar"><span style="width:' + pct + '%"></span></div>';
        list.appendChild(row);
      });
    }
  }

  function updateScopes(root, form, componentName) {
    var component = selected(form, componentName);
    root.querySelectorAll("[data-score-scope]").forEach(function (el) {
      var scopes = (el.getAttribute("data-score-scope") || "").split(/\s+/);
      el.hidden = scopes.indexOf(component) === -1;
    });
  }

  function updateSliderLabels(root) {
    root.querySelectorAll('input[type="range"][data-score-slider]').forEach(function (input) {
      var target = root.querySelector('[data-score-slider-value="' + input.name + '"]');
      if (target) target.textContent = input.value + "%";
    });
  }

  function init(root) {
    var kind = root.getAttribute("data-score-calculator");
    var form = root.querySelector("form");
    if (!form) return;

    function recalc() {
      if (kind === "dr12") {
        updateScopes(root, form, "dr12-component");
        render(root, dr12(form), kind);
      }
      if (kind === "dr14") {
        updateScopes(root, form, "dr14-component");
        render(root, dr14(form), kind);
      }
      updateSliderLabels(root);
    }

    form.addEventListener("input", recalc);
    form.addEventListener("change", recalc);
    recalc();
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-score-calculator]").forEach(init);
  });
})();
