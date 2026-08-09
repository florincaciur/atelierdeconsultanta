(function () {
  "use strict";

  var MAX_TECHNICAL_QUANTITY = 1000000;
  var disclaimer = "Rezultatul calculatorului este orientativ și nu înlocuiește ghidul sau verificarea documentelor.";
  var errorRegion = document.getElementById("calculator-errors");
  var explanation = document.getElementById("so-result-explanation");
  var feedback = document.getElementById("so-action-feedback");
  var total = document.getElementById("total-so");
  var programSuggestion = document.getElementById("so-program-suggestion");

  function rows() {
    return Array.prototype.slice.call(document.querySelectorAll("#calculator tbody tr"));
  }

  function setFeedback(message) {
    if (feedback) feedback.textContent = message;
  }

  function sanitizeInput(input) {
    if (!input || !input.classList.contains("area-input")) return true;
    var value = Number(input.value);
    var valid = input.value === "" || (Number.isFinite(value) && value >= 0 && value <= MAX_TECHNICAL_QUANTITY);
    input.setAttribute("aria-invalid", valid ? "false" : "true");
    if (!valid) {
      input.value = value < 0 || !Number.isFinite(value) ? "0" : String(MAX_TECHNICAL_QUANTITY);
    }
    return valid;
  }

  function validateAll() {
    var invalidCount = 0;
    document.querySelectorAll("#calculator .area-input").forEach(function (input) {
      if (!sanitizeInput(input)) invalidCount += 1;
      input.max = String(MAX_TECHNICAL_QUANTITY);
      input.setAttribute("aria-describedby", "calculator-input-help calculator-errors");
    });
    if (errorRegion) {
      errorRegion.textContent = invalidCount
        ? "O valoare a fost corectată. Folosește numai numere între 0 și 1.000.000; aceasta este o limită tehnică, nu un prag de eligibilitate."
        : "";
    }
    return invalidCount === 0;
  }

  function selectedMetadata(row) {
    var select = row.querySelector(".cultura-select");
    var option = select && select.options[select.selectedIndex];
    return {
      name: option ? option.textContent.trim() : "Categorie",
      unitLabel: option ? option.getAttribute("data-unit-label") || "unități" : "unități"
    };
  }

  function updateExplanation() {
    if (!explanation) return;
    var items = rows().map(function (row) {
      var meta = selectedMetadata(row);
      var quantity = Number(row.querySelector(".area-input")?.value || 0);
      var coefficient = Number(row.querySelector(".so-input")?.value || 0);
      if (!quantity || !coefficient) return "";
      var product = quantity * coefficient;
      return "<li><strong>" + meta.name.replace(/[&<>\"]/g, function (char) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[char];
      }) + ":</strong> " + quantity.toLocaleString("ro-RO") + " " + meta.unitLabel + " × " + coefficient.toLocaleString("ro-RO", { maximumFractionDigits: 3 }) + " EUR = " + product.toLocaleString("ro-RO", { maximumFractionDigits: 2 }) + " EUR SO</li>";
    }).filter(Boolean);
    explanation.innerHTML = items.length
      ? "<h3>Cum a rezultat totalul</h3><ul>" + items.join("") + "</ul>"
      : "<p>Adaugă o categorie și o cantitate documentabilă pentru a vedea pașii calculului.</p>";
  }

  function summaryText() {
    var lines = ["Calcul orientativ SO — FABER", "Sursă coeficienți: AFIR, SOC 2020, lista noiembrie 2024"];
    rows().forEach(function (row) {
      var meta = selectedMetadata(row);
      var quantity = Number(row.querySelector(".area-input")?.value || 0);
      var coefficient = Number(row.querySelector(".so-input")?.value || 0);
      if (!quantity || !coefficient) return;
      lines.push(meta.name + ": " + quantity + " " + meta.unitLabel + " × " + coefficient + " EUR = " + (quantity * coefficient).toFixed(2) + " EUR SO");
    });
    lines.push("Total afișat: " + (total ? total.textContent.trim() : "0") + " EUR SO", disclaimer);
    if (programSuggestion && programSuggestion.textContent.trim()) lines.push("Orientare program: " + programSuggestion.textContent.trim());
    return lines.join("\n");
  }

  async function copySummary() {
    var value = summaryText();
    try {
      await navigator.clipboard.writeText(value);
    } catch (error) {
      var textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setFeedback("Rezumatul calculului a fost copiat. Nu conține date personale.");
  }

  function initCardCarousel(root) {
    var cards = Array.prototype.slice.call(root.children).filter(function (node) {
      return node.classList && node.classList.contains("content-card");
    });
    if (cards.length < 2 || root.classList.contains("so-card-carousel")) return;
    var label = root.getAttribute("data-so-carousel-label") || "Carduri informative";
    var current = 0;
    var controls = document.createElement("div");
    var previous = document.createElement("button");
    var next = document.createElement("button");
    var counter = document.createElement("span");
    root.classList.add("so-card-carousel");
    root.setAttribute("role", "region");
    root.setAttribute("aria-roledescription", "carusel");
    root.setAttribute("aria-label", label);
    controls.className = "so-card-carousel__controls";
    previous.type = "button";
    previous.className = "so-card-carousel__button";
    previous.setAttribute("aria-label", "Cardul anterior");
    previous.textContent = "←";
    next.type = "button";
    next.className = "so-card-carousel__button";
    next.setAttribute("aria-label", "Cardul următor");
    next.textContent = "→";
    counter.className = "so-card-carousel__counter";
    counter.setAttribute("aria-live", "polite");
    controls.append(previous, counter, next);
    root.appendChild(controls);

    function show(index, focusCard) {
      current = (index + cards.length) % cards.length;
      cards.forEach(function (card, cardIndex) {
        var active = cardIndex === current;
        card.hidden = !active;
        card.setAttribute("aria-hidden", String(!active));
        card.setAttribute("role", "group");
        card.setAttribute("aria-roledescription", "slide");
        card.setAttribute("aria-label", (cardIndex + 1) + " din " + cards.length);
        card.tabIndex = active ? 0 : -1;
      });
      counter.textContent = (current + 1) + " / " + cards.length;
      if (focusCard) cards[current].focus();
    }
    previous.addEventListener("click", function () { show(current - 1, true); });
    next.addEventListener("click", function () { show(current + 1, true); });
    root.addEventListener("keydown", function (event) {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      show(current + (event.key === "ArrowRight" ? 1 : -1), true);
    });
    show(0, false);
  }

  function initCollapsibleCards(root) {
    if (root.classList.contains("so-collapsible-cards")) return;
    var cards = Array.prototype.slice.call(root.children).filter(function (node) {
      return node.matches && node.matches("article");
    });
    if (cards.length < 2) return;
    var details = document.createElement("details");
    var summary = document.createElement("summary");
    var panel = document.createElement("div");
    root.classList.add("so-collapsible-cards");
    details.className = "so-card-disclosure";
    panel.className = "so-card-disclosure__panel";
    summary.textContent = "Vezi încă " + (cards.length - 1) + (cards.length === 2 ? " card" : " carduri");
    cards.slice(1).forEach(function (card) { panel.appendChild(card); });
    details.append(summary, panel);
    root.appendChild(details);
  }

  document.addEventListener("input", function (event) {
    if (!event.target.classList?.contains("area-input")) return;
    sanitizeInput(event.target);
  }, true);

  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-copy-so-result]")) copySummary();
    if (event.target.closest("[data-print-so-result]")) {
      setFeedback("Se deschide dialogul de tipărire. Rezumatul nu include date personale.");
      window.print();
    }
  });

  var calculator = document.getElementById("calculator");
  if (calculator) {
    calculator.addEventListener("input", function () {
      validateAll();
      updateExplanation();
    });
    calculator.addEventListener("change", function () {
      validateAll();
      updateExplanation();
    });
    document.querySelectorAll("#calculator tbody").forEach(function (tbody) {
      new MutationObserver(function () {
        validateAll();
        updateExplanation();
      }).observe(tbody, { childList: true });
    });
  }

  validateAll();
  updateExplanation();
  document.querySelectorAll("[data-so-card-carousel]").forEach(initCardCarousel);
  document.querySelectorAll("[data-so-collapsible-cards], [data-aeo-route='/calculator-soc']").forEach(initCollapsibleCards);
})();
