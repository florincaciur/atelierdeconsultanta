(function () {
  "use strict";

  var sticky = document.querySelector("[data-sticky-cta]");
  var heroCta = document.querySelector("[data-contextual-hero-cta]");
  var mobile = window.matchMedia("(max-width: 47.5rem)");

  function reserveStickySpace() {
    if (sticky && !sticky.hidden) document.body.style.setProperty("--contextual-sticky-height", sticky.getBoundingClientRect().height + "px");
  }

  function setStickyVisible(visible) {
    if (!sticky) return;
    if (!visible && sticky.contains(document.activeElement)) return;
    sticky.hidden = !visible;
    document.body.classList.toggle("contextual-sticky-cta-visible", visible);
    reserveStickySpace();
  }

  function observeHero() {
    setStickyVisible(false);
    if (!sticky || !heroCta || !mobile.matches || !("IntersectionObserver" in window)) return null;
    var observer = new IntersectionObserver(function (entries) {
      // Show only after the visitor has passed the primary action. A long hero
      // may place that action below the first screen; it must remain unobscured.
      setStickyVisible(!entries[0].isIntersecting && entries[0].boundingClientRect.bottom <= 0);
    }, { threshold: 0.01 });
    observer.observe(heroCta);
    return observer;
  }

  var observer = observeHero();
  if (sticky && "ResizeObserver" in window) new ResizeObserver(reserveStickySpace).observe(sticky);
  mobile.addEventListener("change", function () {
    if (observer) observer.disconnect();
    observer = observeHero();
  });

  var calculatorCta = document.querySelector("[data-calculator-context-cta]");
  var total = document.getElementById("total-so");
  if (calculatorCta && total) {
    var updateCalculatorLink = function () {
      var url = new URL(calculatorCta.getAttribute("data-contextual-base-href"), window.location.origin);
      var numeric = Number(total.dataset.soValue || 0);
      var params = new URLSearchParams(url.hash.slice(1).replace(/^\?/, "") || url.search.slice(1));
      if (Number.isFinite(numeric) && numeric > 0 && numeric <= 1000000000) params.set("so_result", String(Math.round(numeric)));
      url.search = "";
      url.hash = params.toString();
      calculatorCta.href = url.pathname + url.hash;
    };
    updateCalculatorLink();
    new MutationObserver(updateCalculatorLink).observe(total, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ["data-so-value"] });
  }
})();
