(function () {
  "use strict";

  var sticky = document.querySelector("[data-sticky-cta]");
  var heroCta = document.querySelector("[data-contextual-hero-cta]");
  var mobile = window.matchMedia("(max-width: 47.5rem)");

  function setStickyVisible(visible) {
    if (!sticky) return;
    if (!visible && sticky.contains(document.activeElement)) return;
    sticky.hidden = !visible;
    document.body.classList.toggle("contextual-sticky-cta-visible", visible);
  }

  function observeHero() {
    setStickyVisible(false);
    if (!sticky || !heroCta || !mobile.matches || !("IntersectionObserver" in window)) return null;
    var observer = new IntersectionObserver(function (entries) {
      setStickyVisible(!entries[0].isIntersecting);
    }, { threshold: 0.01 });
    observer.observe(heroCta);
    return observer;
  }

  var observer = observeHero();
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
