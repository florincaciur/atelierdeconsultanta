/* Progressive enhancement: no scroll interception, no rendering library. */
(function () {
  "use strict";
  const page = document.documentElement;
  const hero = document.querySelector("#hero.im-hero");
  if (!hero) return;
  const method = document.querySelector("[data-homepage-method]");
  const scene = document.querySelector("[data-im-scene]");
  const progress = document.querySelector("[data-im-progress]");
  const toggle = document.querySelector("[data-im-motion]");
  const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pinQuery = window.matchMedia("(min-width: 1000px) and (min-height: 700px)");
  const pointerQuery = window.matchMedia("(hover: hover) and (pointer: fine)");
  const chapters = Array.from(document.querySelectorAll(".im-chapters a"));
  const sections = chapters.map(link => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  let optedOut = false;
  let frame = 0;
  let lastStep = -1;
  let lastChapter = -1;
  let paused = false;
  let manualTarget = null;
  let manualUntil = 0;
  let revealObserver = null;
  const clamp = (value, min = 0, max = 1) => Math.max(min, Math.min(max, value));
  try { optedOut = localStorage.getItem("faber-motion") === "off"; } catch (_) { /* Storage is optional. */ }

  const domains = {
    business: { text: "Explorează finanțările pentru afacerea ta", href: "/fonduri-europene-imm", color: "#c65c38" },
    agriculture: { text: "Explorează finanțările pentru agricultură", href: "/fonduri-europene-agricultura", color: "#6d8655" },
    energy: { text: "Explorează investițiile în energie", href: "/fondul-de-modernizare", color: "#be852c" },
    digital: { text: "Explorează finanțările pentru digitalizare", href: "/fonduri-europene-digitalizare", color: "#577c8b" }
  };
  const sectorButtons = Array.from(document.querySelectorAll("[data-im-sector]"));
  const sectorOptions = document.querySelector(".im-sector-options");
  if (sectorOptions) sectorOptions.hidden = false;
  sectorButtons.forEach(button => {
    button.addEventListener("click", () => {
      const domain = domains[button.dataset.imSector];
      if (!domain) return;
      sectorButtons.forEach(item => item.setAttribute("aria-pressed", String(item === button)));
      scene.style.setProperty("--scene-accent", domain.color);
      scene.dataset.sector = button.dataset.imSector;
      document.querySelector("[data-im-sector-link]").href = domain.href;
      document.querySelector("[data-im-sector-text]").textContent = domain.text;
      document.querySelector("[data-im-sector-status]").textContent = `${button.textContent}. ${domain.text}.`;
    });
  });

  function requestFrame() {
    if (!frame && !document.hidden) frame = window.requestAnimationFrame(render);
  }

  function render() {
    frame = 0;
    const viewport = window.innerHeight;
    const scrollTop = window.scrollY;
    const total = document.documentElement.scrollHeight - viewport;
    if (progress) progress.style.transform = `scaleX(${total > 0 ? clamp(scrollTop / total) : 0})`;
    let activeChapter = 0;
    sections.forEach((section, index) => {
      if (section.getBoundingClientRect().top <= viewport * .48) activeChapter = index;
    });
    if (activeChapter !== lastChapter) {
      chapters.forEach((link, index) => {
        if (index === activeChapter) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
      lastChapter = activeChapter;
    }
    if (paused) return;
    const heroRect = hero.getBoundingClientRect();
    if (heroRect.bottom >= 0) hero.style.setProperty("--im-hero-progress", clamp(-heroRect.top / heroRect.height).toFixed(4));
    if (!method || !pinQuery.matches) return;
    const rect = method.getBoundingClientRect();
    const distance = rect.height - (viewport - 80);
    const position = clamp((80 - rect.top) / distance);
    method.style.setProperty("--im-method-progress", position.toFixed(4));
    if (rect.top > viewport || rect.bottom < 0) return;
    const step = Math.min(4, Math.floor(position * 5));
    // Manual tab/keyboard navigation can scroll to a step without intermediate
    // scroll frames replacing that selection or moving keyboard focus.
    if (manualTarget !== null) {
      if (performance.now() < manualUntil && Math.abs(scrollTop - manualTarget) > 4) return;
      manualTarget = null;
    }
    if (step !== lastStep) {
      lastStep = step;
      method.dispatchEvent(new CustomEvent("faber:sequence-select", { detail: { index: step } }));
    }
  }

  function configureMotion(preservePosition) {
    const methodWasPinned = method?.classList.contains("im-scroll-enabled");
    const beforeRect = method?.getBoundingClientRect();
    paused = motionQuery.matches || optedOut;
    page.classList.add("im-page");
    page.classList.toggle("im-motion-on", !paused);
    page.classList.toggle("im-motion-off", paused);
    method?.classList.toggle("im-scroll-enabled", !paused && pinQuery.matches);
    if (toggle) {
      toggle.hidden = false;
      toggle.setAttribute("aria-pressed", String(paused));
      toggle.querySelector("[data-im-motion-label]").textContent = paused ? "Animații oprite" : "Oprește animațiile";
      toggle.title = motionQuery.matches ? "Mișcare redusă conform preferinței dispozitivului" : (paused ? "Activează animațiile" : "Oprește animațiile");
    }
    if (revealObserver) revealObserver.disconnect();
    document.querySelectorAll("[data-im-reveal]").forEach(node => node.classList.remove("im-awaiting"));
    if (!paused && "IntersectionObserver" in window) {
      revealObserver = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          // Re-entering from either direction reveals content again. Never
          // hide a section containing keyboard focus.
          const outside = entry.boundingClientRect.top > window.innerHeight || entry.boundingClientRect.bottom < 0;
          entry.target.classList.toggle("im-awaiting", !entry.isIntersecting && outside && !entry.target.contains(document.activeElement));
        });
      }, { threshold: .08 });
      document.querySelectorAll("#priority-programs .program-explorer-header, #homepage-explorer .homepage-flow-heading, #homepage-contact .homepage-flow-heading").forEach(node => {
        node.setAttribute("data-im-reveal", "");
        revealObserver.observe(node);
      });
    }
    if (preservePosition && methodWasPinned && beforeRect.top < 80 && beforeRect.bottom > 80) {
      // Removing the long sticky section should not strand the visitor at the footer.
      method.scrollIntoView({ behavior: "instant", block: "start" });
    }
    lastStep = -1;
    requestFrame();
  }

  method?.addEventListener("faber:sequence-change", event => {
    if (!event.detail?.interaction || event.detail.interaction === "scroll" || paused || !pinQuery.matches) return;
    const distance = method.offsetHeight - (window.innerHeight - 80);
    const position = (event.detail.index + .3) / 5;
    manualTarget = window.scrollY + method.getBoundingClientRect().top - 80 + distance * position;
    manualUntil = performance.now() + 1400;
    lastStep = event.detail.index;
    window.scrollTo({ top: manualTarget, behavior: "smooth" });
  });

  if (method) {
    const heading = method.querySelector(".homepage-flow-heading");
    const hint = document.createElement("p");
    hint.className = "im-method-scroll-hint";
    hint.textContent = "Derulează în jos sau în sus pentru a parcurge etapele.";
    heading?.append(hint);
  }
  scene?.addEventListener("pointermove", event => {
    if (paused || !pointerQuery.matches) return;
    const rect = scene.getBoundingClientRect();
    scene.style.setProperty("--im-tilt", `${clamp((event.clientX - rect.left) / rect.width, 0, 1) * 10 - 5}deg`);
  }, { passive: true });
  scene?.addEventListener("pointerleave", () => scene.style.setProperty("--im-tilt", "0deg"));
  toggle?.addEventListener("click", () => {
    // The system preference always wins; the user can only add a stricter one.
    optedOut = !paused;
    try { localStorage.setItem("faber-motion", optedOut ? "off" : "on"); } catch (_) { /* Optional. */ }
    configureMotion(true);
  });
  motionQuery.addEventListener("change", () => configureMotion(true));
  pinQuery.addEventListener("change", () => configureMotion(false));
  window.addEventListener("scroll", requestFrame, { passive: true });
  function cancelManualScroll() { manualTarget = null; requestFrame(); }
  window.addEventListener("wheel", cancelManualScroll, { passive: true });
  window.addEventListener("touchstart", cancelManualScroll, { passive: true });
  window.addEventListener("resize", requestFrame, { passive: true });
  document.addEventListener("visibilitychange", requestFrame);
  document.addEventListener("toggle", requestFrame, true);
  document.addEventListener("focusin", event => event.target.closest("[data-im-reveal]")?.classList.remove("im-awaiting"));
  configureMotion(false);
})();
