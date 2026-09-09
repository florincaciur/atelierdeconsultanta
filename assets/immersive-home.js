/* Progressive enhancement: native scrolling, no pinned sections or wheel interception. */
(function () {
  "use strict";
  const page = document.documentElement;
  const hero = document.querySelector("#hero.im-hero");
  if (!hero) return;
  const method = document.querySelector("[data-homepage-method]");
  const progress = document.querySelector("[data-im-progress]");
  const toggle = document.querySelector("[data-im-motion]");
  const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  const chapters = Array.from(document.querySelectorAll(".im-chapters a"));
  const sections = chapters.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  let optedOut = false;
  let paused = false;
  let frame = 0;
  let lastChapter = -1;
  let revealObserver = null;
  const clamp = (value, min = 0, max = 1) => Math.max(min, Math.min(max, value));
  try { optedOut = localStorage.getItem("faber-motion") === "off"; } catch (_) { /* Storage is optional. */ }

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
    if (activeChapter === lastChapter) return;
    chapters.forEach((link, index) => {
      if (index === activeChapter) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
    lastChapter = activeChapter;
  }

  function configureMotion() {
    paused = motionQuery.matches || optedOut;
    page.classList.add("im-page");
    page.classList.toggle("im-motion-on", !paused);
    page.classList.toggle("im-motion-off", paused);
    method?.classList.remove("im-scroll-enabled");
    if (toggle) {
      toggle.hidden = false;
      toggle.setAttribute("aria-pressed", String(paused));
      toggle.querySelector("[data-im-motion-label]").textContent = paused ? "Animații oprite" : "Oprește animațiile";
      toggle.title = motionQuery.matches ? "Mișcare redusă conform preferinței dispozitivului" : (paused ? "Activează animațiile" : "Oprește animațiile");
    }
    revealObserver?.disconnect();
    document.querySelectorAll("[data-im-reveal]").forEach((node) => node.classList.remove("im-awaiting"));
    if (!paused && "IntersectionObserver" in window) {
      revealObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          const outside = entry.boundingClientRect.top > window.innerHeight || entry.boundingClientRect.bottom < 0;
          entry.target.classList.toggle("im-awaiting", !entry.isIntersecting && outside && !entry.target.contains(document.activeElement));
        });
      }, { threshold: .08 });
      document.querySelectorAll("#priority-programs .program-explorer-header, #homepage-explorer .homepage-flow-heading, #homepage-contact .homepage-flow-heading").forEach((node) => {
        node.setAttribute("data-im-reveal", "");
        revealObserver.observe(node);
      });
    }
    requestFrame();
  }

  method?.addEventListener("faber:sequence-change", (event) => {
    const index = Number(event.detail?.index || 0);
    method.style.setProperty("--im-method-progress", (index / 4).toFixed(2));
  });
  toggle?.addEventListener("click", () => {
    optedOut = !paused;
    try { localStorage.setItem("faber-motion", optedOut ? "off" : "on"); } catch (_) { /* Optional. */ }
    configureMotion();
  });
  motionQuery.addEventListener("change", configureMotion);
  window.addEventListener("scroll", requestFrame, { passive: true });
  window.addEventListener("resize", requestFrame, { passive: true });
  document.addEventListener("visibilitychange", requestFrame);
  document.addEventListener("toggle", requestFrame, true);
  document.addEventListener("focusin", (event) => event.target.closest("[data-im-reveal]")?.classList.remove("im-awaiting"));
  configureMotion();
})();
