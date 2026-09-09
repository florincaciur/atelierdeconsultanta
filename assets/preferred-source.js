(() => {
  "use strict";

  const controls = [...document.querySelectorAll("[google-add-preferred-source-btn]")];
  if (!controls.length) return;

  const update = (control) => {
    const actions = control.closest(".preferred-source-cta__actions");
    if (!actions) return;
    const rendered = control.childElementCount > 0 || Boolean(control.shadowRoot?.childElementCount);
    actions.classList.toggle("is-google-ready", rendered);
  };

  controls.forEach((control) => {
    update(control);
    const observer = new MutationObserver(() => update(control));
    observer.observe(control, { childList: true, subtree: true, attributes: true });
  });
})();
