(function (root) {
  'use strict';
  function percentage(value) {
    var n = Number(value);
    return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  }
  function calculate(data) {
    var education = [0, 15, 20].indexOf(Number(data.education)) >= 0 ? Number(data.education) : 0;
    var association = [0, 5, 10].indexOf(Number(data.association)) >= 0 ? Number(data.association) : 0;
    var parts = [education, association, percentage(data.land) / 10 + (data.building ? 10 : 0),
      (percentage(data.precision) >= 10 ? 14 : 0) + (data.circular ? 5 : 0),
      ['forest', 'biosecurity'].indexOf(data.risk) >= 0 ? 10 : percentage(data.insurance) / 10,
      ['installation', 'first'].indexOf(data.history) >= 0 ? 21 : 0];
    // Keep full precision for threshold comparisons; formatting must never promote a score.
    var total = parts.reduce(function (sum, value) { return sum + value; }, 0);
    return { parts: parts, total: total, band: total >= 80 ? 'first' : total >= 45 ? 'second' : 'below' };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { calculate: calculate };
  if (typeof document === 'undefined') return;
  var labels = ['Calificare', 'Asociere', 'Proprietate', 'Tehnologii și resurse', 'Gestionarea riscului', 'Instalare / prima accesare'];
  document.querySelectorAll('[data-dr12-calculator]').forEach(function (box) {
    var form = box.querySelector('form');
    function update() {
      form.elements.insurance.disabled = form.elements.risk.value !== 'insurance';
      var data = Object.fromEntries(new FormData(form));
      data.building = form.elements.building.checked;
      data.circular = form.elements.circular.checked;
      var result = calculate(data);
      var valid = form.checkValidity();
      var format = function (n) { return n.toLocaleString('ro-RO', { maximumFractionDigits: 3 }); };
      box.querySelector('[data-dr12-total]').textContent = valid ? format(result.total) : '—';
      box.querySelector('[data-dr12-status]').textContent = !valid ? 'Corectează procentele: valori între 0 și 100, cu cel mult două zecimale.' : result.band === 'first'
        ? 'Pragul de 80p este atins. Depunerea depinde de lansarea sesiunii și de verificarea documentelor.'
        : result.band === 'second' ? 'Pragul minim de 45p este atins; pragul primei etape de 80p nu este atins.' : 'Sub pragul minim de 45 de puncte.';
      var list = box.querySelector('[data-dr12-breakdown]');
      list.replaceChildren();
      if (valid) result.parts.forEach(function (points, i) { var li = document.createElement('li'); li.textContent = labels[i] + ': ' + format(points) + 'p'; list.appendChild(li); });
    }
    form.addEventListener('input', update);
    form.addEventListener('change', update);
    form.addEventListener('submit', function (event) { event.preventDefault(); update(); });
    form.addEventListener('reset', function () { setTimeout(update, 0); });
    update();
  });
})(typeof window !== 'undefined' ? window : globalThis);
