# P0.07 — raport accesibilitate Contact

## Rezultat

Formularul are etichete explicite, descrieri și erori asociate, sumar de erori cu linkuri, focus pe prima eroare, stări distincte de încărcare/eroare/succes și prevenirea trimiterii duble. Eroarea de rețea păstrează valorile și oferă acțiunea „Încearcă din nou”.

Testele automate acoperă:

- alternativa email OR telefon;
- asocierea `label`, `aria-describedby`, `aria-invalid` și sumar–câmp;
- ordinea tastaturii și poziția focusului față de header;
- `aria-busy`, buton dezactivat și o singură cerere la dublu-click;
- retry după eroare fără pierderea valorilor;
- regiunea de succes `aria-live="polite"`;
- target-uri de minimum 24 px și 44 px pe mobil;
- reflow la 320 px și text la 200%;
- absența datelor de contact neaprobate din componenta principală, footer și JSON-LD.

## Contact canonic

`publicPhone`, `publicEmail` și confirmarea proprietarului Gmail sunt încă `pending`. Componenta randată nu include `tel:` sau `mailto:`. După aprobarea fișei juridice, build-ul va genera automat:

```html
<a href="tel:+40769828338">0769 828 338</a>
<a href="mailto:atelier.consultanta@gmail.com">atelier.consultanta@gmail.com</a>
```

Aceste valori sunt exemplele candidate cerute și nu sunt considerate aprobate prin acest raport.

## Testare umană rămasă

Sesiunea efectivă cu NVDA/VoiceOver este `DE_VALIDAT_UMAN`. Procedura completă se află în `docs/contact-accessibility-manual-qa.md`.

## Capturi

- `reports/qa/contact-accessibility-desktop.png`
- `reports/qa/contact-accessibility-mobile-errors.png`
