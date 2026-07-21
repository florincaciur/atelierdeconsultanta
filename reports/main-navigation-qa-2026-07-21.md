# P1.02 — QA navigare principală

| Lățime | Mod | Rezultat | Captură |
|---:|---|---|---|
| 320px | mobile | PASS | `reports/main-navigation-qa-2026-07-21/navigation-320-mobile.png` |
| 360px | mobile | PASS | `reports/main-navigation-qa-2026-07-21/navigation-360-mobile.png` |
| 390px | mobile | PASS | `reports/main-navigation-qa-2026-07-21/navigation-390-mobile.png` |
| 768px | mobile | PASS | `reports/main-navigation-qa-2026-07-21/navigation-768-mobile.png` |
| 1024px | mobile | PASS | `reports/main-navigation-qa-2026-07-21/navigation-1024-mobile.png` |
| 1366px | desktop | PASS | `reports/main-navigation-qa-2026-07-21/navigation-1366-desktop.png` |

## Contract verificat

- șase destinații principale și CTA separat;
- disclosure-uri mobile bazate pe `button` și `aria-expanded`;
- Escape închide disclosure-ul/meniul și restaurează focusul;
- tab order nativ, focus vizibil și `aria-current="page"`;
- target-uri mobile de minimum 44×44 CSS px;
- fără blocarea scroll-ului la deschiderea meniului;
- fără overflow orizontal la 320, 360, 390, 768, 1024 și 1366 px;
- zero statusuri sau valori de program în navigare.
