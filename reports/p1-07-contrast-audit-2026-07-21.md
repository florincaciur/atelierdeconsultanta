# P1.07 — Raport de contrast și acoperire

Rezultat: **PASS**

Versiune: `p1.07-v1`
Data auditului: 2026-07-21

## Contrast WCAG

| Utilizare | Pereche | Raport | Prag | Rezultat |
|---|---|---:|---:|---|
| text normal | text / background | 14.02:1 | 4.5:1 | PASS |
| text secundar | muted / background | 5.68:1 | 4.5:1 | PASS |
| contur componentă | border / surface | 3.56:1 | 3:1 | PASS |
| CTA primar | white / accent | 5.32:1 | 4.5:1 | PASS |
| CTA hover/active | white / accentHover | 7.67:1 | 4.5:1 | PASS |
| status apel deschis | success / successSurface | 6.77:1 | 4.5:1 | PASS |
| status consultare/calendar | warning / warningSurface | 7.75:1 | 4.5:1 | PASS |
| status închis/arhivat | closed / closedSurface | 7.04:1 | 4.5:1 | PASS |
| eroare | error / errorSurface | 6.59:1 | 4.5:1 | PASS |
| focus pe fundal deschis | focus / surface | 5.69:1 | 3:1 | PASS |
| focus pe fundal închis | focusOnDark / navy | 11.39:1 | 3:1 | PASS |
| text pe fundal închis | white / navy | 16.43:1 | 4.5:1 | PASS |
| link/accent scurt | accent / background | 4.8:1 | 4.5:1 | PASS |

## Pilot și componente detectate

| URL | Contract vizual | Componente prezente |
|---|---|---|
| / | PASS | header, hero, accordion, form, cta, footer |
| /contact | PASS | header, hero, accordion, form, cta, breadcrumb, footer |
| /afir-autoconsum-agroalimentar | PASS | header, hero, statusBadge, table, accordion, cta, breadcrumb, footer |

stickyCta este definit în contract, dar nu este injectat deoarece lipsește din pilot; carousel apare numai pe homepage.

## Contract automat

- PASS: scopedCss
- PASS: body17px
- PASS: lineHeight
- PASS: measure68ch
- PASS: responsiveHeadings
- PASS: focusVisible
- PASS: reducedMotion
- PASS: mobileTarget44
- PASS: loading
- PASS: error
- PASS: statusSymbols
- PASS: stickyCtaContract
