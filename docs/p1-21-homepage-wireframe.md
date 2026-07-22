# P1.21 — Wireframe homepage decizional

## Desktop

```text
┌──────────────────────── header ────────────────────────┐
│ HERO: H1 + explicație + CTA principal / secundar       │
│                              SVG traseu în 5 etape      │
├──────────────── Cum decidem ───────────────────────────┤
│ Solicitant │ Program │ Punctaj │ Buget │ Decizie       │
├──────────────── Programe prioritare ───────────────────┤
│ ← [un singur card activ din maximum 6] →  1 din 6     │
│ Huburi: AFIR │ ADR │ Digitalizare │ Energie │ GAL      │
├──────────────── Servicii ──────────────────────────────┤
│ Eligibilitate │ Consultanță │ Proiectare │ Implementare│
├──────────────── Instrumente ───────────────────────────┤
│ Calculator SO │ Checklist eligibilitate │ Documente    │
├──────────────── De ce FABER ───────────────────────────┤
│ Sursă/status │ analiză integrată │ limite explicite    │
├──────────────── Analiză recentă ───────────────────────┤
│ DR 12 vs DR 14                              [citește]   │
├──────────────── CTA final ─────────────────────────────┤
│ [Începe verificarea]  telefon  telefon  email           │
└──────────────────────── footer ────────────────────────┘
```

## Mobil

```text
┌────────── header / meniu disclosure ──────────┐
│ HERO: H1, text, CTA principal, CTA secundar   │
│ SVG traseu, fără pierdere de informație       │
├────────── Cum decidem (scroll-snap) ──────────┤
│ 01 │ 02 │ 03 │ 04 │ 05                       │
├────────── Carusel unic ───────────────────────┤
│ ← card activ →  · 1 din 6                    │
│ huburile se împachetează pe două rânduri      │
├────────── 4 servicii ─────────────────────────┤
│ carduri într-o singură coloană                │
├────────── 3 instrumente ──────────────────────┤
├────────── 3 dovezi ───────────────────────────┤
├────────── analiză recentă ────────────────────┤
├────────── CTA + contact direct ───────────────┤
└────────── footer ─────────────────────────────┘
```

Cuprinsul rămâne un `details/summary` închis implicit, generat numai cât timp homepage-ul este configurat drept pagină lungă. Nu există conținut ascuns pentru reducerea artificială a înălțimii și nu există formular duplicat.
