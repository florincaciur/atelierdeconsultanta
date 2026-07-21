# P1.09 — Wireframe și reguli pentru pagini lungi

## Program / ghid — desktop

```text
┌──────────────────────────────── Header sticky ────────────────────────────────┐
├─ Breadcrumb ──────────────────────────────────────────────────────────────────┤
├──────────────────────────── Hero / status curent ─────────────────────────────┤
│                                                                                │
│  ┌──── Cuprins sticky ────┐  ┌──────── Conținut decizional, max. 68ch ─────┐ │
│  │ Secțiune activă         │  │ Rezumat + status + criterii + valori         │ │
│  │ Context și reguli       │  │ [Verifică proiectul]                        │ │
│  │ Documente               │  │ Riscuri și condiții                         │ │
│  │ Riscuri                 │  │ Tabele/carduri comparabile                  │ │
│  │ … scroll intern         │  │ Istoric / implementare / metodologie       │ │
│  └─────────────────────────┘  │ FAQ și detalii secundare: <details> native  │ │
│                               └─────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────┘
```

Cuprinsul rămâne sticky numai în limita articolului principal. Secțiunea activă folosește `aria-current="location"`, iar fiecare titlu are o ancoră deterministă și `scroll-margin-top` pentru header.

## Homepage — desktop

```text
┌──────────────────────────────── Header sticky ────────────────────────────────┐
├──────────────────────────────────── Hero ─────────────────────────────────────┤
├────────────── Cuprins sticky orizontal, 4–5 coloane adaptive ─────────────────┤
├──────────────────────────── Secțiunile homepage-ului ─────────────────────────┤
└───────────────────────────────────────────────────────────────────────────────┘
```

Homepage-ul păstrează secțiunile full-width; cuprinsul nu forțează conținutul într-o coloană îngustă.

## Mobil

```text
┌──────── Header ────────┐
├──────── Hero ──────────┤
├─ ▸ Cuprins ────────────┤  disclosure nativ, închis inițial cu JS
├─ Rezumat / status ─────┤  deschis integral fără JS
├─ Acțiune decizională ──┤
├─ Conținut max. 68ch ───┤
├─ Tabele scroll intern ─┤
└────────────────────────┘
```

## Reguli implementate

- Pragul se calculează automat din conținutul principal: homepage forțat, apoi pagini `program`/`ghid` cu peste 1.500 de cuvinte.
- Generatorul rulează după inventarul P1.01 și modifică numai fișierul canonic al fiecărei rute.
- Rezumatul factual existent rămâne înaintea detaliilor; pe programe, prima acțiune este plasată imediat după rezumatul decizional.
- FAQ, achiziții, mecanisme de plată și listele complete de surse devin detalii secundare native. Textul rămâne în HTML.
- Tabelele primesc un wrapper focusabil, cu nume accesibil și scroll intern; pagina nu capătă overflow orizontal.
- Fără JavaScript, cuprinsul este deschis și toate textele rămân disponibile. JavaScript-ul actualizează doar starea secțiunii și compactarea inițială pe mobil.
