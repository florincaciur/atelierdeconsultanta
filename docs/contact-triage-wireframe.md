# Wireframe — formular scurt în două etape

## Desktop

```text
┌──────────────────────── Formular ────────────────────────┬──────── Ajutor ────────┐
│ Pasul 1 din 2                    aprox. 60–90 secunde    │ Ce ne ajută             │
│                                                          │ • tip solicitant         │
│ [ Tip solicitant *       ] [ Județ / localitate *     ] │ • localitate             │
│ [ Ce investiție doriți să realizați? *                 ] │ • investiție concretă    │
│ ┌──────────── Email sau telefon * ─────────────────────┐ │ • email SAU telefon      │
│ │ [ Email                ] [ Telefon                  ] │ │ • fără date sensibile   │
│ └──────────────────────────────────────────────────────┘ │                         │
│ ▸ Date opționale, dacă le cunoști                        │                         │
│ [ ] Am citit informarea privind prelucrarea datelor *    │                         │
│                                                          │                         │
│ [ Verifică și trimite ] [ Adaugă detalii ]               │                         │
└──────────────────────────────────────────────────────────┴─────────────────────────┘

Pasul 2 din 2 — opțional
[ Descriere extinsă ] [ Documente disponibile ]
[ Buget / listă cheltuieli ] [ Preferință contact ]
[ Înapoi ] [ Vezi rezumatul ]

Rezumat înainte de trimitere
Tip solicitant … | Localitate … | Investiție … | Email/telefon …
[ Modifică ] [ Trimite solicitarea ]
```

## Mobil și fără JavaScript

Pe mobil, toate câmpurile și acțiunile sunt pe o singură coloană. Cu JavaScript, numai etapa activă este vizibilă, iar valorile rămân în același formular DOM. Fără JavaScript, pașii 1 și 2 sunt afișați succesiv pe aceeași pagină; pasul 2 rămâne opțional, iar validarea finală este făcută de Worker. Rezumatul interactiv este o îmbunătățire progresivă și nu blochează trimiterea informațiilor esențiale.

Ordinea de focus urmează ordinea vizuală. Erorile folosesc `role="alert"`, etapele au titluri programatice, iar perechea email/telefon este un `fieldset` cu cerința comună descrisă explicit.
