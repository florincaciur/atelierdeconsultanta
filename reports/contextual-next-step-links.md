# Audit linkuri contextuale și next-step – 13 iulie 2026

## Rezultat

Cele șapte pagini prioritare au exact un bloc editorial next-step și maximum patru destinații explicate. Blocurile înlocuite aveau 128 de linkuri; configurația nouă are 63, o reducere netă de 65 linkuri. Validarea a identificat 0 erori.

| Rută | Linkuri în blocul înlocuit | Linkuri next-step | Reducere | Status |
|---|---:|---:|---:|---|
| /verificare-eligibilitate-fonduri-europene | 4 | 4 | 0 | CONFORM |
| /calculator-soc | 5 | 4 | 1 | CONFORM |
| /dr12-afir | 7 | 4 | 3 | CONFORM |
| /dr14 | 6 | 4 | 2 | CONFORM |
| /por-adr-nord-est | 10 | 4 | 6 | CONFORM |
| /femeia-antreprenor-2026 | 6 | 3 | 3 | CONFORM |
| /despre-faber | 5 | 4 | 1 | CONFORM |
| /afir-autoconsum-agroalimentar | 11 | 4 | 7 | CONFORM |
| /fonduri-europene-agricultura | 7 | 4 | 3 | CONFORM |
| /fonduri-regionale | 7 | 4 | 3 | CONFORM |
| /fonduri-europene-nord-est | 9 | 4 | 5 | CONFORM |
| /fonduri-europene-imm | 8 | 4 | 4 | CONFORM |
| /fonduri-europene | 15 | 4 | 11 | CONFORM |
| /consultanta-afir | 11 | 4 | 7 | CONFORM |
| /finantari-panouri-fotovoltaice | 7 | 4 | 3 | CONFORM |
| /investitii-modernizarea-microintreprinderilor-apel-2 | 10 | 4 | 6 | CONFORM |

## Distribuția linkurilor pe tip

| Tip | Linkuri | Pagini-sursă | Destinații interne distincte |
|---|---:|---:|---:|
| navigation | 4179 | 102 | 42 |
| contextual | 937 | 95 | 92 |
| next-step | 63 | 16 | 22 |
| source | 666 | 102 | 1 |
| CTA | 552 | 102 | 36 |

Fișierul `internal-link-map.csv` include pentru fiecare legătură numărul de linkuri outgoing și incoming din același tip.

## Reguli verificate

- zero linkuri next-step către redirecturi, rute legacy `.html`, pagini noindex sau destinații moarte;
- atribute analytics complete și coerente cu sursa și destinația;
- explicație de o propoziție pentru fiecare ancoră descriptivă;
- minimum un link și maximum patru linkuri în fiecare bloc prioritar;
- sursa oficială DR12 este clasificată separat ca link `next-step`, cu destinație externă securizată.

## Pagini fără link next-step

Sunt semnalate 86 rute indexabile fără next-step. Acestea nu sunt tratate automat ca erori deoarece remedierea este limitată deliberat la paginile prioritare, pentru a evita proliferarea artificială a blocurilor: `/`, `/apeluri-gal`, `/consultanta-fonduri-europene`, `/digitalizare-imm`, `/e-move`, `/management-proiecte-fonduri-europene`, `/plan-de-afaceri-fonduri-europene`, `/pocidif-21`, `/pro-infra`, `/programul-tranzitie-justa`, `/programul-tranzitie-justa-intrebari-documente`, `/proiectare-fonduri-europene`, `/start-up-nation-2026`, `/studiu-fezabilitate-fonduri-europene`, `/blog`, `/glosar-fonduri-europene`, `/metodologie-verificare-eligibilitate`, `/studii-de-caz-fonduri-europene`, `/surse-oficiale-fonduri-europene`, `/acte-necesare-fonduri-europene-nerambursabile` și încă 66 rute disponibile în matricea CSV

## Ancore repetate excesiv

- „consultanță fonduri europene”: 45 pagini-sursă (contextual)
- „contact”: 37 pagini-sursă (contextual)
- „verificare eligibilitate”: 28 pagini-sursă (contextual)
- „fonduri europene”: 23 pagini-sursă (contextual)
- „calendar fonduri europene”: 16 pagini-sursă (contextual)
- „digitalizare imm”: 16 pagini-sursă (contextual)
- „consultanță afir”: 15 pagini-sursă (contextual)
- „start-up nation”: 15 pagini-sursă (contextual)
- „surse oficiale”: 15 pagini-sursă (contextual)
- „fonduri europene imm”: 14 pagini-sursă (contextual)
- „instrumente”: 14 pagini-sursă (contextual)
- „glosar fonduri europene”: 12 pagini-sursă (contextual)
- „metodologie eligibilitate”: 12 pagini-sursă (contextual)
- „dr 12 afir”: 11 pagini-sursă (contextual)
- „start-up nation 2026”: 11 pagini-sursă (contextual)
- „digitalizare imm / pnrr”: 9 pagini-sursă (contextual)
- „gal afir”: 9 pagini-sursă (contextual)
- „ghiduri”: 9 pagini-sursă (contextual)
- „pocidif 2.1”: 9 pagini-sursă (contextual)
