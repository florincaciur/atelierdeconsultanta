# Audit legături interne contextuale – 21 iulie 2026

## Rezultat

Matricea sitewide conține 6351 legături clasificate. Dintre acestea, 80 sunt legături contextuale administrate pe 22 pagini, iar 16 sunt CTA-uri de conversie. Validarea a identificat 0 erori.

## Distribuția linkurilor pe tip

| Tip | Linkuri | Pagini-sursă | Destinații interne distincte |
|---|---:|---:|---:|
| navigation | 4457 | 91 | 50 |
| contextual | 718 | 91 | 98 |
| next-step | 0 | 0 | 0 |
| source | 583 | 91 | 1 |
| CTA | 593 | 90 | 27 |

Fișierul `internal-link-map.csv` include pentru fiecare legătură numărul de linkuri outgoing și incoming din același tip.

## Reguli verificate

- zero legături contextuale administrate către redirecturi, rute legacy `.html`, pagini noindex sau destinații moarte;
- tracking analytics numai pentru relația de conversie; legăturile editoriale nu emit evenimente CTA;
- ancore descriptive, fără formulări generice precum „click aici”;
- maximum patru relații pe pagina de program: părinte, instrument, comparație/ghid și conversie.

## Pagini fără legături contextuale administrate

Sunt semnalate 69 rute indexabile fără un bloc contextual administrat. Acestea nu sunt tratate automat ca erori: matricea nu generează automat „nori” de resurse pe fiecare pagină. Rute: `/blog`, `/metodologie-verificare-eligibilitate`, `/surse-oficiale-fonduri-europene`, `/acte-necesare-fonduri-europene-nerambursabile`, `/blog-afir-fotovoltaice-ferme-2026`, `/cat-costa-consultanta-fonduri-europene-ghid`, `/cheltuieli-eligibile-digitalizare-imm`, `/cheltuieli-eligibile-pocidif-21`, `/cod-caen-start-up-nation-2026`, `/documente-punctaj-pocidif-21`, `/femeia-antreprenor-2026-conditii-idei-afaceri`, `/ghiduri`, `/glosar-fonduri-europene`, `/greseli-fonduri-europene`, `/intrebari-frecvente`, `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`, `/intrebari/ce-documente-sunt-necesare-pentru-dr12`, `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`, `/pnrr-digitalizare-imm-cheltuieli-eligibile`, `/programul-tranzitie-justa-intrebari-documente` și încă 49 rute disponibile în matricea CSV

## Ancore repetate excesiv

- „consultanță fonduri europene”: 32 pagini-sursă (contextual)
- „contact”: 30 pagini-sursă (contextual)
- „fonduri europene”: 17 pagini-sursă (contextual)
- „verificare eligibilitate”: 17 pagini-sursă (contextual)
- „calendar fonduri europene”: 14 pagini-sursă (contextual)
- „start-up nation”: 14 pagini-sursă (contextual)
- „instrument verifică criteriile inițiale de eligibilitate controlează solicitantul, investiția și documentele înainte de pregătirea dosarului.”: 13 pagini-sursă (contextual)
- „consultanță afir”: 11 pagini-sursă (contextual)
- „fonduri europene imm”: 11 pagini-sursă (contextual)
- „glosar fonduri europene”: 11 pagini-sursă (contextual)
- „metodologie eligibilitate”: 11 pagini-sursă (contextual)
- „surse oficiale”: 11 pagini-sursă (contextual)
- „instrumente”: 10 pagini-sursă (contextual)
- „start-up nation 2026”: 10 pagini-sursă (contextual)
