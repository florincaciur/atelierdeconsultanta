# P1.03 — Arhitectura hub-urilor Programe

Data deciziei inițiale: 2026-07-21

Revizie catalog și relații family: 2026-08-24

Sursa de configurare: `config/program-family-hubs.json`
Sursa programelor: `config/seo-programs.json`

## Decizia de URL

Convenția este **păstrarea rutelor canonice existente**. Familia este o proprietate controlată din registru, nu un segment nou impus în URL. Nu se creează rute și nu se implementează redirecturi în P1.03. O schimbare viitoare de rută rămâne blocată până la o mapare source → target și aprobare SEO bazată inclusiv pe date GSC și backlink-uri.

Ruta canonică `/fonduri-europene` este catalogul public. Echivalentul repo pentru `catalogEnabled=true` este `discovery.listed=true`; selecția unică `catalogPrograms()` produce în prezent **23** intrări publice, fără redirect targets. Reuniunea cardurilor celor cinci familii trebuie să fie identică acestei selecții.

| Familie | Rută canonică păstrată | Decizie | Redirect | Motiv |
|---|---|---|---|---|
| AFIR & agricultură | `/afir` | KEEP / REWRITE | Nu | Rută canonică și indexabilă deja folosită ca punct de intrare AFIR. |
| Regional / ADR | `/fonduri-regionale` | KEEP / REWRITE | Nu | Rută canonică existentă pentru familia regională; devine hub, fără schimbare cosmetică de URL. |
| Digitalizare & inovare | `/fonduri-europene-digitalizare` | KEEP / REWRITE | Nu | Rută canonică existentă, aliniată intenției de familie Digitalizare & inovare. |
| Energie | `/finantari-panouri-fotovoltaice` | KEEP / REWRITE | Nu | Ruta performantă existentă este păstrată; H1 lărgește prudent rolul către familia Energie. |
| Antreprenoriat & GAL | `/fonduri-europene-imm` | KEEP / REWRITE | Nu | Ruta canonică existentă este păstrată și primește rolul Antreprenoriat & GAL. |

## Taxonomie controlată

Fiecare program are exact un `discovery.parentHub`. Filtrele nu acceptă valori editoriale în HTML; opțiunile sunt calculate din clasificarea registrului și din programele publicabile.

### Tip solicitant

| Valoare | Etichetă publică |
|---|---|
| `fermieri_agroalimentar` | Fermieri și sector agroalimentar |
| `imm_micro` | IMM și microîntreprinderi |
| `institutii_publice` | Instituții publice |
| `beneficiari_gal` | Beneficiari din teritorii GAL |
| `nespecificat` | Categoria se confirmă în ghid |

### Regiune

| Valoare | Etichetă publică |
|---|---|
| `national` | Național |
| `nord_est` | Regiunea Nord-Est |
| `regional` | Regional |
| `local_gal` | Teritoriu GAL |
| `nespecificat` | Regiunea se confirmă în ghid |

### Tip investiție

| Valoare | Etichetă publică |
|---|---|
| `agricultura` | Agricultură și dezvoltarea fermei |
| `energie_autoconsum` | Energie pentru autoconsum |
| `energie_regenerabila` | Producție de energie regenerabilă |
| `digitalizare` | Digitalizare |
| `inovare` | Cercetare și inovare |
| `investitii_productive` | Investiții productive |
| `antreprenoriat` | Pornirea sau dezvoltarea afacerii |
| `mobilitate` | Mobilitate cu emisii reduse |
| `infrastructura` | Infrastructură și eficiență energetică |
| `dezvoltare_locala` | Dezvoltare locală prin GAL |

Statusul folosește exclusiv taxonomia registrului: `apel_deschis`, `ghid_aprobat_nedeschis`, `consultare_publica`, `calendar_estimativ`, `apel_inchis`, `arhivat`.

## Atribuirea programelor

| Program | Pagină | Hub părinte unic | Stare registru | Card public |
|---|---|---|---|---|
| Programul Regional Nord-Est | `/por-adr-nord-est` | Regional / ADR — `/fonduri-regionale` | `public` | Nu — pagina este chiar hub-ul |
| Fonduri regionale | `/fonduri-regionale` | Regional / ADR — `/fonduri-regionale` | `public` | Nu — pagina este chiar hub-ul |
| DR12 AFIR | `/dr12-afir` | AFIR & agricultură — `/afir` | `public` | Da |
| DR14 AFIR | `/dr14` | AFIR & agricultură — `/afir` | `public` | Da |
| DR18 AFIR | `/dr18` | AFIR & agricultură — `/afir` | `public` | Da |
| Start-Up Nation | `/start-up-nation-2026` | Antreprenoriat & GAL — `/fonduri-europene-imm` | `public` | Da |
| Femeia Antreprenor | `/femeia-antreprenor-2026` | Antreprenoriat & GAL — `/fonduri-europene-imm` | `public` | Da |
| Digitalizare IMM | `/digitalizare-imm` | Digitalizare & inovare — `/fonduri-europene-digitalizare` | `public` | Da |
| Modernizarea microîntreprinderilor – Apel 2 | `/investitii-modernizarea-microintreprinderilor-apel-2` | Regional / ADR — `/fonduri-regionale` | `public` | Da |
| Fondul pentru Modernizare – autoconsum | `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| Fondul pentru Modernizare – energie regenerabilă | `/fondul-modernizare-energie-regenerabila-2026` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| AFIR Autoconsum Agroalimentar | `/afir-autoconsum-agroalimentar` | AFIR & agricultură — `/afir` | `public` | Da |
| Autoconsum instituții publice | `/autoconsum-public-fotovoltaice-institutii-publice` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| PRO INFRA | `/pro-infra` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| Apeluri GAL | `/apeluri-gal` | Antreprenoriat & GAL — `/fonduri-europene-imm` | `public` | Da |
| GAL-AFIR / LEADER | `/gal-afir` | Antreprenoriat & GAL — `/fonduri-europene-imm` | `public` | Da |
| e-MOVE RO | `/e-move` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| PoCIDIF 2.1 | `/pocidif-21` | Digitalizare & inovare — `/fonduri-europene-digitalizare` | `public` | Da |
| PNRR | `/pnrr` | Digitalizare & inovare — `/fonduri-europene-digitalizare` | `public` | Da |
| Diaspora Investește Acasă | `/diaspora-investeste-acasa` | Antreprenoriat & GAL — `/fonduri-europene-imm` | `public` | Da |
| e-DRIVE | `/e-drive` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| e-Mobility RO | `/e-mobility` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| PC1 Stocare stand-alone | `/fondul-modernizare-pc1-stocare` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |
| Programul Tranziție Justă | `/programul-tranzitie-justa` | Regional / ADR — `/fonduri-regionale` | `public` | Da |
| Fondul pentru Modernizare | `/fondul-de-modernizare` | Energie — `/finantari-panouri-fotovoltaice` | `public` | Da |

Înregistrări excluse din cardurile publice până la validare: .

## Wireframe funcțional

### Desktop

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ H1 + introducere 50–80 cuvinte                 [Verifică proiectul]     │
├──────────────────────────────────────────────────────────────────────────┤
│ Tip solicitant │ Regiune │ Tip investiție │ Status │ [Resetează]       │
│ Regiune live: „N programe afișate din N”                                │
├───────────────────────────────────┬──────────────────────────────────────┤
│ Card program                      │ Card program                         │
│ status complet + verificat la     │ status complet + verificat la       │
│ beneficiar + rezumat + sursă      │ beneficiar + rezumat + sursă        │
│ [Vezi condițiile]                 │ [Vezi condițiile]                   │
├───────────────────────────────────┴──────────────────────────────────────┤
│ Cum alegi (3 pași)                         │ CTA verificare proiect     │
├──────────────────────────────────────────────────────────────────────────┤
│ Ghiduri / instrumente relevante │ 5 întrebări reale                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Mobil

```text
┌─────────────────────────────┐
│ H1 + introducere            │
│ [Verifică proiectul]        │
├─────────────────────────────┤
│ Tip solicitant              │
│ Regiune                     │
│ Tip investiție              │
│ Status                      │
│ [Resetează]                 │
│ Rezultat aria-live          │
├─────────────────────────────┤
│ Card program                │
│ [Vezi condițiile]           │
├─────────────────────────────┤
│ Cum alegi + CTA             │
├─────────────────────────────┤
│ Resurse + FAQ               │
└─────────────────────────────┘
```

## Reguli de publicare și indexare

- cardurile sunt generate numai pentru `publicationState=public`, cu `verifiedAt`, `sourceUrl` și `sourceVersion` oficiale;
- beneficiarul este preluat din `eligibleApplicants`; dacă registrul nu îl precizează, cardul cere consultarea ghidului și nu inventează o categorie;
- statusul, data verificării, rezumatul și sursa provin din registrul unic;
- filtrele folosesc controale native, actualizează o regiune `aria-live="polite"` și păstrează selecția în query string prin `history.replaceState`;
- query-urile de filtrare nu sunt linkuri crawlable, iar canonical-ul rămâne ruta hub-ului fără parametri;
- fără JavaScript, toate cardurile și informațiile esențiale rămân vizibile;
- homepage-ul leagă direct cele cinci hub-uri, iar fiecare program public listat este legat din hub: adâncime maximă două clickuri de navigare.

## Copy și întrebări

H1-urile, introducerile, secțiunile „Cum alegi”, cele 25 de întrebări și linkurile strict relevante sunt versionate în `config/program-family-hubs.json`. Introducerile au între 50 și 80 de cuvinte, iar fiecare hub are exact 5 întrebări.
