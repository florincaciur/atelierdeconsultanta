# P1.02 — Sitemap de navigare

Configurație canonică: `config/main-navigation.json`

Breakpoint desktop: **1180px**
CTA separat: **Începe verificarea proiectului** → `/contact`

| Destinație principală | Destinație secundară / URL | Interacțiune |
|---|---|---|
| Servicii | Analiză eligibilitate → `/verificare-eligibilitate-fonduri-europene` | disclosure |
| Servicii | Consultanță → `/consultanta-fonduri-europene` | disclosure |
| Servicii | Proiectare → `/proiectare-fonduri-europene` | disclosure |
| Servicii | Implementare → `/management-proiecte-fonduri-europene` | disclosure |
| Programe | AFIR & agricultură → `/afir` | disclosure |
| Programe | Regional / ADR → `/fonduri-regionale` | disclosure |
| Programe | Digitalizare & inovare → `/fonduri-europene-digitalizare` | disclosure |
| Programe | Energie → `/finantari-panouri-fotovoltaice` | disclosure |
| Programe | Antreprenoriat & GAL → `/fonduri-europene-imm` | disclosure |
| Calculatoare | Calculator punctaj POR Micro – Apelul 2 → `/investitii-modernizarea-microintreprinderilor-apel-2#simulator-punctaj-apel-2` | disclosure |
| Calculatoare | Calculator SO → `/calculator-soc` | disclosure |
| Calculatoare | Calculator punctaj DR 14 → `/dr14#dr14-punctaj` | disclosure |
| Despre FABER | Echipa → `/despre-faber` | disclosure |
| Despre FABER | Metodologie → `/metodologie-verificare-eligibilitate` | disclosure |
| Despre FABER | Studii de caz → `/studii-de-caz-fonduri-europene` | disclosure |
| Despre FABER | Date companie → `/despre-faber#about-public-data` | disclosure |
| Contact | `/contact` | direct |

```mermaid
graph TD
  NAV["Navigare principală"] --> S["Servicii"]
  NAV --> P["Programe"]
  NAV --> CALC["Calculatoare"]
  CALC --> MICRO["Punctaj POR Micro – Apelul 2"]
  CALC --> SO["Calculator SO"]
  CALC --> DR14["Punctaj DR 14"]
  NAV --> D["Despre FABER"]
  NAV --> C["Contact"]
  NAV -. CTA separat .-> V["Începe verificarea proiectului"]
```

## Reguli

- Desktop: patru disclosure-uri semantice, inclusiv meniul Calculatoare, Contact ca link direct și CTA separat.
- Mobil: butoane disclosure reale cu `aria-expanded`; linkurile nu deschid accidental grupurile.
- Maximum 12 linkuri vizibile în fiecare grup.
- Navigarea nu conține statusuri, etichete de status, date de verificare sau valori de program.
- URL-urile canonice nu sunt schimbate de această configurație.
