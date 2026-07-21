# Decizii SEO/business necesare după auditul tehnic

Nicio pereche de mai jos nu a fost redirecționată automat. Până la aprobare, URL-urile își păstrează starea tehnică existentă.

| Subiect | Stare curentă | Decizie necesară | Owner propus | Test după aprobare |
|---|---|---|---|---|
| `/gdpr` → `/politica-de-confidentialitate` | `/gdpr` este indexabil, dar exclus din sitemap; 7 linkuri interne îl indică | Aviz juridic și aprobare SEO pentru migrare + 301 | Jurist + SEO lead | 301 într-un hop, target 200/self-canonical, source absent din sitemap și linkuri |
| Pagini de program în validare | 8 rute sunt `noindex`, iar 29 de linkuri interne le indică | Consultant FABER confirmă statusul/sursa; apoi editorul decide publicare sau retragere din navigare | Consultant FABER + editor | Status/sursă aprobate și self-canonical în sitemap, ori linkuri eliminate dacă rămân nepublice |
| URL-uri concurente din `config/url-consolidation-candidates.json` | Rămân 200/self-canonical; nu s-au creat redirecturi | Aprobare pe baza GSC, backlinkurilor, conversiilor și rolului unic | Proprietar + SEO lead | Harta aprobată, migrare conținut, 301 direct și linkuri actualizate |
| URL-uri istorice necunoscute | 404 corect, fără redirect la homepage | 404/410 sau destinație semantică doar pentru fiecare caz confirmat | SEO lead + owner conținut | Statusul aprobat; fără soft-404, chain sau redirect generic |
| Redirectul de host `www` | Defectul live este confirmat; patch-ul și ruta worker sunt pregătite | Nu cere decizie semantică; cere deploy și recrawl | DevOps/dezvoltator | Orice URL `www` face exact un 301 către HTTPS non-www și targetul răspunde 200 |

## URL-uri concurente care rămân blocate pentru aprobare

- `/fonduri-europene` vs `/fonduri-nerambursabile`
- `/digitalizare-imm` vs `/granturi-digitalizare-imm`
- `/consultanta-fonduri-europene` vs `/firma-consultanta-fonduri-europene`
- `/eligibilitate-fonduri-europene` vs `/verificare-eligibilitate-fonduri-europene`
- `/dr12-afir` vs `/dr-12-afir-instalarea-tinerilor-fermieri`
- `/dr14` vs `/dr-14-afir-conditii-eligibilitate-greseli-frecvente`

Deciziile detaliate și inventarul de metrici rămân în `reports/url-consolidation-approval-2026-07-21.md` și `reports/url-consolidation-inventory-2026-07-21.csv`.
