# Viteză, mobil și conversie · 10 noiembrie 2026

Comparația folosește paginile publice servite de Cloudflare. Revizia de referință este `b5560907`, iar revizia optimizată măsurată este `b322f4b6`. [Măsurătorile inițiale](before.json) · [Măsurătorile după publicare](after.json)

## Laborator mobil

Chromium 148 pe Windows, procesor Ryzen 5 6600H, profil Playwright Pixel 7 cu viewport de 412 × 839 px și DPR 2,625. CPU încetinit de patru ori prin CDP. Profilul principal folosește 1.600 kbps descărcare, 750 kbps încărcare și latență de 150 ms. Cache-ul browserului și service worker-ele sunt dezactivate pentru fiecare navigare. Sunt raportate medianele a trei rulări. Pentru contact, o rulare de referință fără candidat LCP a fost completată de o rulare suplimentară a aceleiași pagini. [Repetarea contactului](before-contact-repeat.json)

LCP provine din ultima intrare `largest-contentful-paint` înaintea interacțiunilor. CLS este maximul ferestrelor de schimbări fără intrare recentă. Latența interacțiunii provine din Event Timing pentru trei atingeri reale emise de Playwright. Scenariile schimbă grupul de programe, deschid și închid documentele, adaugă și șterg un rând SO sau deschid și închid detaliile opționale din contact. Aceste durate sunt observații de laborator pentru scenariile respective. INP de teren este raportat separat.

| Pagină | LCP în ms | CLS | Interacțiune în ms | Timp blocant în ms |
| --- | ---: | ---: | ---: | ---: |
| Homepage | 2.424 → 2.316 | 0 → 0 | 144 → 160 | 433 → 261 |
| e-DRIVE | 1.556 → 1.400 | 0 → 0 | 104 → 104 | 375 → 244 |
| ADR Centru | 1.488 → 1.388 | 0 → 0 | 88 → 96 | 385 → 242 |
| Calculator SO | 1.748 → 1.624 | 0,03731 → 0 | 192 → 176 | 798 → 250 |
| Contact | 1.568 → 1.528 | 0 → 0 | 144 → 128 | 600 → 290 |

Timpul blocant însumează porțiunea fiecărei sarcini lungi care depășește 50 ms între FCP și punctul de eșantionare. Prima încărcare homepage a avut LCP de 4.928 ms înainte și 4.860 ms după. Intervalele din trei rulări permit verificarea variației. Creșterile de 16 ms pe homepage și 8 ms pe ADR Centru provin din aceste scenarii de atingere.

Transferul folosește octeții codificați raportați de CDP până la aproximativ 1,1 secunde după evenimentul de încărcare. Valorile în kB sunt zecimale și rotunjite. Ilustrațiile SVG inline intră în greutatea documentului HTML.

| Pagină | Transfer total în kB | Scripturi în kB | Imagini în kB | Domenii externe în kB | Cereri |
| --- | ---: | ---: | ---: | ---: | ---: |
| Homepage | 720 → 529 | 586 → 406 | 9,3 → 7,4 | 395 → 205 | 48 → 32 |
| e-DRIVE | 689 → 451 | 616 → 389 | 9,3 → 7,1 | 420 → 182 | 39 → 23 |
| ADR Centru | 683 → 445 | 617 → 389 | 9,1 → 7,1 | 420 → 182 | 38 → 22 |
| Calculator SO | 827 → 452 | 619 → 391 | 9,3 → 7,4 | 556 → 182 | 43 → 24 |
| Contact | 714 → 448 | 646 → 392 | 9,3 → 7,3 | 447 → 182 | 45 → 23 |

Linkul direct Preferred Sources înlocuiește widgetul pe cele 107 canonice. Încărcarea anterioară implica `news.google.com` și `www.gstatic.com`. Calculatorul SO folosește fonturile sistemului și elimină cei 134 kB măsurați pentru fișierele de font. Din transferul rămas, încărcările Google Tag apar prin `www.googletagmanager.com` și prin ruta `/vvcx/` de pe domeniul site-ului. Pe homepage, stylesheet-ul de iconuri de la `unpkg.com` reprezintă aproximativ 23 kB. [Implementarea cu link direct, Google Search Central](https://developers.google.com/search/docs/appearance/preferred-sources)

## Conexiune de 400 kbps

O rulare pe pagină și revizie, cu latență de 400 ms, 400 kbps în ambele sensuri și același CPU încetinit de patru ori. Evenimentul `load` include resursele încărcate odată cu pagina. Contactul a avut un candidat LCP observabil după eliminarea derulării și a focusului automat la inițializare. [Înainte](before-constrained.json) · [După](after-constrained.json)

| Pagină | LCP în ms | Evenimentul load în secunde | Interacțiune în ms |
| --- | ---: | ---: | ---: |
| Homepage | 5.800 → 5.612 | 15,16 → 12,25 | 168 → 144 |
| e-DRIVE | 3.644 → 3.452 | 14,38 → 11,03 | 104 → 112 |
| ADR Centru | 3.372 → 3.636 | 14,35 → 10,90 | 112 → 96 |
| Calculator SO | 3.992 → 3.736 | 17,17 → 10,99 | 208 → 160 |
| Contact | n/d → 3.676 | 15,01 → 10,94 | 144 → 136 |

La 400 kbps, evenimentul `load` a venit mai devreme pe toate paginile. LCP pe ADR Centru a crescut cu 264 ms în rularea unică, iar homepage a rămas peste cinci secunde.

## Date de teren CrUX

Ultimul interval afișat a fost 11 octombrie – 7 noiembrie 2026. Pentru domeniu și pentru cele cinci pagini, CrUX Vis nu a furnizat percentile mobile curente pentru LCP, INP și CLS. Pe toate dispozitivele, domeniul are p75 LCP **1.004 ms**, INP **86 ms** și CLS **0,00**. Pentru URL-ul e-DRIVE, agregarea pe toate dispozitivele a furnizat CLS **0,00**. API-ul public PageSpeed Insights a răspuns HTTP 429. [Dovezile CrUX Vis](crux.json) · [CrUX Vis pentru domeniu](https://cruxvis.withgoogle.com/#/?view=cwvsummary&url=https%3A%2F%2Fatelierdeconsultanta.ro%2F&identifier=origin&device=ALL&periodStart=0&periodEnd=-1&display=p75s)

## Conversie și accesibilitate

- CTA-urile păstrează `source_page` chiar cu referrerul suprimat. În formular au fost verificate e-DRIVE, ADR Centru și transferul valorii de 1.945 SO. Traseele cu email și telefon au fost validate separat. Scenariul ADR Centru a primit un răspuns simulat 503 cu întârziere, a păstrat datele și a reușit la reîncercare. Șase cereri au fost interceptate în browser. Verificarea generală a producției folosește GET.
- Tasta Tab ajunge la legătura de salt. Meniul mobil se deschide cu Enter și se închide cu Escape când focusul este pe buton. Comutarea grupurilor de programe funcționează cu tastatura. Cu mișcare redusă, testul a găsit zero animații active în conținutul principal.
- A fost corectat contrastul subsolurilor homepage și SO. Regula automată de contrast a raportat zero încălcări în stările verificate. Cele cinci CTA-uri principale au fost măsurate direct pe fundalul randat. Au rămas noduri pe care axe le-a marcat pentru verificare manuală, listate în [rezultatul brut din producție](qa-live.json).
- Cu JavaScript dezactivat, homepage oferă legături către programe și calendarul complet. Pe e-DRIVE și ADR Centru sunt vizibile statutul, măsurile și exemplul ERP. Pe calculator rămân exemplele și accesul la tabelul coeficienților. La contact, butonul de trimitere nativ rămâne vizibil.

Verificarea separată a generatorului istoric al traseului homepage P1.21 raportează o diferență preexistentă de ordine a resurselor în head. Diferența se reproduce în revizia de referință. Testele de navigare și conversie folosesc pagina randată.

Pentru reproducere, rulează `node tools/audit-mobile-performance.js --output=profil-mobil.json` și `node tests/mobile-conversion-contract.mjs --origin=https://atelierdeconsultanta.ro --output=qa.json`. Testele de conversie blochează cererile de scriere din browser și răspund local la API.
