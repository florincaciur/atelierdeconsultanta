# Changelog editorial P0.02

Data: **2026-08-18**. Acest changelog documentează corecțiile și blocajul editorial; nu reprezintă aprobarea copy-ului candidat.

## dr12-afir

- **Înainte (observat live):** Homepage: card «Activ» cu 200.000 EUR și 80%/65%; meniu: «variantă consultativă»; paginile DR12 foloseau formulări nealiniate.
- **Corecție candidat:** `apel_deschis` — Alte sectoare: termen expirat · Zootehnic până la 2 dec., 15:59:59
- **Acțiune aplicată:** exclus din meniu, homepage, carusele, carduri factuale și JSON-LD; URL-urile prioritare au `noindex, follow` și mesaj neutru de suspendare.
- **Valori:** eliminate cât timp `numericClaimsApproved=false`.
- **Publicare finală:** blocată; validator Codex — verificare documentară la solicitarea utilizatorului, aprobare `approved`.
- **Copy pregătit pentru aprobare:** DR-12, verificat la 2026-11-11. Depunerea este deschisă. Sector zootehnic are termen în contor la 02.12.2026, ora 15:59:59. Pentru Alte sectoare, termenul afișat de 11.11.2026, ora 00:00, a expirat. Sursa: contorul AFIR, consultat după miezul nopții.
- **Sursă primară:** https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/
- **URL-uri afectate:** `/`, `/admin`, `/afir`, `/calculator-soc`, `/consultanta-afir`, `/dr-12-afir-instalarea-tinerilor-fermieri`, `/dr12-afir`, `/dr12-afir-tineri-fermieri`, `/dr14`, `/dr14-afir-ferme-mici`, `/fonduri-europene`, `/fonduri-europene-agricultura`, `/fonduri-europene-caen/0111-culturi-cereale`, `/fonduri-europene-nerambursabile-2026`, `/fonduri-europene-nord-est`, `/fonduri-pentru-ferme`, `/fonduri-pentru-utilaje-agricole`, `/gal-afir`, `/ghiduri`, `/intrebari/ce-documente-sunt-necesare-pentru-dr12`, `/resurse`, `/resurse-utile`, `/studii-de-caz-fonduri-europene`, `/verificare-eligibilitate-fonduri-europene`, `/webinarii`.

## dr14-afir

- **Înainte (observat live):** Pagina și suprafețele globale indicau în mod depășit o variantă consultativă, fără valorile confirmate în ghidul final.
- **Corecție candidat:** `apel_deschis` — Depuneri până la 16 noiembrie · achizițiile simple sunt închise
- **Acțiune aplicată:** exclus din meniu, homepage, carusele, carduri factuale și JSON-LD; URL-urile prioritare au `noindex, follow` și mesaj neutru de suspendare.
- **Valori:** eliminate cât timp `numericClaimsApproved=false`.
- **Publicare finală:** blocată; validator Codex — verificare documentară la solicitarea utilizatorului, aprobare `approved`.
- **Copy pregătit pentru aprobare:** Depuneri până la 16 noiembrie; componenta achiziții simple este închisă — verificat la 2026-11-10. Sursa: Agenția pentru Finanțarea Investițiilor Rurale (AFIR), Contorul oficial al sesiunilor active DR-14; cererea v1.1 din 25.08.2026 și clarificarea pe componente din 21.08.2026. Depunerea este deschisă.
- **Sursă primară:** https://depunerepspac.afir.ro/Sesiune/Lista
- **URL-uri afectate:** `/`, `/afir`, `/calculator-soc`, `/consultanta-afir`, `/dr-14-afir-conditii-eligibilitate-greseli-frecvente`, `/dr14`, `/dr14-afir-ferme-mici`, `/fonduri-europene`, `/fonduri-europene-agricultura`, `/fonduri-europene-caen/0111-culturi-cereale`, `/fonduri-europene-nord-est`, `/fonduri-pentru-ferme`, `/fonduri-pentru-utilaje-agricole`, `/gal-afir`, `/ghiduri`, `/intrebari/ce-documente-sunt-necesare-pentru-dr12`, `/resurse-utile`, `/studii-de-caz-fonduri-europene`.

## pro-infra

- **Înainte (observat live):** Homepage: card «Activ» cu 15.000.000 EUR și 100%, în timp ce meniul spunea schemă aprobată și pagina nu confirma un apel deschis.
- **Corecție candidat:** `ghid_aprobat_nedeschis` — Apel în curs de lansare – calendarul depunerii nu este anunțat
- **Acțiune aplicată:** exclus din meniu, homepage, carusele, carduri factuale și JSON-LD; URL-urile prioritare au `noindex, follow` și mesaj neutru de suspendare.
- **Valori:** eliminate cât timp `numericClaimsApproved=false`.
- **Publicare finală:** blocată; validator Codex — verificare documentară la solicitarea utilizatorului, aprobare `approved`.
- **Copy pregătit pentru aprobare:** Apel în curs de lansare – calendarul depunerii nu este anunțat — verificat la 2026-11-10. Sursa: Ministerul Transporturilor și Infrastructurii, Schema PRO INFRA consolidată, art. 5, 13 și 16, cu modificările Ordinului nr. 101/12.02.2026. Depunerea nu este deschisă.
- **Sursă primară:** https://legislatie.just.ro/Public/DetaliiDocument/306916
- **URL-uri afectate:** `/`, `/fonduri-europene`, `/fonduri-europene-nerambursabile-2026`, `/pro-infra`.

## digitalizare-imm

- **Înainte (observat live):** Homepage: card «Activ» cu 100.000 EUR și 90%; registrul/hubul folosea «calendar estimativ», iar apelul PNRR citat avea depunerea încheiată la 30.06.2023.
- **Corecție candidat:** `apel_inchis` — Apel închis – depunerea nu este deschisă
- **Acțiune aplicată:** exclus din meniu, homepage, carusele, carduri factuale și JSON-LD; URL-urile prioritare au `noindex, follow` și mesaj neutru de suspendare.
- **Valori:** eliminate cât timp `numericClaimsApproved=false`.
- **Publicare finală:** blocată; validator Caciur Florin / Bogdan Iftode, aprobare `approved`.
- **Copy pregătit pentru aprobare:** Apel închis – depunerea nu este deschisă — verificat la 2026-11-10. Sursa: Ministerul Investițiilor și Proiectelor Europene, Ordinul MIPE nr. 607/28.04.2026; modifică Ghidul aprobat prin Ordinul nr. 3185/2022. Depunerea nu este deschisă.
- **Sursă primară:** https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/
- **URL-uri afectate:** `/`, `/blog`, `/cheltuieli-eligibile-pocidif-21`, `/consultant-fonduri-europene-imm`, `/consultanta-fonduri-europene-bucuresti`, `/consultanta-pnrr-digitalizare`, `/contact`, `/digitalizare-imm`, `/digitalizare-imm-pnrr`, `/dr-12-afir-instalarea-tinerilor-fermieri`, `/fonduri-europene`, `/fonduri-europene-bucuresti`, `/fonduri-europene-caen/4321-instalatii-electrice`, `/fonduri-europene-caen/6201-dezvoltare-software`, `/fonduri-europene-digitalizare`, `/fonduri-europene-nerambursabile-2026`, `/fonduri-europene-nord-est`, `/ghiduri`, `/granturi-digitalizare-imm`, `/idei-afaceri-fonduri-europene`, `/instrumente`, `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`, `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`, `/pnrr-digitalizare-imm-cheltuieli-eligibile`, `/pocidif-21`, `/resurse`, `/studii-de-caz-fonduri-europene`, `/verificare-eligibilitate-fonduri-europene`, `/webinarii`.
