# Revizie după feedback-ul beneficiarului — 31 august 2026

S-au păstrat structura aprobată și tranzițiile native la scroll în ambele sensuri. Sculptura din prima secțiune a fost înlocuită cu tabelul celor zece măsuri existente, afișat fără acordeon. Fiecare măsură are o ilustrație conceptuală distinctă: investiție într-o clădire, fermă, tractor, seră, panouri solare, camion electric, casă / revenire, autobuz electric, stație de încărcare sau baterii de stocare.

Hover-ul, focusul cu tastatura și atingerea schimbă scena, denumirea, statutul și linkul de detalii. Scenele inactive nu rulează animații; mișcarea redusă și butonul de oprire a animațiilor sunt respectate. Fără JavaScript, măsurile rămân legături obișnuite. Printscreen-ul menționat nu a fost disponibil; s-a folosit tabelul din sursa anterioară.

Formularul comun de solicitări este acum în ultima secțiune, înaintea componentei Google. Păstrează informarea aprobată, alternativa email sau telefon, câmpurile opționale, protecția anti-spam, rezumatul și reîncercarea după eroare. Pagina sursă este `/`, inclusiv în markup-ul fără JavaScript. Formularul nu derulează homepage-ul la inițializare; comportamentul paginii Contact rămâne păstrat.

Homepage-ul preia culorile comune din `assets/design-profiles.css`. Compararea în browser cu `/fonduri-europene` a confirmat aceleași valori pentru bleumarin (`#0d1f3c`), portocaliu (`#b84716`) și text (`#1a2540`). Header-ul folosește stilurile comune; culorile semantice ale statusurilor din registru nu au fost alterate.

## Verificări efectuate

- Sincronizarea ambilor generatori este stabilă și trece `--check`.
- Contractele homepage-ului, ale registrului programelor și ale suprafețelor publice trec.
- Testul responsive trece la 320, 390, 768 și 1366 px: fără depășire orizontală, o singură scenă vizibilă, toate cele zece selecții la hover, tastatură și atingere, link corect și ilustrație încadrată integral.
- Testul formularului din homepage verifică validarea fără trimitere, păstrarea valorilor între etape, eroare simulată 503, reîncercare și succes simulat; payload-ul identifică homepage-ul. Nu există un al doilea buton de trimitere din fallback în fluxul cu JavaScript.
- Testele comune Contact trec: contract static, backend, browser, fără JavaScript, focus și erori, prevenirea trimiterii duble, reîncercare, 320 px și zoom text 200%.
- Au trecut verificarea conținutului esențial, regulile editoriale și cele 16.818 legături locale.
- Construirea Cloudflare, validarea pachetului, identitatea mărcii și datele de contact trec; pachetul conține cele două formulare așteptate, unul pe homepage și unul în Contact.
- CSS analizat fără erori sau avertismente; JavaScript verificat sintactic.

Verificările de formular folosesc răspunsuri locale simulate; nu au fost trimise solicitări reale. Nu s-a făcut push sau deploy. Aceste verificări nu reprezintă o nouă măsurare INP de teren.

Backup-ul site-ului inițial este neschimbat. Prima variantă imersivă este păstrată suplimentar în `immersive-v1-before-feedback.zip` și în eticheta Git `backup/immersive-v1-before-feedback-2026-08-31`.
