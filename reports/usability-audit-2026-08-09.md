# Audit de utilizare — atelierdeconsultanta.ro

Data auditului: 9 august 2026

## Rezumat

Buildul public acoperă 100 de URL-uri canonice și nu are pagini orfane, linkuri locale rupte, linkuri interne către redirecturi sau erori în datele structurate. Navigația globală este coerentă la 320, 360, 390, 768, 1024 și 1366 px. Paginile refăcute în această etapă — homepage, Contact, Fonduri europene, Proiectare, DR 14, Calculator SO și cele patru programe noi — nu necesită o nouă intervenție imediată.

Numărul de cuvinte din audit este folosit numai ca semnal de profunzime, nu ca obiectiv editorial. Prioritatea reală este ușurința cu care utilizatorul înțelege statutul, își recunoaște situația și găsește următorul pas.

## Prioritate ridicată

1. `/verificare-eligibilitate-fonduri-europene`
   - Pagina are 662 de cuvinte, niciun FAQ vizibil și nu are un bloc administrat de linkuri „pasul următor”.
   - Recomandare: unificarea cu traseul de triere din Contact, exemple pe tipuri de solicitant, rezultate posibile clar delimitate și legături către Calculator SO, documente și Contact.

2. `/dr12-afir`
   - Pagina are 987 de cuvinte și un singur FAQ, iar ierarhia este mai greu de parcurs decât modelul DR 14.
   - Recomandare: migrare la formatul DR 14 — răspuns rapid, statut, cifre-cheie, potrivire/nepotrivire, investiții, documente în `<details>`, pași, surse și FAQ.

3. `/pro-infra`
   - Pagina are 611 cuvinte și un singur FAQ; este una dintre cele mai subțiri pagini de program.
   - Recomandare: refacere în noul format de program, cu filtru tehnic pentru beneficiar, investiție și limitele schemei.

4. `/afir`
   - Hub important, dar cu numai 863 de cuvinte și cinci programe/repere prezentate într-un format mai vechi.
   - Recomandare: diagramă de decizie DR 12 versus DR 14 versus autoconsum, statut vizibil pe card și Calculator SO integrat în primul ecran util.

## Prioritate medie

5. `/fonduri-europene-imm`
   - Recomandare: separarea mai clară între antreprenoriat național, inițiative GAL și programul pentru diaspora; filtre după vechimea firmei și localizare.

6. `/finantari-panouri-fotovoltaice`
   - Hubul deservește opt programe și devine dens.
   - Recomandare: filtru după autoconsum, producție, stocare, transport și tip de beneficiar; comparație compactă a statutului și sursei.

7. `/calendar-fonduri-europene`
   - Recomandare: cronologie filtrabilă după familie și statut, cu data ultimei verificări pe fiecare rând și distincție puternică între estimare, consultare și depunere deschisă.

8. `/surse-oficiale-fonduri-europene`
   - Recomandare: grupare pe autoritate și program, căutare în pagină, marcarea ultimului document verificat și legături reciproce cu paginile de program.

9. `/instrumente`
   - Pagina rămâne indexabilă și descoperibilă, deși a fost eliminată din navigația principală.
   - Recomandare: transformare într-un hub compact de instrumente, cu rezultat/livrabil explicit pentru fiecare card și traseu direct spre programul relevant.

10. `/ghiduri`
    - Are profunzime editorială bună, dar este o listă lungă și nu mai este în meniul principal.
    - Recomandare: filtre după etapa proiectului, beneficiar și familie de finanțare; evidențierea ghidurilor actualizate recent.

## Prioritate de uniformizare

11. `/e-move`
    - Conținutul este suficient, însă formatul poate fi aliniat cu e-DRIVE și e-Mobility RO pentru comparație vizuală directă.

12. Paginile de program mai vechi din familiile regional, digitalizare și antreprenoriat
    - Recomandare: migrare graduală la componenta unică folosită de DR 14 și de cele patru pagini noi, fără modificarea URL-urilor canonice.

## Dovezi tehnice

- 100 URL-uri canonice verificate; 0 pagini orfane.
- 14.924 linkuri locale și 685 fragmente de ancoră verificate; 0 probleme.
- 144 reguli de redirect; 0 bucle, 0 lanțuri, 0 linkuri interne către redirecturi.
- 100 pagini indexabile cu date structurate conforme; 81 pagini cu FAQPage și un WebApplication pentru Calculator SO.
- 12 politici de crawler public verificate; rutele private rămân protejate.
- 28 observații de limbaj generativ, niciuna cu severitate ridicată.
- 7 rute testate în șase viewporturi și 170 de pagini publice cu skip-link valid.
