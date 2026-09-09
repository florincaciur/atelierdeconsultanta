# P1.16 — Despre FABER: copy, wireframe și validări

Generat din `config/about-faber-governance.json` la 2026-07-22. Acest raport este intern; valorile marcate `DE_VALIDAT_UMAN` nu sunt randate ca fapte publice.

## Copy public implementat

- Hero: „Consultanță prudentă înainte de dosar”.
- Poziționare: „Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar.”
- Operator: randat exclusiv din registrul juridic aprobat `config/legal-identity.json`.
- Echipă: politica de publicare și câmpurile necesare sunt explicate, fără nume, fotografii sau experiență presupusă.
- Metodă: triere → documente → punctaj → dosar → clarificări și implementare.
- Limite: fără promisiune de aprobare, fără a echivala listarea cu acreditarea din partea AFIR, fără rezultate neverificate.
- Dovezi: studii de caz, rezultate și testimoniale numai cu documente, metodă și acord.
- CTA: „Vezi dacă proiectul merită pregătit”.

## Wireframe implementat

```
[Header + navigație]
[Hero: poziționare | CTA principal | CTA metodă | 4 repere]
[Introducere: ce este FABER | criterii de lucru]
[Operator: entitate, CUI, ONRC, sediu, contact — registru canonic]
[Echipă: politica de publicare | checklist profil aprobat]
[Metodă: 01 Triere → 02 Documente → 03 Punctaj → 04 Dosar → 05 Clarificări/implementare]
[Ce nu promite FABER: 3 limite]
[Dovezi publicabile: studiu de caz | rezultat | testimonial]
[Afilieri/listări: formulare condiționată de document oficial]
[Metodologie | Studii de caz | Contact]
[CTA contextual]
[Întrebări frecvente]
[Footer]
```

## Active și dovezi necesare

- Fotografie reală pentru fiecare persoană, fișier original, text alternativ, autor/drept de utilizare și acord scris de publicare.
- Fișă aprobată pentru fiecare persoană: nume, rol, specializări, experiență verificabilă, LinkedIn oficial și paginile de analiză atribuite.
- Pentru studii de caz: documente justificative, program/versiune, perioadă, metodă, acord și regulă de anonimizare.
- Pentru rezultate: baza de calcul, universul analizat, perioada și limitele comparației.
- Pentru nomenclatorul AFIR: URL oficial, document/versiune, dată și potrivirea exactă a FABER PUBLISHING S.R.L.
- Pentru alte afilieri: documentul organizației, valabilitate, entitatea exactă și acordul de publicare.

## Puncte de validare umană

| Înregistrare | Status | Publicare | Date/dovezi necesare |
|---|---|---|---|
| team_profiles | DE_VALIDAT_UMAN | blocked | `fotografie reală și drept de utilizare`; `nume`; `rol`; `specializări`; `experiență verificabilă`; `LinkedIn oficial, dacă există`; `acord pentru publicare`; `pagini de autor atribuite` |
| case_studies_and_results | DE_VALIDAT_UMAN | blocked | `documente justificative`; `beneficiarul poate fi publicat`; `sector`; `program`; `serviciu FABER`; `investiție`; `etapă`; `rezultat verificabil`; `valoare publicabilă`; `locație publicabilă`; `permisiune pentru nume și logo`; `metodă de calcul și perioadă pentru orice valoare`; `regulă de anonimizare`; `aprobarea formulării publice` |
| testimonials | DE_VALIDAT_UMAN | blocked | `text aprobat`; `autor`; `funcție`; `companie`; `permisiune de publicare` |
| afir_nomenclature_listing | DE_VALIDAT_UMAN | blocked | `URL oficial AFIR`; `numele și versiunea documentului`; `data verificării`; `potrivirea exactă a entității juridice`; `aprobarea formulării listată în nomenclatorul orientativ AFIR` |
| other_affiliations | DE_VALIDAT_UMAN | blocked | `document oficial al organizației`; `perioada valabilității`; `entitatea afiliată`; `acord pentru publicare` |

## Poarta de publicare

Până la aprobarea fiecărui rând, site-ul poate afișa doar faptul că informația nu este încă publicată. Nu se publică placeholderul `DE_VALIDAT_UMAN`, profiluri parțiale, rezultate, afilieri sau formulări care sugerează acreditare ori clasament.
