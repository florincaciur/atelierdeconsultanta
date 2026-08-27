# Task 24 — metodologie editorială și trust evidence

Data auditului: **27 august 2026**.

## Stare publică

- Ruta canonică pentru metodologie rămâne `/metodologie-verificare-eligibilitate` și include politica editorială publică.
- Ruta canonică pentru studii de caz și testimoniale rămâne `/studii-de-caz-fonduri-europene`.
- `/studii-de-caz`, `/portofoliu` și `/testimoniale` rămân aliasuri istorice cu redirect 301; URL equity și graful intern nu sunt schimbate.
- Numărul de studii de caz aprobate este **0**.
- Numărul de testimoniale aprobate este **0**.
- Nu se publică `Review` ori `AggregateRating` în JSON-LD cât timp nu există dovezi eligibile și aprobate.

Pagina canonică publică metodologia și criteriile, nu exemple prezentate drept rezultate reale. `config/about-faber-governance.json#trustEvidencePolicy` păstrează starea de publicare, iar `pendingValidations` enumeră informațiile interne care trebuie furnizate înaintea unui caz sau testimonial.

## Gate de publicare

Un studiu de caz poate trece din `blocked` în public numai după documentarea beneficiarului publicabil, sectorului, programului, serviciului FABER, investiției, etapei, rezultatului verificabil și a permisiunilor pentru valoare, locație, nume și logo. Etapa și rezultatul sunt câmpuri diferite: depunerea nu este aprobare, contractarea nu este finalizare, iar o clarificare nu este rezultat financiar.

Un testimonial poate fi publicat numai după păstrarea textului aprobat, autorului, funcției, companiei și permisiunii. Anonimizarea trebuie acceptată explicit. O apreciere nu justifică automat `Review` sau `AggregateRating`; eligibilitatea datelor structurate se verifică separat.

## Comenzi

- `npm run sync:trust-evidence` materializează blocurile publice gestionate.
- `npm run check:trust-evidence` detectează driftul.
- `npm run test:trust-evidence` verifică sursa, starea blocată, redirecturile și absența schema de review.
- `npm run test:trust-evidence:dist` repetă contractul pe artefactul Cloudflare.

Mai puține dovezi reale sunt preferabile unui volum artificial. Orice informație internă încă lipsă rămâne în `docs/faber-remediation/NEEDS_CONFIRMATION.md` și nu este substituită prin exemple inventate.
