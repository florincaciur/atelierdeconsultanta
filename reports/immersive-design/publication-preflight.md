# Verificarea publicării — 31 august 2026

**Designul este implementat și testat, dar nu a fost publicat.** Înainte de publicare rămân aprobarea designului de către beneficiar și rezolvarea cerinței existente pentru valoarea INP de referință aprobată. Configurațiile de aprobare nu au fost modificate.

## Rezultatul verificării suplimentare

Comanda `node tools/p0-release-gate.js --environment=staging` a fost executată pe pachetul `dist` din worktree-ul separat de validare, la `2026-08-31T13:30:28.988Z`. „Staging” în acest raport înseamnă un server local; nu s-a făcut deploy și nu s-au trimis formulare reale.

- 21 de controale PASS, 2 controale FAIL, zero blocaje de severitate critical.
- Identitatea juridică, contactul, formularul, accesibilitatea, analytics, statusurile programelor, redirecturile, sitemap-ul și controlul editorial au trecut.
- Ambele FAIL-uri privesc aceeași cerință: `performance.inpBaseline` este încă `DE_VALIDAT_UMAN` în `config/p0-release-gate.json`, atât la controlul local, cât și la cel din staging local.
- Responsabilul definit de proiect este `Frontend performance owner`. Regula existentă cere responsabil și retest documentat pentru FAIL-urile high înainte de aprobarea finală; recomandarea controlului este salvarea unui baseline INP aprobat înainte de deploy.

Scriptul afișează decizia globală „PASS” deoarece numai severitatea critical îi blochează automat execuția. Aceasta **nu înseamnă că toate controalele au trecut** sau că aprobarea umană a fost acordată. Raportul JSON original este păstrat în `publication-preflight-2026-08-31.json`.

## Măsurători locale disponibile

| Rută | LCP (ms) | CLS | Răspuns sintetic (ms) |
|---|---:|---:|---:|
| `/` | 132 | 0 | 6 |
| `/fonduri-europene` | 108 | 0,00006 | 28 |
| `/consultanta-fonduri-europene` | 116 | 0,00005 | 14 |
| `/digitalizare-imm` | 128 | 0,00005 | 19 |

Aceste valori se încadrează în pragurile configurate. Proba folosește un browser headless la 390 × 844 px și un server local, limitează cererile externe, apoi măsoară timpul până la două cadre de animație după un click sintetic. Câmpul denumit `syntheticInpMs` în script **nu reprezintă INP real de teren** și nu validează toate interacțiunile. Nu se poate deduce performanța clienților din producție sau o îmbunătățire procentuală față de rapoartele istorice din aceste rezultate.

## Corecții editoriale limitate

Controlul pachetului a identificat trei titluri generice preexistente. Au fost înlocuite numai titlurile, fără schimbarea informațiilor despre finanțare, a linkurilor sau a identificatorilor:

- Autoconsum public: „Verificări înaintea investiției în autoconsum public”.
- Femeia Antreprenor: „Pregătirea investiției prin Femeia Antreprenor”.
- Start-Up Nation: „Cum se aplică regulile publicate pentru ediția 2024”.

După reconstruire, controlul editorial a trecut pe toate cele 104 URL-uri canonice.

Șablonul homepage-ului preia acum și textul de poziționare din configurația editorială existentă, după prezentarea FABER. Pipeline-ul nu mai trebuie să îl adauge separat. După această aliniere s-au repetat controalele editoriale, contractele homepage-ului și testele responsive.

## Ce mai trebuie înainte de publicare

1. Beneficiarul verifică previzualizarea și aprobă înlocuirea paginii principale.
2. Responsabilul de performanță furnizează și aprobă dovada INP cerută de proiect; se documentează sursa, perioada, dispozitivul și rutele acoperite. Măsurătorile sintetice de mai sus nu vor fi folosite ca substitut pentru această dovadă.
3. Într-un checkout curat al versiunii aprobate se reconstruiește site-ul și se repetă gate-ul, apoi se urmează fluxul de publicare existent și se verifică versiunea live, navigarea și animațiile în ambele sensuri.

La ultima verificare din acest task, atât `origin/main`, cât și `https://atelierdeconsultanta.ro/release.json` indicau versiunea de dinaintea designului: `baac7b9e16eaaeac99f580a47b73f5c2b91b3cc8`. Backup-ul acestei versiuni rămâne separat și neschimbat.
