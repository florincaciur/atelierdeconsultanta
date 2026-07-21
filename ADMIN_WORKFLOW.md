# ADMIN_WORKFLOW

## Registrul unic al programelor

Datele factuale despre programele de finanțare se modifică exclusiv în
`config/seo-programs.json#programs`, conform `config/program-registry.schema.json`.
`banners.json`, `official-guides.json`, meniul, homepage-ul, paginile și JSON-LD sunt
consumatori generați și nu sunt surse editoriale.

Flux obligatoriu înainte de publicare:

1. Responsabilul editorial confirmă documentul oficial, versiunea și data verificării.
2. Completează registrul și folosește numai unul dintre cele șase statusuri controlate.
3. Rulează `npm run validate:program-registry` și `npm run sync:program-facts`.
4. Rulează `npm run test:program-registry` și `npm run audit:program-facts`.

O înregistrare `pending_validation` poate conține `DE_VALIDAT_UMAN`, dar nu este
publicată în meniu, homepage, carusel sau JSON-LD. Pentru `status=arhivat`, `noindex`
se aplică numai după completarea explicită a `archivedNoindexDecision=noindex` și
numai dacă `evergreenValue=false`.

## Aprobarea factuală P0.02

DR12, DR14, PRO INFRA și Digitalizare IMM au o poartă nominală suplimentară în
`config/program-status-approvals.json`. Cât timp `approvalState=pending`:

1. `validatorName` rămâne `DE_VALIDAT_UMAN`;
2. programul rămâne `publicationState=pending_validation` în registrul unic;
3. valorile, calendarul și copy-ul candidat nu se publică;
4. URL-urile din `publicationHoldUrls` păstrează mesajul neutru și `noindex, follow`.

Consultantul FABER verifică documentul oficial curent, versiunea, caracterul final
sau consultativ și intervalul efectiv. Abia apoi completează nominal validatorul și
data aprobării, actualizează registrul unic și rulează:

1. `npm run report:program-statuses`;
2. `npm run validate:program-statuses`;
3. `npm run sync:program-facts`;
4. `npm run test:program-statuses`;
5. `npm run build`.

Raportul de aprobare este `reports/program-status-validation-2026-07-21.md`, iar
istoricul corecțiilor este `reports/editorial-status-changelog-2026-07-21.md`.

## Guvernanță editorială P0.03

Metadatele de autor, reviewer, sursă, verificare, reverificare, modificare
substanțială și changelog se editează în `config/editorial-governance.json`, conform
`config/editorial-governance.schema.json`. Atribuirea implicită este organizațională;
un nume personal poate deveni public numai cu `personalNameConsent=true`.

Înainte de publicare rulează:

1. `npm run validate:editorial-governance`;
2. `npm run sync:editorial-governance`;
3. `npm run test:editorial-governance`;
4. `npm run build`.

Filtrele din panoul Programe identifică sursa lipsă, verificarea expirată, reviewerul
lipsă și contradicția program–pagină. Expirarea este doar un warning intern și
blochează schimbarea statusului până la reverificare. `dateModified` și sitemap
`lastmod` provin exclusiv din `lastMeaningfulUpdate`; build-ul, CSS-ul și operațiunile
automate nu actualizează data. Procedura completă, de o pagină, este în
`docs/procedura-guvernanta-editoriala.md`.

## Identitate juridică și NAP P0.04

Fișa unică este `config/legal-identity.json`, conform
`config/legal-identity.schema.json`. Valorile observate în site sunt doar candidați
și nu devin date canonice prin simpla lor existență în cod. Până la confirmarea
decidentului și avizul juristului, `approvalState=pending` și
`publicationState=blocked`.

Flux obligatoriu:

1. Decidentul completează pentru fiecare câmp valoarea, sursa internă, aprobatorul
   și data aprobării.
2. Pentru Registrul Comerțului, adresa publică sau profilurile inexistente, se poate
   folosi `not_applicable` numai prin aprobare explicită.
3. Dacă emailul aprobat este `atelier.consultanta@gmail.com`, proprietarul completează
   separat `operationalEmailOwnerConfirmation=approved`.
4. Juristul aprobă Termenii, politica de confidențialitate, operatorul de date,
   contractantul și emitentul facturilor.
5. Se rulează `npm run report:legal-identity`, `npm run validate:legal-identity` și
   `npm run test:legal-identity`.

Comenzile `npm run deploy` și `npm run deploy:pages` încep cu
`validate:legal-identity:publish` și eșuează cât timp fișa nu este complet aprobată.
Tabelul pentru decizie și inventarul suprafețelor sunt în
`reports/legal-identity-approval.md`. Fișa și raportul nu constituie opinie juridică.

## Login și reset local

Adminul este la `/admin/` și are `noindex,nofollow`. Autentificarea locală folosește o singură sursă de adevăr:

- `localStorage.faber_admin_email`
- `localStorage.faber_admin_password`
- `sessionStorage.faber_admin_auth`

Dacă nu există valori locale, se folosesc valorile bootstrap din `admin/index.html`. După login, schimbă credențialele din panoul Setări GitHub. Nu există token GitHub hardcodat în repo.

Butonul „Resetează datele locale de autentificare” șterge doar:

- `faber_admin_email`
- `faber_admin_password`
- `faber_admin_auth`

Dacă browserul are doar email sau doar parolă locală, adminul afișează: „Datele locale par corupte. Resetează datele locale și configurează din nou accesul.”

## GitHub token

Tokenul GitHub se introduce în Setări GitHub și se salvează doar în browser:

- `localStorage.faber_github_owner`
- `localStorage.faber_github_repo`
- `localStorage.faber_github_branch`
- `localStorage.faber_github_token`

Tokenul trebuie să aibă permisiune de scriere pe repository. Nu se comite în repo.

## Administrare postări blog

Editorul de blog suportă:

- creare postare nouă;
- editare postare;
- salvare draft;
- publicare;
- filtrare după status;
- slug generat automat din titlu;
- validare slug unic;
- meta title, meta description, excerpt și conținut;
- keyword principal și keyworduri secundare;
- banner imagine, schimbare banner și eliminare banner;
- alt text obligatoriu când există banner;
- preview înainte de publicare;
- actualizare `blog.json`, pagina HTML statică și `sitemap.xml`.

Structura postării include: `id`, `title`, `slug`, `metaTitle`, `metaDescription`, `excerpt`, `content`, `status`, `primaryKeyword`, `secondaryKeywords`, `bannerImage`, `bannerAlt`, `author`, `createdAt`, `updatedAt`, `publishedAt`, `canonicalUrl`, `internalLinks`, `faq`.

## Banner postare

Imaginile încărcate din editor sunt salvate prin GitHub API în `/assets/blog/`. Numele fișierului este curățat: litere mici, fără spații, fără diacritice și fără caractere speciale.

Dacă bannerul este eliminat, câmpurile `bannerImage` și `bannerAlt` se golesc, iar articolul generat nu afișează imagine. Dacă bannerul este schimbat, articolul folosește doar noua referință.

## Sitemap

La publicarea unei postări, adminul regenerează `sitemap.xml` cu paginile publice și postările cu `status: published`. Drafturile nu sunt incluse.

## Teste manuale recomandate în browser curat/incognito

1. Deschide `/admin/`.
2. Încearcă login cu date greșite și verifică mesajul „Email sau parolă incorectă.”
3. Rulează resetarea datelor locale și verifică dacă sunt șterse doar cheile documentate.
4. Configurează GitHub owner/repo/branch/token și testează conexiunea.
5. Creează o postare draft și verifică `blog.json`.
6. Editează draftul, adaugă banner și alt text.
7. Deschide preview.
8. Publică postarea și verifică pagina HTML generată.
9. Schimbă bannerul și publică din nou.
10. Elimină bannerul și confirmă că pagina nu afișează imagine broken.
11. Verifică slug duplicat.
12. Confirmă că drafturile nu apar în sitemap.
