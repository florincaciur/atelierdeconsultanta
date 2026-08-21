# Informații care necesită confirmare FABER

Data baseline: **21 august 2026**.

Acest fișier conține numai informații interne sau aprobări care nu pot fi deduse sigur din repository. Niciuna nu blochează documentarea Task 00. Numele proiectului Cloudflare, branch-ul de producție și verificarea deploymentului au putut fi deduse: proiect/worker `atelierdeconsultanta`, producție din `main`, verificare prin `/release.json` și workflowul `production-live-verification.yml`.

## 1. Politica efectivă de consimțământ pentru Microsoft Clarity

**Stare observată:** `assets/analytics-events.js` încarcă Microsoft Clarity automat după load/idle sau prima interacțiune. Nu există în repository un CMP, un banner de cookies ori un apel de consent care să condiționeze încărcarea. Politica publică spune că analytics neesențial necesită consimțământ acolo unde legea aplicabilă îl cere și indică un banner de cookies.

**Confirmare necesară:** juristul/ownerul trebuie să confirme care comportament este aprobat pentru vizitatorii site-ului: Clarity numai după opt-in, altă configurație de consent mode sau un temei documentat care schimbă textul public. Este necesară și confirmarea dacă există un CMP injectat exclusiv din Cloudflare/dashboard, invizibil în repository.

**De ce este necesară:** fără această informație, o remediere ar putea fie să blocheze analytics legitim, fie să păstreze o neconcordanță legală/publică.

## 2. Profiluri reale ale echipei

**Stare observată:** `config/about-faber-governance.json#pendingValidations/team_profiles` este blocat.

**Confirmare necesară pentru fiecare profil publicabil:** fotografie reală și drept de utilizare, nume, rol, specializări, experiență verificabilă, LinkedIn oficial dacă există, acord pentru publicare și paginile de autor atribuite.

**De ce este necesară:** aceste date nu pot fi inventate sau deduse din cod; în lipsa lor, profilurile rămân private.

## 3. Studii de caz și rezultate FABER

**Stare observată:** `case_studies_and_results` este blocat în guvernanța About.

**Confirmare necesară:** documente justificative, metoda de calcul și perioada pentru orice rezultat, acordul beneficiarului, regula de anonimizare și aprobarea formulării publice.

**De ce este necesară:** fără probe nu pot fi publicate cifre, rezultate, testimoniale sau claims despre experiența FABER.

## 4. Afilieri și referințe AFIR

**Stare observată:** `afir_nomenclature_listing` și `other_affiliations` sunt blocate.

**Confirmare necesară:** pentru mențiunea AFIR — URL oficial, document, versiune, data verificării, potrivirea exactă a entității juridice și formularea aprobată; pentru alte afilieri — document oficial, perioadă de valabilitate, entitatea afiliată și acordul de publicare.

**De ce este necesară:** repository-ul interzice explicit claims de acreditare/afiliere fără dovezi.

## 5. Activarea CRM și a evenimentului `qualified_lead`

**Stare observată:** `config/contact-triage.json` declară `crmDetectedInRepository=false` și `qualifiedLeadActivation=DE_VALIDAT_UMAN`. Endpointul tehnic există, dar activarea și destinația operațională nu sunt confirmate în repo.

**Confirmare necesară:** CRM-ul/adaptorul ales, ownerul operațional, destinația HTTPS, metoda de autentificare prin secret Cloudflare și câmpurile aprobate pentru evenimentul server-side fără PII.

**De ce este necesară:** activarea fără destinație și ownership confirmate poate pierde lead-uri sau expune date.

## 6. Dovada QA manuală cu screen reader

**Stare observată:** contractele responsive automate trec, dar `config/responsive-accessibility.json#manualScreenReader.publicationState` este `DE_VALIDAT_UMAN`.

**Confirmare necesară:** persoana care execută verificarea, data, combinația NVDA + browser și rezultatul pe cele șapte rute declarate, inclusiv formular, meniu, carusel și calculator.

**De ce este necesară:** această probă nu poate fi înlocuită de un contract DOM sau de o presupunere automată.

## Informații care nu mai lipsesc

- Branch de producție: `main`.
- Proiect/worker cu active: `atelierdeconsultanta`.
- Worker domeniu: `atelierdeconsultanta-domain-seo`.
- Verificare deployment disponibilă din mediu: `https://atelierdeconsultanta.ro/release.json` trebuie să conțină SHA-ul exact; rutele afectate se verifică apoi live.
- Identitatea juridică și canalele publice: registry-ul `config/legal-identity.json` este aprobat; orice neconcordanță de materializare trebuie tratată ca defect de sync, nu completată cu valori noi.
