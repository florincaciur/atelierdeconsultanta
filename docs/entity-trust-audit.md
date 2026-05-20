# Audit entitate, contact si claims - FABER / Atelier de Consultanta

Data audit: 2026-05-20

## Rezumat

Auditul a verificat aparitiile publice pentru brand, domeniu, email, telefoane, adresa, social links si claims comerciale. Entitatea canonica folosita in schema este `FABER - Atelier de Consultanta`, iar forma de afisare pentru utilizatori poate ramane `FABER / Atelier de Consultanță`.

Datele de contact principale sunt consecvente dupa actualizare: `atelier.consultanta@gmail.com`, `+40769828338` si `+40753326229`. Datele juridice, social links si claims-urile numerice nu au dovada in proiect si trebuie validate de client.

## Harta valorilor gasite

| Valoare gasita | Fisier / zona | Este consecvent? | Necesita dovada? | Recomandare |
| --- | --- | --- | --- | --- |
| `FABER - Atelier de Consultanta` | `tools/schema-helpers.js`, schema Organization din paginile generate, `contact/index.html`, pagini programatice | Da, ca nume canonic in schema | Nu, dar trebuie confirmata forma juridica separata | Pastreaza ca nume canonic in schema si foloseste alternateName pentru variantele cu diacritice. |
| `FABER / Atelier de Consultanță` | `despre-faber/index.html`, homepage, texte de brand | Da, ca forma editoriala pentru utilizatori | Nu | Foloseste forma cu diacritice in continut si titluri. |
| `Atelier de Consultanta FABER` | schema Organization din pagini generate | Da, ca alternateName | Nu | Pastreaza ca denumire alternativa, dar nu o transforma in claim juridic. |
| `atelierdeconsultanta.ro` / `https://atelierdeconsultanta.ro` | `sitemap.xml`, `robots.txt`, `llms.txt`, canonical URLs, schema helpers | Da | Nu | Mentine URL-urile canonice fara `.html` si fara parametri. |
| `atelier.consultanta@gmail.com` | `tools/schema-helpers.js`, `contact/index.html`, `llms.txt`, articole, pagini legale dupa actualizare | Da | Nu, daca este emailul public aprobat | Foloseste aceasta adresa in schema, Contact, GDPR, confidentialitate si termeni. |
| `contact@atelierdeconsultanta.ro` | `gdpr.html`, `politica-de-confidentialitate.html`, `termeni-si-conditii.html` inainte de actualizare | Nu, era inconsistent cu schema si Contact | Da, daca trebuie pastrat ca alias oficial | A fost inlocuit cu `atelier.consultanta@gmail.com`. Daca exista alias de domeniu, clientul trebuie sa confirme. |
| `+40769828338` / `0769828338` | `tools/schema-helpers.js`, `contact/index.html`, `llms.txt`, homepage / linkuri tel sau WhatsApp | Da | Nu, daca numarul este aprobat pentru publicare | Pastreaza format E.164 in schema si format lizibil in continut. |
| `+40753326229` / `0753326229` | `tools/schema-helpers.js`, `contact/index.html`, `llms.txt`, homepage / linkuri tel sau WhatsApp | Da | Nu, daca numarul este aprobat pentru publicare | Pastreaza ca al doilea contactPoint, fara a-l marca drept linie garantata 24/7. |
| Adresa juridica | Nu exista valoare publica confirmata in proiect | Nu se poate evalua | Da | Completeaza doar dupa confirmare: `TODO_CLIENT_ADRESA`. Nu adauga adresa in Organization schema pana nu este validata. |
| CUI / date juridice | Nu exista valoare publica confirmata in proiect | Nu se poate evalua | Da | Completeaza dupa confirmare: `TODO_CLIENT_CUI`. |
| Reprezentant legal / persoana publica | Nu exista valoare publica confirmata in proiect | Nu se poate evalua | Da | Completeaza dupa confirmare: `TODO_CLIENT_REPREZENTANT`. Nu inventa Person schema. |
| LinkedIn | Nu exista link social confirmat in proiect | Nu se poate evalua | Da | Adauga in pagina Despre si `sameAs` doar dupa confirmare: `TODO_CLIENT_LINKEDIN`. |
| Google Business Profile | Nu exista link confirmat in proiect | Nu se poate evalua | Da | Adauga doar dupa confirmare: `TODO_CLIENT_GOOGLE_BUSINESS_PROFILE`. |
| `250+ proiecte` / `Proiecte declarate lucrate` | `index.html`, sectiunea Despre | Da, apare ca statistica declarata | Da | Pastreaza markerul `TODO_CLIENT_DOVADA_CLAIM` pana exista lista interna, portofoliu anonimizat sau aprobare client. |
| `45M€+` / `Valoare declarată în proiecte` | `index.html`, sectiunea Despre | Da, apare ca statistica declarata | Da | Clarifica daca reprezinta valoare totala proiecte, granturi aprobate sau alta baza de calcul. Marcheaza `TODO_CLIENT_DOVADA_CLAIM`. |
| `98%` / rata declarata | `index.html`, sectiunea Despre | Da, apare ca rata declarata, nu garantie | Da | Defineste metoda de calcul, perioada si esantionul. Marcheaza `TODO_CLIENT_DOVADA_CLAIM`. |
| `10 ani` / experienta declarata | `index.html`, sectiunea Despre | Da, apare ca experienta declarata | Da | Confirma intervalul si daca se refera la firma, echipa sau fondatori. Marcheaza `TODO_CLIENT_DOVADA_CLAIM`. |
| `specialistii FABER` / autor editorial | `blog.html`, `admin/index.html`, metadate articole | Partial: autorul este brandul, reviewerul este deseori `TODO_CLIENT_REVIEWER` | Da, pentru persoanele concrete | Pastreaza autorul ca organizatie pana exista autori/revieweri nominali aprobati. |
| Claim calitativ despre consultant si aprobare | `blog-afir-fotovoltaice-ferme-2026.html` | Era prea ferm | Da, daca ar fi ramas formularea initiala | Formularea a fost temperata: verificarea reduce riscuri, nu promite aprobare. |

## Modificari aplicate

- A fost creata pagina publica `/despre-faber/` cu continut de entitate, limite comerciale, contact, linkuri catre metodologie, studii de caz, surse oficiale si date lipsa marcate cu TODO.
- `tools/schema-helpers.js` a primit descriere de organizatie si alternateName extins: `FABER`, variante cu si fara diacritice si domeniul.
- Homepage-ul trimite acum catre `/despre-faber` din header, meniu mobil, footer si sectiunea de resurse utile.
- Claims-urile numerice din homepage folosesc markerul cerut `TODO_CLIENT_DOVADA_CLAIM`.
- Emailul din paginile legale a fost uniformizat la `atelier.consultanta@gmail.com`.
- Formularea prea ferma din articolul despre fotovoltaice AFIR a fost inlocuita cu o afirmatie prudenta despre reducerea riscurilor.
- `llms.txt`, generatorul de sitemap si build-ul Cloudflare includ pagina `/despre-faber`.

## Date necesare de la client

- `TODO_CLIENT_CUI`
- `TODO_CLIENT_ADRESA`
- `TODO_CLIENT_REPREZENTANT`
- `TODO_CLIENT_LINKEDIN`
- `TODO_CLIENT_GOOGLE_BUSINESS_PROFILE`
- `TODO_CLIENT_DOVADA_CLAIM` pentru `250+ proiecte`, `45M€+`, `98%` si `10 ani`.

## Recomandari urmatoare

1. Confirmarea datelor juridice inainte de adaugarea lor in Organization schema.
2. Confirmarea unui profil LinkedIn si Google Business Profile inainte de adaugarea `sameAs`.
3. Definirea metodologiei pentru claims: perioada, esantion, ce inseamna proiect lucrat, ce inseamna valoare proiect si cum este calculata rata declarata.
4. Inlocuirea `TODO_CLIENT_REVIEWER` cu o persoana sau rol editorial validat, daca brandul vrea E-E-A-T mai puternic.
