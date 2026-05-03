# ADMIN_WORKFLOW

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
