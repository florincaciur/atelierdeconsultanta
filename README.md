# FABER — Atelier de Consultanță

Site static pentru [atelierdeconsultanta.ro](https://atelierdeconsultanta.ro), gestionat prin GitHub Pages și un panou de administrare integrat.

---

## Administrarea caruselului de bannere

Caruselul de pe homepage este controlat exclusiv prin fișierul **`banners.json`** din rădăcina repository-ului. Nu mai există slide-uri hardcodate în `index.html`.

### Cum funcționează

La încărcarea paginii, `index.html` citește `banners.json`, filtrează bannerele cu `"active": true`, le sortează după câmpul `order` și le randează dinamic. Dacă niciun banner nu este activ, secțiunea de carusel este ascunsă complet (fără spațiu gol).

---

## Structura unui banner în `banners.json`

```json
{
  "id": "slide-por-adr",
  "tag": "Infrastructură regională",
  "title": "POR ADR Nord-Est\n2021–2027",
  "description": "Descriere scurtă a programului.",
  "amount": "Finanțare: până la 300.000 € per proiect",
  "ctaText": "Detalii program →",
  "ctaLink": "por-adr-nord-est.html",
  "image": "admin/banners/slide-por-adr.webp",
  "altText": "Banner program POR ADR Nord-Est",
  "icon": "ph-buildings",
  "order": 1,
  "active": true
}
```

| Câmp | Descriere |
|------|-----------|
| `id` | Identificator unic (slug fără spații) |
| `tag` | Eticheta de categorie afișată deasupra titlului |
| `title` | Titlul slide-ului; `\n` devine `<br>` în HTML |
| `description` | Textul descriptiv al programului |
| `amount` | Linia cu suma de finanțare (partea după `:` apare bold) |
| `ctaText` | Textul butonului de acțiune |
| `ctaLink` | URL-ul butonului (relativ sau absolut) |
| `image` | Calea către imaginea de fundal (goală = fără imagine) |
| `altText` | Text alternativ pentru accesibilitate |
| `icon` | Clasa icon Phosphor (ex: `ph-buildings`) |
| `order` | Numărul de ordine în carusel (1 = primul) |
| `active` | `true` = vizibil pe site, `false` = ascuns |

---

## Operațiuni din pagina de Admin

Accesează **`/admin/`** și navighează la secțiunea **🖼️ Bannere carusel**.

### Activează / dezactivează un banner

1. Găsește cardul bannerului dorit.
2. Apasă butonul **⏸️ Dezactivează** (sau **▶️ Activează** dacă e inactiv).
3. Badge-ul din colțul cardului se schimbă în **INACTIV** / **ACTIV**.
4. Apasă **🚀 Publică banners.json** pentru a trimite modificarea pe site.

> Bannerul dezactivat nu este șters — rămâne în `banners.json` cu `"active": false` și poate fi reactivat oricând.

### Modifică textele unui banner

1. Editează direct câmpurile din card: titlu, tag, descriere, sumă, text CTA, link CTA.
2. Apasă **🚀 Publică banners.json** când ești gata.

> Modificările se salvează în memorie în timp real. Nu există buton „Salvează" per card — toată publicarea se face o singură dată cu butonul global.

### Schimbă ordinea de afișare

1. Modifică câmpul **Ordine afișare** din fiecare card (număr întreg, 1 = primul).
2. Apasă **🚀 Publică banners.json**.

### Adaugă un banner nou

1. Apasă **+ Banner nou**.
2. Completează toate câmpurile din cardul nou apărut (titlu, descriere, CTA, imagine etc.).
3. Schimbă statusul în **Activ** cu butonul **▶️ Activează**.
4. Apasă **🚀 Publică banners.json**.

### Încarcă / schimbă imaginea unui banner

1. În secțiunea **Imagine banner** din card, apasă zona punctată pentru a alege un fișier local (WebP/JPG/PNG, recomandat 1200×630 px, sub 500 KB).
2. Imaginea este încărcată automat în GitHub la `admin/banners/<id>.webp`.
3. Apasă **🚀 Publică banners.json** pentru a activa imaginea pe site.

### Șterge / golește imaginea unui banner

1. Apasă **🗑️ Șterge imagine** din cardul respectiv.
2. Confirmă acțiunea în dialogul de confirmare.
3. Banner-ul va fi afișat fără imagine de fundal (cu gradientul implicit al slide-ului).
4. Apasă **🚀 Publică banners.json**.

### Șterge definitiv un banner

1. Apasă **❌ Șterge banner** din card.
2. Confirmă în dialogul de confirmare.
3. Apasă **🚀 Publică banners.json**.

> **Atenție:** ștergerea este definitivă în sesiunea curentă. Dacă vrei să recuperezi un banner șters, folosește **⬇️ Export JSON local** înainte de publicare sau accesează istoricul de commit-uri din GitHub.

### Export și import manual JSON

- **⬇️ Export JSON local** — descarcă `banners.json` cu starea curentă din memorie. Util pentru backup sau editare manuală.
- **🔄 Reîncarcă din GitHub** — înlocuiește starea din memorie cu versiunea publicată pe GitHub (anulează modificările nepublicate).

---

## Editare directă a `banners.json` (fără admin)

Poți edita fișierul direct în GitHub (sau local) respectând structura de mai sus, apoi dai commit și push pe branch-ul `main`. GitHub Pages republicată automat în 1–2 minute.

**Reguli de respectat:**
- `id` trebuie să fie unic pentru fiecare banner.
- `order` determină ordinea; valorile duplicat sunt permise (sortare stabilă).
- `active: false` ascunde bannerul fără a-l șterge.
- Câmpul `image` gol (`""`) face slide-ul să apară fără imagine, cu gradientul CSS implicit.

---

## Fallback dacă toate bannerele sunt inactive

Dacă `banners.json` nu conține niciun banner cu `"active": true` (sau fișierul lipsește / nu poate fi citit), secțiunea `#carousel-section` din homepage este ascunsă complet cu `display: none`. Nu rămâne spațiu gol sau layout spart.

---

## Fișiere relevante

| Fișier | Rol |
|--------|-----|
| `banners.json` | Sursa de adevăr pentru toate bannerele caruselului |
| `index.html` | Homepage — citește și randează `banners.json` la runtime |
| `admin/index.html` | Panoul de administrare |
| `admin/banners/` | Directorul unde sunt stocate imaginile de banner |
