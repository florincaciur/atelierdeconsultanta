# CHANGELOG

## 2026-04-30

- Auditat fișierele HTML, `robots.txt`, `sitemap.xml`, `blog.html`, `blog.json` și `/admin/index.html`.
- Confirmat că folderul curent nu este repository Git și că `rg.exe` nu poate fi rulat din cauza „Access is denied”.
- Reparat linkurile interne către homepage din paginile legale: `index.html` a fost înlocuit cu `/`.
- Curățat `robots.txt`: site public permis, `/admin/` blocat intenționat, sitemap declarat.
- Scurtat meta descriptions și title-uri prea lungi.
- Transformat `blog.html` într-un hub crawlable fără dependență exclusivă de JavaScript și adăugat carduri statice către articole.
- Creat stylesheet comun pentru articole: `assets/blog/article.css`.
- Finalizat 8 articole statice, fiecare cu peste 1.200 de cuvinte, canonical, H1 unic, FAQ și schema `BlogPosting`.
- Adăugat pagini suport pentru linkuri interne și SEO: `/consultanta-fonduri-europene/`, `/fonduri-europene-nerambursabile-2026/`, `/digitalizare-imm-pnrr/`, `/fondul-de-modernizare/`, `/contact/`.
- Actualizat `blog.json` cu schema completă de postări și status `draft/published`.
- Actualizat `sitemap.xml` cu paginile publice și cele 8 articole, fără `/admin/` și fără `/index.html`.
- Reparat buguri JavaScript vechi din admin în zona de bannere, unde ghilimelele din `confirm()` rupeau scriptul.
- Consolidat loginul admin cu chei locale documentate, detectare date corupte și reset limitat la datele relevante.
- Extins workflow-ul admin pentru postări: draft, publicare HTML static, sitemap, SEO fields, preview, banner upload în `/assets/blog/`, eliminare banner și validări.
