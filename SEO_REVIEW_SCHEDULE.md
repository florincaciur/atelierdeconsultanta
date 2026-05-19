# Calendar revizuire SEO si AI Search

## La fiecare 3 luni

- Revizuieste paginile de program: DR12, DR14, Start-Up Nation, Femeia Antreprenor, Digitalizare IMM, Fondul de Modernizare si microintreprinderi.
- Verifica daca s-au schimbat sume, procente, criterii, termene, grile de punctaj sau documente obligatorii.
- Actualizeaza FAQPage si blocurile speakable daca intrebarile frecvente se schimba.
- Ruleaza `node tools/audit-content-depth.js --min-words 2000` si `npm run verify:seo`.

## La fiecare 6 luni

- Revizuieste hub-urile: fonduri europene, IMM, agricultura, digitalizare, PNRR, AFIR, ghiduri, resurse si instrumente.
- Verifica linkurile interne, sitemap.xml, llms.txt si robots.txt.
- Actualizeaza paginile programatice CAEN/local/FAQ pe baza interogarilor din Search Console.

## Dupa fiecare ghid nou

- Ruleaza `node tools/extract-source-facts.js`.
- Actualizeaza `config/seo-programs.json` fara a copia nume de fisiere sau sourceRef in continut public.
- Regeneraza paginile si lead magneturile relevante.
