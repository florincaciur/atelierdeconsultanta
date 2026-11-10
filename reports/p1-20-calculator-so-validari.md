# P1.20 — Metodologia Calculatorului SO

Data reviziei: **10.11.2026**
Versiune metodă: **FABER-SO-1.1**
Versiune coeficienți: **SOC 2020 — lista AFIR noiembrie 2024**

## Sursa oficială

- pagină AFIR: https://www.afir.ro/info-la-zi/lista-detaliata-coeficienti-standard-output-soc-2020/
- document AFIR: https://www.afir.ro/api/file/document?filename=Lista+detaliata+a+Coeficientilor+standard+output+SOC+2020+nov+2024&filetype=pdf&url=%2Fmedia%2Fye3ppryg%2Flista-detaliata-a-coeficientilor-standard-output-soc-2020-nov-2024.pdf
- SHA-256 document: `4DBCA7CE226BFCD3E54BED11238664C81E443D54BC889E98F7C2602C2206DA06`
- definiție și metodă generală: Eurostat, sursele publicate în pagină

## Implementare

- 46 categorii SOC documentate prin cod, coeficient și unitate;
- formula existentă `coeficient × cantitate` și însumarea nu au fost schimbate;
- totalul este calculat cu zecimale și afișat prin `Math.round`;
- rezultatul oferă o sugestie prudentă de program, fără verdict automat de eligibilitate;
- rezultatul are explicație pe rând, copiere și tipărire fără PII;
- CTA transmite numai `source_page` și `so_result` numeric validat.

## Exemple acoperite de teste

- Fermă vegetală cu grâu și porumb: 12445.65 EUR, afișat 12446 EUR.
- Fermă de vaci pentru lapte: 11300.24 EUR, afișat 11300 EUR.
- Exploatație mixtă cu porumb și albine: 3666.15 EUR, afișat 3666 EUR.
- Exploatație cu pui de carne: 749.685 EUR, afișat 750 EUR.

## DE_VALIDAT_UMAN înaintea folosirii într-un dosar

- Specialistul agricol confirmă pentru fiecare proiect codul SOC corect, unitatea și corespondența cu evidențele APIA/ANSVSA/ANZ.
- Versiunea finală a Cererii de finanțare și tabelul SOC al apelului ales prevalează asupra acestui instrument orientativ.

Aceste puncte nu blochează publicarea metodologiei și a coeficienților oficiali, dar blochează folosirea rezultatului drept verdict de eligibilitate ori substitut pentru tabelul Cererii de finanțare.
