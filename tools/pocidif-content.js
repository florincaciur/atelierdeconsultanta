"use strict";

const { renderOfficialSources } = require("./official-sources");

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function faqHtml(page) {
  return (page.faq || [])
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");
}

function sourcesHtml(page) {
  return renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
}

function renderPocidifMain(page) {
  return `
      <section aria-labelledby="pocidif-raspuns-rapid">
        <h2 id="pocidif-raspuns-rapid">Răspuns rapid</h2>
        <p class="intro">${esc(page.quickAnswer)}</p>
        <p class="source-note"><strong>Status document:</strong> această pagină folosește ghidul aprobat prin Ordinul MIPE nr. 965/23.06.2026, schema de ajutor aprobată prin Ordinul MIPE nr. 875/15.06.2026, cele 19 anexe și clarificările oficiale publicate la 9 iulie 2026. <strong>Ultima verificare:</strong> <time datetime="2026-07-13">13 iulie 2026</time>.</p>
      </section>

      <section aria-labelledby="pocidif-denumire">
        <h2 id="pocidif-denumire">Denumirea completă a programului</h2>
        <p>PoCIDIF este <strong>Programul Creștere Inteligentă, Digitalizare și Instrumente Financiare 2021–2027</strong>. Pagina tratează apelul nr. 1 din Acțiunea 2.1 – „Dezvoltarea de noi servicii/aplicații/produse prin inovare și adoptarea de tehnologii avansate”, Prioritatea 2 – Digitalizare în administrația publică centrală și mediul de afaceri, obiectivul specific RSO1.1 privind dezvoltarea capacităților de cercetare și inovare și adoptarea tehnologiilor avansate.</p>
        <p>Acțiunea este finanțată din Fondul European pentru Dezvoltare Regională. Denumirea lungă contează: apelul nu este o schemă generală pentru digitalizarea internă a unei firme, ci o intervenție pentru IMM-uri TIC care creează un rezultat inovator destinat pieței.</p>
      </section>

      <section aria-labelledby="pocidif-obiectiv">
        <h2 id="pocidif-obiectiv">Obiectivul apelului</h2>
        <p>Obiectivul este dezvoltarea și introducerea pe piață a unor servicii, aplicații sau produse noi ori îmbunătățite semnificativ, obținute prin cercetare, dezvoltare și inovare și bazate pe tehnologii avansate. Rezultatul trebuie să se înscrie într-un subdomeniu de specializare inteligentă indicat de ghid: dispozitive și sisteme microelectronice, rețelele viitorului și comunicații, IoT, tehnologii XR, inteligență artificială, tehnologii pentru trasabilitate sau roboți și agenți cognitivi.</p>
        <p>Produsul trebuie introdus pe piață, nu doar prototipat. Ghidul exclude proiectele care conțin numai achiziții de active sau numai cercetare și dezvoltare fără inovare de produs și fără activități de introducere pe piață.</p>
      </section>

      <section aria-labelledby="pocidif-solicitanti">
        <h2 id="pocidif-solicitanti">Cine poate aplica</h2>
        <p>Solicitanții eligibili sunt întreprinderi din sectorul TIC care desfășoară activitate în România și se încadrează ca microîntreprinderi, întreprinderi mici sau întreprinderi mijlocii. Sunt acceptate societăți constituite în baza Legii nr. 31/1990, societăți cooperative constituite în baza Legii nr. 1/2005 și societăți care funcționează în baza OUG nr. 6/2011, dacă îndeplinesc toate condițiile ghidului.</p>
        <p>Ghidul include și întreprinderi nou-înființate din TIC. Pentru ajutorul dedicat întreprinderilor nou-înființate, beneficiarii sunt microîntreprinderi sau întreprinderi mici, iar întreprinderile nou-înființate inovatoare trebuie să îndeplinească definiția și dovezile specifice. Un solicitant și grupul său pot beneficia în cadrul apelului pentru un singur proiect.</p>
      </section>

      <section aria-labelledby="pocidif-caen">
        <h2 id="pocidif-caen">Coduri CAEN</h2>
        <p>Ghidul aprobat enumeră nouă coduri CAEN obligatorii pentru lider și, după caz, parteneri:</p>
        <ul>
          <li><strong>2611</strong> – Fabricarea altor componente electronice;</li>
          <li><strong>2612</strong> – Fabricarea subansamblurilor electronice (module);</li>
          <li><strong>2630</strong> – Fabricarea echipamentelor de comunicații;</li>
          <li><strong>5821</strong> – Activități de editare a jocurilor de calculator;</li>
          <li><strong>5829</strong> – Activități de editare a altor produse software;</li>
          <li><strong>6210</strong> – Activități de realizare a software-ului la comandă;</li>
          <li><strong>6220</strong> – Consultanță în tehnologia informației și managementul mijloacelor de calcul;</li>
          <li><strong>6290</strong> – Alte activități de servicii privind tehnologia informației;</li>
          <li><strong>6310</strong> – Prelucrarea datelor, administrarea paginilor web și activități conexe.</li>
        </ul>
        <p>Codul pentru care se solicită finanțarea trebuie autorizat în condițiile ghidului. La contractare, toate locațiile de implementare declarate trebuie să aibă autorizat codul sau codurile finanțate; lipsa autorizării conduce la respingere fără clarificări suplimentare.</p>
      </section>

      <section aria-labelledby="pocidif-tip-intreprindere">
        <h2 id="pocidif-tip-intreprindere">Tipul întreprinderii</h2>
        <p>Dimensiunea întreprinderii influențează eligibilitatea anumitor ajutoare și intensitatea finanțării. Statutul de microîntreprindere, întreprindere mică sau mijlocie se verifică atât la depunere, cât și la contractare, prin întreprinderile legate și partenere. Întreprinderile mari nu sunt eligibile.</p>
        <p>Solicitantul trebuie să aibă profit din exploatare pozitiv în ultimul exercițiu financiar încheiat; excepția este IMM-ul înființat în anul depunerii, fără situații financiare încheiate. Se verifică lipsa datoriilor fiscale nete, lipsa stării de insolvență sau dificultate și capacitatea de a acoperi contribuția proprie, costurile neeligibile și funcționarea investiției.</p>
      </section>

      <section aria-labelledby="pocidif-activitati">
        <h2 id="pocidif-activitati">Activități eligibile</h2>
        <p>Structura obligatorie combină cercetarea industrială și/sau dezvoltarea experimentală, introducerea în producție a rezultatului, introducerea pe piață, informarea și publicitatea și auditarea tehnică. Pot fi incluse și pregătirea documentației, raportul expertului ori auditorului pentru întreprinderile nou-înființate inovatoare, managementul, accesibilizarea și alte activități permise.</p>
        <p>Activitatea de bază este cercetarea, dezvoltarea și inovarea produsului, aplicației sau serviciului TIC. Finanțarea nerambursabilă alocată activității de bază trebuie să reprezinte minimum 80% din finanțarea totală. Beneficiarul poate contracta servicii specializate, dar nu poate externaliza integral activitățile tehnice.</p>
      </section>

      <section aria-labelledby="pocidif-cdi-produs">
        <h2 id="pocidif-cdi-produs">Cercetare, inovare și produs digital</h2>
        <p>Cercetarea industrială urmărește cunoștințe și competențe noi pentru produse sau servicii noi ori îmbunătățite semnificativ. Dezvoltarea experimentală folosește cunoștințele existente pentru prototipare, demonstrare, pilotare, testare și validare în condiții reprezentative. Modificările de rutină ale unui produs existent nu sunt dezvoltare experimentală.</p>
        <p>Inovarea trebuie demonstrată în cererea de finanțare și planul de afaceri. Rezultatul este un produs, serviciu sau o aplicație complet nouă ori semnificativ îmbunătățită, diferită de oferta anterioară și de soluțiile existente pe piață. Cel puțin un rezultat inovator trebuie comercializat, iar dovezile nu pot fi simple facturi proforme sau acorduri fără vânzare.</p>
      </section>

      <section aria-labelledby="pocidif-hardware-software">
        <h2 id="pocidif-hardware-software">Hardware, software și servicii</h2>
        <p>Pentru introducerea în producție pot fi eligibile active corporale și necorporale: hardware TIC, echipamente de calcul și testare, dispozitive IoT, echipamente pentru AI, edge, AR/VR, procesare de date, sisteme autonome ori securitate, precum și aplicații software, licențe, platforme cloud și infrastructuri bazate pe tehnologii avansate. Fiecare activ trebuie justificat prin arhitectură, activitate și rezultat.</p>
        <p>Pentru cercetare și dezvoltare sunt eligibile, în condițiile ghidului, costuri de personal, instrumente și echipamente în măsura și pe durata utilizării în proiect, cercetare contractuală, cunoștințe, brevete și servicii de consultanță ori echivalente. Abonamentele SaaS, PaaS, XaaS, resursele cloud, API-urile și modelele AI pot fi bugetate numai când sunt folosite pentru activitățile proiectului și încadrate în categoria corectă.</p>
      </section>

      <section aria-labelledby="pocidif-proprietate-intelectuala">
        <h2 id="pocidif-proprietate-intelectuala">Proprietate intelectuală</h2>
        <p>Dosarul trebuie să explice drepturile asupra codului, componentelor, datelor, licențelor, brevetelor și rezultatelor obținute. Activele necorporale finanțate trebuie utilizate exclusiv în unitatea beneficiară, să fie amortizabile, achiziționate în condițiile pieței de la terți fără legături și păstrate în activele întreprinderii cel puțin trei ani.</p>
        <p>Ghidul permite prin ajutor de minimis costuri pentru certificarea, obținerea, validarea și protejarea brevetelor și a altor active necorporale. Pentru anumite intensități ale ajutorului CDI, diseminarea rezultatelor sau acordarea de licențe neexclusive și nediscriminatorii poate avea relevanță; opțiunea trebuie corelată cu schema și cu strategia de valorificare.</p>
      </section>

      <section aria-labelledby="pocidif-indicatori">
        <h2 id="pocidif-indicatori">Indicatori</h2>
        <p>Indicatorii sunt de realizare, rezultat și etapă. Proiectul trebuie să obțină cel puțin un produs, serviciu sau o aplicație inovatoare folosind tehnologii avansate. RCO01 și RCO02 urmăresc întreprinderile sprijinite, iar RCR03 urmărește IMM-urile care introduc inovare de produs.</p>
        <p>Indicatorii suplimentari cer minimum un rezultat inovator, minimum trei dovezi de comercializare și o performanță a investiției mai mare de 0,5, calculată prin raportarea veniturilor generate la costurile de dezvoltare și exploatare. Cel puțin o dovadă de introducere pe piață trebuie prezentată cel târziu la un an după finalizarea implementării; nerealizarea condiției poate conduce la recuperarea integrală a finanțării.</p>
      </section>

      <section aria-labelledby="pocidif-parteneriate">
        <h2 id="pocidif-parteneriate">Parteneriate</h2>
        <p>Proiectele în parteneriat sunt permise. Liderul și partenerii trebuie să fie microîntreprinderi, întreprinderi mici sau mijlocii din TIC, cu activitate în România și coduri CAEN eligibile. Întreprinderile nou-înființate nu sunt eligibile ca parteneri, dar pot avea rol de lider dacă îndeplinesc condițiile specifice.</p>
        <p>Fiecare partener poate participa la maximum un proiect, regulă aplicată și firmelor sale legate și partenere. Acordul din Anexa 16 trebuie să descrie rolurile, activitățile și bugetele și să rămână în vigoare inclusiv pe durata celor 36 de luni de post-implementare. Liderul nu poate fi înlocuit.</p>
      </section>

      <section aria-labelledby="pocidif-documente">
        <h2 id="pocidif-documente">Documente</h2>
        <p>La depunere sunt cerute cererea de finanțare, declarația unică, hotărârea AGA/CA sau decizia asociatului unic, planul de afaceri, planul de monitorizare, declarația TVA, bugetul defalcat, minimum două oferte pentru cheltuielile eligibile, centralizatorul ofertelor, documentele echipei, declarațiile privind conflictul de interese, statutul IMM și cumulul ajutoarelor, situațiile financiare pentru ultimii doi ani și documentele explicative necesare.</p>
        <p>Pentru întreprinderea nou-înființată inovatoare se adaugă raportul expertului extern, raportul auditorului sau celelalte dovezi acceptate. Pentru parteneriat este obligatoriu acordul din Anexa 16. La contractare se recertifică situația juridică, fiscală, financiară, CAEN, locația și contribuția proprie.</p>
      </section>

      <section aria-labelledby="pocidif-buget">
        <h2 id="pocidif-buget">Buget și cofinanțare</h2>
        <p>Valoarea minimă nerambursabilă este <strong>200.000 euro</strong>. Maximul este <strong>1.500.000 euro</strong> pentru un serviciu sau o aplicație software inovatoare și <strong>3.000.000 euro</strong> pentru un produs hardware inovator. Pentru hardware, suma care depășește 1.500.000 euro trebuie justificată prin finanțarea liniei de producție, iar producția trebuie realizată de lider sau partener.</p>
        <p>Cofinanțarea nu are o singură rată. Bugetul combină, după caz, ajutor regional, ajutor pentru cercetare industrială și dezvoltare experimentală, ajutor pentru întreprinderi nou-înființate și ajutor de minimis. Intensitatea se determină pentru fiecare categorie după dimensiunea firmei, regiune și condițiile schemei. Beneficiarul dovedește la contractare contribuția proprie, exclusiv TVA, prin extras de cont sau linie ori contract de credit.</p>
      </section>

      <section aria-labelledby="pocidif-punctaj">
        <h2 id="pocidif-punctaj">Punctaj</h2>
        <p>Pragul de calitate este <strong>70 de puncte</strong>, iar pragul de excelență este <strong>92 de puncte</strong>. Grila evaluează relevanța și maturitatea, noutatea rezultatului, sectoarele vizate, maturitatea comercială și Product-Market Fit, calitatea și fezabilitatea proiectului, echipa, sustenabilitatea și potențialul de extindere. Acolo unde grila definește opțiuni fixe, nu se acordă punctaje intermediare.</p>
        <p>Lipsa caracterului inovator sau o soluție tehnologic depășită poate aduce zero la subcriteriul critic și respingerea. Este obligatorie o echipă cu un coordonator tehnic și cel puțin doi experți tehnici. La egalitate se compară mai întâi secțiunea Relevanță și maturitate, apoi Calitatea proiectului, iar ulterior ordinea depunerii.</p>
      </section>

      <section aria-labelledby="pocidif-greseli">
        <h2 id="pocidif-greseli">Greșeli</h2>
        <ul class="warning-list">
          <li>proiectul este o achiziție IT sau un website, fără cercetare, inovare și rezultat comercializabil;</li>
          <li>codul CAEN nu este dintre cele nouă coduri ori nu este autorizat la locația de implementare;</li>
          <li>firma sau grupul depune mai multe proiecte ori solicită finanțare pentru o investiție deja finanțată;</li>
          <li>activitățile tehnice sunt externalizate integral și echipa proprie nu atinge pragul cerut;</li>
          <li>bugetul nu separă tipurile de ajutor, nu are două oferte sau include costuri fără legătură tehnică;</li>
          <li>planul de afaceri nu demonstrează piața, diferențierea, comercializarea și veniturile;</li>
          <li>drepturile asupra codului, datelor, licențelor și rezultatelor nu sunt clarificate;</li>
          <li>indicatorii sunt supraestimați sau nu pot fi dovediți prin livrabile și tranzacții reale;</li>
          <li>cheltuielile încep înainte de momentul permis de schema de ajutor aplicabilă.</li>
        </ul>
      </section>

      <section aria-labelledby="pocidif-faq">
        <h2 id="pocidif-faq">FAQ</h2>
        ${faqHtml(page)}
      </section>

${sourcesHtml(page)}

      <section aria-labelledby="pocidif-cta">
        <h2 id="pocidif-cta">CTA: verifică proiectul PoCIDIF 2.1</h2>
        <p>Trimite certificatul constatator, structura de grup, situațiile financiare, locația, descrierea produsului, subdomeniul tehnologic, arhitectura, echipa, planul de cercetare și dezvoltare, bugetul, ofertele, indicatorii și strategia de comercializare. Verificarea urmărește separat eligibilitatea firmei, activitățile, tipurile de ajutor și punctajul documentabil.</p>
        <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea eligibilității PoCIDIF 2.1</a></p>
      </section>`;
}

function renderPocidifEligibility(page) {
  return `
      <p class="intro">${esc(page.quickAnswer)}</p>
      <p class="source-note"><strong>Baza verificării:</strong> ghidul aprobat prin Ordinul MIPE nr. 965/23.06.2026, schema de ajutor, anexele și clarificările oficiale din 9 iulie 2026. Pagina principală rămâne <a href="/pocidif-21">PoCIDIF 2.1</a>.</p>
      <section><h2>Solicitanții eligibili</h2><p>Pot aplica microîntreprinderi, întreprinderi mici și întreprinderi mijlocii din sectorul TIC, cu activitate în România. Forma juridică trebuie să fie una dintre cele permise de ghid: societate constituită potrivit Legii nr. 31/1990, societate cooperativă potrivit Legii nr. 1/2005 sau societate care funcționează în baza OUG nr. 6/2011. Calitatea de întreprindere se probează prin certificatul constatator verificat de OIPSI.</p><p>Încadrarea IMM se menține la depunere și la semnarea contractului. Calculul include întreprinderile partenere și legate; o firmă care este aparent IMM individual poate depăși pragurile după consolidarea datelor grupului.</p></section>
      <section><h2>Întreprinderi nou-înființate și inovatoare</h2><p>Întreprinderile nou-înființate din TIC sunt eligibile în condițiile ajutorului dedicat, dar trebuie să fie microîntreprinderi sau întreprinderi mici. Pentru categoria nou-înființată inovatoare, firma necotată trebuie să fie înregistrată de maximum cinci ani și să respecte condițiile privind preluarea activității, distribuirea profiturilor și fuziunile.</p><p>Caracterul inovator se demonstrează prin una dintre dovezile acceptate: evaluarea unui expert extern, raportul auditorului sau situațiile financiare privind cheltuielile de cercetare-dezvoltare ori documentele corespunzătoare celorlalte situații din definiția ghidului. Expertul extern are cerințe proprii de experiență și publicații sau certificări.</p></section>
      <section><h2>Codurile CAEN acceptate</h2><table><thead><tr><th>CAEN</th><th>Activitate</th></tr></thead><tbody><tr><td>2611</td><td>Fabricarea altor componente electronice</td></tr><tr><td>2612</td><td>Fabricarea subansamblurilor electronice</td></tr><tr><td>2630</td><td>Fabricarea echipamentelor de comunicații</td></tr><tr><td>5821</td><td>Editarea jocurilor de calculator</td></tr><tr><td>5829</td><td>Editarea altor produse software</td></tr><tr><td>6210</td><td>Realizarea software-ului la comandă</td></tr><tr><td>6220</td><td>Consultanță IT și managementul mijloacelor de calcul</td></tr><tr><td>6290</td><td>Alte servicii privind tehnologia informației</td></tr><tr><td>6310</td><td>Prelucrarea datelor, administrarea paginilor web și activități conexe</td></tr></tbody></table><p>Codul folosit pentru finanțare trebuie să fie autorizat. La contractare, toate locațiile de implementare declarate trebuie să aibă autorizate codurile finanțate; ghidul precizează că neîndeplinirea condiției conduce la respingere fără solicitarea de clarificări.</p></section>
      <section><h2>Condiții financiare și fiscale</h2><p>Solicitantul trebuie să aibă profit din exploatare pozitiv în ultimul exercițiu financiar încheiat, chiar dacă rezultatul net a fost negativ. Excepția este IMM-ul înființat în anul depunerii, fără situații financiare încheiate. Firma nu trebuie să aibă obligații fiscale nete restante, fapte relevante în cazierul fiscal, proceduri de insolvență ori lichidare sau ordine de recuperare neexecutate.</p><p>Întreprinderea nu poate fi în dificultate în sensul Regulamentului (UE) nr. 651/2014. Separat, trebuie să aibă capacitatea financiară de a plăti contribuția proprie, costurile neeligibile și funcționarea proiectului. Cofinanțarea eligibilă, fără TVA, se dovedește la contractare prin extras de cont sau linie ori contract de credit.</p></section>
      <section><h2>Locația și activitatea proiectului</h2><p>Solicitantul dovedește dreptul de folosință asupra spațiului prin proprietate, închiriere, concesiune, superficie sau comodat pentru implementare și durabilitate. Contractele nu trebuie să confere proprietarului drepturi asupra bunurilor cumpărate prin proiect. Modificarea locației este permisă doar în interiorul aceleiași regiuni NUTS 2, în condițiile ghidului.</p><p>Proiectul trebuie să dezvolte un produs, o aplicație sau un serviciu inovator într-unul dintre subdomeniile tehnologice eligibile. O firmă cu CAEN acceptat nu devine automat eligibilă dacă proiectul este doar o dotare internă ori o aplicație fără inovare și introducere pe piață.</p></section>
      <section><h2>Parteneriatele</h2><p>Parteneriatul poate reuni microîntreprinderi, întreprinderi mici și mijlocii TIC. Partenerul trebuie să îndeplinească aceleași condiții relevante de eligibilitate și să aibă rol, activități și buget propriu. Întreprinderea nou-înființată nu poate fi partener, însă poate fi lider dacă îndeplinește condițiile categoriei sale.</p><p>Un partener se poate angaja în maximum un proiect, inclusiv prin firmele sale legate și partenere. Acordul de parteneriat din Anexa 16 trebuie corelat cu bugetul și menținut pe perioada de implementare și cele 36 de luni de post-implementare. Liderul nu poate fi retras sau înlocuit.</p></section>
      <section><h2>Limita de un proiect și finanțările anterioare</h2><p>Un solicitant poate beneficia doar într-un singur proiect, iar limita se aplică grupului de firme. Dacă aceeași entitate înscrie proiectul de mai multe ori, numai ultima transmitere intră în evaluare. Solicitantul nu poate cere din nou finanțare pentru același obiectiv sau aceeași investiție finanțată din fonduri publice.</p><p>Ghidul exclude și solicitanții care au primit finanțare în Acțiunea 1.1 PoCIDIF, programe regionale, PNRR sau Programul Sănătate pentru dezvoltarea de servicii, aplicații ori produse. Verificarea istoricului trebuie făcută la nivelul proiectului și al rezultatului finanțat, nu numai după titlul apelului anterior.</p></section>
      <section><h2>Sectoare și situații excluse</h2><p>Lista anexată exclude activități din pescuit și acvacultură, producție agricolă primară, anumite activități agricole, siderurgie, lignit și cărbune, transport și infrastructură conexă, energie, comunicații în bandă largă și alte domenii prevăzute de regulile ajutorului. Sunt excluse și jocurile de noroc, industria tutunului, activitățile cu conținut obscen, anumite activități financiare și imobiliare și activități legate de combustibili fosili.</p><p>O întreprindere cu activități eligibile și neeligibile poate primi sprijin numai dacă evidența contabilă separă activitățile și finanțarea nu ajunge la sectorul exclus.</p></section>
      <section><h2>Checklist înainte de depunere</h2><ul><li>calculează statutul IMM împreună cu firmele legate și partenere;</li><li>verifică forma juridică și certificatul constatator;</li><li>confirmă autorizarea CAEN la fiecare locație;</li><li>verifică profitul din exploatare, datoriile, cazierul fiscal și starea de dificultate;</li><li>documentează dreptul asupra spațiului și regiunea proiectului;</li><li>inventariază ajutoarele și proiectele similare primite;</li><li>stabilește dacă depunerea este individuală sau în parteneriat;</li><li>dovedește contribuția proprie și costurile neeligibile;</li><li>leagă solicitantul eligibil de un produs inovator, nu doar de un CAEN TIC.</li></ul></section>
      <section><h2>Întrebări frecvente</h2>${faqHtml(page)}</section>
${sourcesHtml(page)}
      <section><h2>Verifică eligibilitatea PoCIDIF 2.1</h2><p>Trimite certificatul constatator, structura de grup, situațiile financiare, codurile CAEN, locația, ajutoarele primite și rolurile partenerilor. <a href="/verificare-eligibilitate-fonduri-europene">Solicită verificarea documentată</a> înainte de pregătirea bugetului.</p></section>`;
}

function renderPocidifExpenses(page) {
  return `
      <p class="intro">${esc(page.quickAnswer)}</p>
      <p class="source-note"><strong>Baza verificării:</strong> ghidul aprobat și anexele Acțiunii 2.1, schema de ajutor și clarificările MIPE publicate după aprobare. Pentru condițiile generale vezi <a href="/pocidif-21">pagina principală PoCIDIF 2.1</a>.</p>
      <section><h2>Bugetul pornește de la activități</h2><p>O cheltuială nu devine eligibilă doar pentru că apare într-o categorie din ghid. Ea trebuie să fie legată de o activitate eligibilă, necesară rezultatului inovator, rezonabilă, justificată și încadrată în tipul corect de ajutor. Bugetul trebuie citit împreună cu arhitectura tehnică, etapele de dezvoltare, planul de afaceri și indicatorii.</p><p>Apelul cere o succesiune completă: cercetare industrială și/sau dezvoltare experimentală, introducere în producție, introducere obligatorie pe piață, informare și publicitate și audit tehnic. Un proiect format exclusiv din active corporale și necorporale ori exclusiv din cercetare fără inovare și piață nu este finanțabil.</p></section>
      <section><h2>Cercetare industrială și dezvoltare experimentală</h2><p>În cercetarea industrială pot intra activități planificate pentru dobândirea de cunoștințe și competențe noi, inclusiv componente, prototipuri de laborator și linii-pilot necesare validării tehnologiilor. Dezvoltarea experimentală poate acoperi proiectarea, prototiparea, demonstrarea, pilotarea, testarea și validarea produsului în medii reprezentative.</p><p>Modificările de rutină sau periodice nu sunt dezvoltare experimentală. Planul tehnic trebuie să arate incertitudinea rezolvată, ipotezele testate, livrabilele, criteriile de acceptanță și legătura fiecărei etape cu produsul, aplicația sau serviciul final.</p></section>
      <section><h2>Introducerea în producție și pe piață</h2><p>Rezultatele CDI trebuie introduse în producție prin ajutor regional sau ajutor pentru întreprinderi nou-înființate, după caz. Dacă solicitantul nu poate folosi aceste tipuri de ajutor, activitatea de introducere în producție se suportă din fonduri proprii. Introducerea pe piață este obligatorie și este susținută prin ajutor de minimis.</p><p>Activitățile comerciale pot include promovarea, listarea pe marketplace, instrumente de analiză pentru go-to-market, participarea la evenimente și diseminarea rezultatelor. Ele nu pot înlocui produsul tehnic și nici dovezile reale de comercializare asumate prin indicatori.</p></section>
      <section><h2>Hardware TIC și echipamente</h2><p>În cadrul investiției inițiale pot fi eligibile hardware TIC și echipamentele aferente, inclusiv instalarea, configurarea și punerea în funcțiune. Ghidul oferă exemple precum servere și GPU pentru calcul de înaltă performanță sau AI, dispozitive edge, senzori și gateway-uri IoT, echipamente AR/VR, sisteme pentru procesarea datelor, infrastructură blockchain, roboți, drone și echipamente de securitate cibernetică.</p><p>Pentru CDI, instrumentele și echipamentele sunt eligibile numai în măsura și pe durata utilizării în proiect. Dacă sunt folosite și ulterior sau în alte activități, bugetarea trebuie să respecte regulile de amortizare și alocare. Echipamentele second-hand sunt neeligibile.</p></section>
      <section><h2>Produse hardware inovatoare</h2><p>Produsul hardware este un echipament independent cu componentă software de control și management. Valoarea maximă nerambursabilă poate ajunge la 3.000.000 euro, inclusiv minimis. Producția trebuie realizată de întreprinderea beneficiară, lider sau partener.</p><p>Dacă ajutorul depășește 1.500.000 euro, diferența trebuie justificată prin finanțarea liniei de producție. Bugetul trebuie să lege proiectarea electronică, prototiparea, firmware-ul, testarea de conformitate, pregătirea producției și activele liniei de rezultatul comercial.</p></section>
      <section><h2>Software, licențe și cloud</h2><p>Pot fi eligibile aplicații software, licențe, acces la platforme cloud și infrastructuri ori servicii bazate pe tehnologii avansate. Pentru CDI, ghidul menționează abonamente SaaS, PaaS și XaaS, medii de dezvoltare și testare, baze de date gestionate, pipeline-uri ML, servicii AI/ML, API-uri și modele sau licențe AI pe consum, precum și resurse cloud pentru procesare, stocare, antrenare, simulare și testare.</p><p>Fiecare serviciu trebuie dimensionat prin utilizatori, volum, durată, mediu și etapă. Licențele generale ale firmei, costurile fără trasabilitate către proiect și resursele folosite în alte produse nu trebuie ascunse într-un abonament global.</p></section>
      <section><h2>Personal propriu și servicii specializate</h2><p>Activitățile pot fi realizate de personalul solicitantului sau prin servicii specializate: cercetare contractuală, dezvoltare software la comandă, testare și validare. Echipa trebuie să includă un coordonator tehnic și minimum doi experți tehnici calificați.</p><p>Externalizarea integrală este interzisă. Finanțarea nerambursabilă aferentă activității tehnice desfășurate de personalul propriu trebuie să reprezinte minimum 20% din finanțarea activității de bază. Costurile salariale se raportează la grila din Anexa 9, la timpul efectiv și la regulile privind numărul maxim de ore.</p></section>
      <section><h2>Proprietate intelectuală și active necorporale</h2><p>Prin ajutor de minimis pot fi eligibile serviciile pentru certificarea, obținerea, validarea și protejarea brevetelor și a altor active necorporale. În activitățile CDI pot intra cunoștințe și brevete cumpărate sau obținute sub licență de la surse externe în condiții de concurență deplină.</p><p>Activele necorporale aferente investiției trebuie utilizate exclusiv în unitatea beneficiară, să fie amortizabile, achiziționate de la terți fără legături în condițiile pieței și păstrate în activele firmei cel puțin trei ani. Dosarul trebuie să distingă drepturile preexistente, drepturile cumpărate și rezultatele create în proiect.</p></section>
      <section><h2>Ajutor regional, CDI, întreprinderi noi și minimis</h2><p>Bugetul poate combina patru logici de ajutor. Ajutorul regional finanțează activele unei investiții inițiale pentru introducerea în producție. Ajutorul pentru cercetare și dezvoltare acoperă cercetarea industrială și dezvoltarea experimentală. Ajutorul pentru întreprinderi nou-înființate folosește condițiile specifice firmei. Ajutorul de minimis acoperă introducerea pe piață și activitățile auxiliare permise.</p><p>Intensitatea nu se aplică uniform întregului buget. Ea depinde de tipul cheltuielii, regiunea NUTS, dimensiunea firmei și condițiile specifice ajutorului. Un singur procent folosit pentru toate liniile este un semnal că bugetul nu a fost încă încadrat corect.</p></section>
      <section><h2>Praguri obligatorii</h2><ul><li>minimum 80% din finanțarea nerambursabilă totală este alocată activității de bază;</li><li>minimum 20% din finanțarea activității de bază revine activității tehnice realizate de personalul propriu;</li><li>ajutorul de minimis pentru o întreprindere unică nu depășește 300.000 euro în trei ani;</li><li>consultanța și managementul încadrate în limitele precizate de ghid nu depășesc plafonul aplicabil;</li><li>costurile indirecte sunt rambursate prin rata forfetară de 7% raportată la costurile directe eligibile definite de ghid;</li><li>mentenanța după implementare este susținută din fonduri proprii timp de 36 de luni.</li></ul></section>
      <section><h2>Valoarea proiectului și cofinanțarea</h2><p>Valoarea minimă nerambursabilă este 200.000 euro. Maximul este 1.500.000 euro pentru o soluție software și 3.000.000 euro pentru un produs hardware inovator. Pentru întreprinderi nou-înființate, plafoanele ajutorului specific diferă între regiunea mai dezvoltată, regiunile mai puțin dezvoltate și întreprinderea nou-înființată inovatoare.</p><p>Contribuția proprie rezultă după aplicarea intensității fiecărei categorii de ajutor. La aceasta se adaugă TVA-ul și costurile neeligibile, după tratamentul fiscal și regulile ghidului. La contractare, contribuția eligibilă exclusiv TVA se dovedește prin document bancar.</p></section>
      <section><h2>Oferte și rezonabilitatea costurilor</h2><p>Pentru fiecare cheltuială eligibilă sunt necesare minimum două oferte sau justificări de preț: oferte semnate și datate, studii de piață, analize detaliate ori capturi de pe site-uri oficiale care identifică data și furnizorul. Centralizatorul din Anexa 7 prezintă specificațiile, prețurile, oferta aleasă și justificarea.</p><p>Ofertele trebuie să fie comparabile tehnic. Specificațiile nu se scriu după un singur furnizor și nu se justifică prin denumiri comerciale fără parametri. OIPSI poate reduce cheltuielile considerate nerezonabile chiar dacă există două documente.</p></section>
      <section><h2>Cheltuieli neeligibile și demararea</h2><p>Sunt neeligibile, între altele, echipamentele second-hand, dobânzile și comisioanele, amenzile, penalitățile, diferențele de curs, contribuțiile în natură, provizioanele, mentenanța după implementare și costurile de operare în durabilitate. Tratamentul TVA se aplică potrivit valorii operațiunii și posibilității de recuperare, în limitele ghidului.</p><p>Pentru ajutoarele de stat, cheltuielile efectuate înainte de depunerea cererii sunt neeligibile, cu excepția limitată a documentației pregătitoare încadrate la minimis. Orice comandă sau contract trebuie verificat înainte de semnare prin regulile efectului stimulativ.</p></section>
      <section><h2>Checklist de buget</h2><ul><li>separă activitățile obligatorii și rezultatele lor;</li><li>încadrează fiecare cost în tipul de ajutor corect;</li><li>calculează pragurile de 80%, 20%, minimis și costuri indirecte;</li><li>documentează rolul fiecărui activ, serviciu și expert;</li><li>verifică drepturile asupra software-ului, datelor și brevetelor;</li><li>obține două oferte comparabile și centralizatorul;</li><li>calculează contribuția proprie, TVA-ul și costurile neeligibile;</li><li>nu semna comenzi înainte de verificarea momentului permis;</li><li>corelează bugetul cu indicatorii, calendarul și planul de afaceri.</li></ul></section>
      <section><h2>Întrebări frecvente</h2>${faqHtml(page)}</section>
${sourcesHtml(page)}
      <section><h2>Verifică bugetul PoCIDIF 2.1</h2><p>Trimite arhitectura, activitățile CDI, lista de echipamente, licențe și servicii, echipa, ofertele și contribuția proprie. <a href="/verificare-eligibilitate-fonduri-europene">Solicită analiza încadrării cheltuielilor</a>.</p></section>`;
}

function renderPocidifDocumentsScoring(page) {
  return `
      <p class="intro">${esc(page.quickAnswer)}</p>
      <p class="source-note"><strong>Baza verificării:</strong> ghidul aprobat și anexele Acțiunii 2.1, în special modelele cererii, planului de monitorizare, planului de afaceri, bugetului, ofertelor și grila de evaluare. Vezi și <a href="/pocidif-21">pagina principală PoCIDIF 2.1</a>.</p>
      <section><h2>Dosarul este un sistem coerent</h2><p>Evaluatorul citește aceleași ipoteze în cererea de finanțare, planul de afaceri, arhitectură, buget, echipă, indicatori și oferte. Dacă produsul este prezentat diferit între documente, costurile nu duc la aceleași livrabile sau veniturile nu susțin indicatorii, dosarul devine fragil chiar dacă toate anexele există formal.</p><p>Documentele se completează în limba română și se transmit prin MySMIS2021, în formatele și cu semnăturile cerute. Anexele-model nu trebuie refăcute într-o structură proprie.</p></section>
      <section><h2>Documentele obligatorii la depunere</h2><ol><li>cererea de finanțare conform Anexei 1;</li><li>declarația unică, Anexa 2;</li><li>împuternicirea, dacă semnează altă persoană;</li><li>hotărârea AGA/CA sau decizia asociatului unic privind proiectul, valoarea și cofinanțarea;</li><li>dovezile pentru întreprinderea nou-înființată inovatoare, când este cazul;</li><li>acordul de parteneriat, Anexa 16, când există parteneri;</li><li>planul de afaceri, Anexa 4;</li><li>planul de monitorizare, Anexa 3;</li><li>declarația TVA, Anexa 5;</li><li>bugetul defalcat, Anexa 6;</li><li>minimum două oferte sau justificări de preț pentru fiecare cheltuială eligibilă;</li><li>centralizatorul ofertelor, Anexa 7;</li><li>actul de numire și CV-urile echipei;</li><li>declarațiile de conflict de interese, Anexa 8;</li><li>declarația IMM, Anexa 11;</li><li>declarația privind cumulul ajutoarelor, Anexa 17;</li><li>situațiile financiare pentru ultimii doi ani;</li><li>alte documente explicative necesare susținerii proiectului.</li></ol></section>
      <section><h2>Planul de afaceri</h2><p>Planul de afaceri demonstrează problema de piață, caracterul inovator, utilizatorii, concurenții, strategia de comercializare, Product-Market Fit, modelele de venit, riscurile, echipa și sustenabilitatea. Afirmațiile despre noutate trebuie susținute prin comparații și dovezi, nu prin adjective.</p><p>Previziunile financiare alimentează indicatorul de performanță a investiției. Veniturile directe și indirecte trebuie să provină din exploatarea produsului creat, iar costurile includ dezvoltarea și exploatarea în durabilitate. O prognoză optimistă poate crește artificial scorul, dar creează risc de recuperare dacă indicatorii devin imposibil de atins.</p></section>
      <section><h2>Planul tehnic și echipa</h2><p>Arhitectura descrie cerințele, componentele, datele, integrările, securitatea, mediile, testarea, livrarea și operarea. Pentru hardware, descrie arhitectura electronică, PCB-ul, prototiparea, firmware-ul și validarea de conformitate. Activitățile se împart în repere verificabile.</p><p>Echipa conține obligatoriu un coordonator tehnic și minimum doi experți tehnici. Lipsa acestei structuri conduce la respingere. CV-urile, calificările, certificările și rolurile trebuie corelate cu activitățile, iar înlocuirea în implementare este acceptată numai justificat și cu experiență cel puțin similară.</p></section>
      <section><h2>Bugetul și ofertele</h2><p>Bugetul defalcat din Anexa 6 trebuie corelat cu activitățile și categoriile MySMIS. Pentru fiecare cheltuială, minimum două oferte justifică prețul. Centralizatorul arată denumirea, specificațiile minime, unitatea de măsură, prețurile, valoarea bugetată, alegerea și motivul alegerii.</p><p>Evaluatorul poate corecta sau elimina costuri nerezonabile ori fără legătură. Bugetul trebuie să respecte pragurile activității de bază, contribuției tehnice proprii, minimisului, costurilor indirecte și intensităților aplicabile.</p></section>
      <section><h2>Indicatorii de realizare și rezultat</h2><p>RCO01 și RCO02 măsoară întreprinderile sprijinite, iar RCR03 măsoară IMM-urile care introduc inovare de produs. În parteneriat, ținta pentru întreprinderile sprijinite reflectă liderul și partenerii. Valoarea de bază a indicatorilor este zero.</p><p>Proiectul trebuie să livreze minimum un produs, serviciu sau o aplicație inovatoare, minimum trei dovezi de comercializare și o performanță a investiției mai mare de 0,5. Cel puțin o dovadă de introducere pe piață este necesară în primul an după implementare. Contractele și facturile pot fi dovezi; facturile proforme și acordurile fără comercializare nu sunt suficiente.</p></section>
      <section><h2>Indicatorii de etapă</h2><p>Planul de monitorizare definește repere calitative, valorice sau cantitative: proof of concept, prototip, testare beta, pilot cu clienți, sistem funcțional ori produs lansat. Primul indicator se poate stabili după o lună, dar nu mai târziu de șase luni de la începerea implementării. Cel puțin un indicator de etapă trebuie să fie calitativ.</p><p>Pentru fiecare reper se indică termenul și dovada: cod sursă, repository, raport de testare, demo, proces-verbal, documentație API, analytics, scrisori de la utilizatori sau dovezi de vânzare. Indicatorul nu trebuie formulat ca o activitate vagă precum „dezvoltare platformă”.</p></section>
      <section><h2>Structura punctajului</h2><p>Grila acordă maximum 100 de puncte și evaluează relevanța și maturitatea, calitatea proiectului, fezabilitatea, capacitatea tehnică și financiară și sustenabilitatea. Secțiunea privind relevanța punctează noutatea produsului și numărul sectoarelor vizate. Maturitatea analizează produsul comercializabil și Product-Market Fit.</p><p>Caracterul complet nou poate primi mai mult decât o îmbunătățire semnificativă, dar numai dacă sunt dovedite problema, tehnologia emergentă, diferențierea, interoperabilitatea și valoarea adăugată. Acolo unde grila are opțiuni fixe, evaluatorul nu acordă punctaje intermediare.</p></section>
      <section><h2>Pragul de calitate și pragul de excelență</h2><p>Punctajul final este media punctajelor evaluatorilor. Pragul de calitate este <strong>70 de puncte</strong>; sub el proiectul este respins. Pragul de excelență este <strong>92 de puncte</strong>, iar proiectele care îl ating intră în mecanismul de selecție directă descris de ghid, în limita bugetului și a regulilor aplicabile.</p><p>Pragul nu garantează finanțarea dacă alocarea este insuficientă. Pentru egalități se compară mai întâi punctajul secțiunii Relevanță și maturitate, apoi Calitatea proiectului și, dacă egalitatea continuă, ordinea depunerii.</p></section>
      <section><h2>Criterii care pot respinge proiectul</h2><p>Zero la subcriteriul critic privind inovarea conduce la respingere dacă proiectul nu demonstrează caracter inovator, repetă soluții existente sau folosește o tehnologie depășită. Lipsa coordonatorului și a celor doi experți tehnici este de asemenea eliminatorie.</p><p>Eligibilitatea solicitantului, CAEN, activitățile obligatorii, introducerea pe piață și indicatorii nu pot fi compensate prin punctaj mare la marketing sau sustenabilitate. Evaluarea folosește documentele depuse; răspunsurile la clarificări nu trebuie să creeze un proiect nou.</p></section>
      <section><h2>Documentele pentru întreprinderea inovatoare</h2><p>Când se solicită ajutor pentru o întreprindere nou-înființată inovatoare, se depune raportul expertului extern, raportul auditorului sau dovezile corespunzătoare definiției aplicabile. Expertul care evaluează noutatea și riscul tehnologic trebuie să aibă minimum zece ani de experiență în sector și publicațiile ori certificările cerute.</p><p>Raportul trebuie să analizeze stadiul tehnologiei, noutatea substanțială și riscul tehnologic ori industrial. Un document de recomandare comercială sau o opinie nesusținută nu înlocuiește raportul cerut.</p></section>
      <section><h2>Contractare și recertificare</h2><p>În etapa de contractare se cer documentele statutare, declarațiile IMM și de cumul, certificatele fiscale, documentele locației și celelalte dovezi care recertifică eligibilitatea. Codurile CAEN trebuie autorizate la toate locațiile declarate. Contribuția proprie se dovedește în termenul indicat în scrisoarea de contractare.</p><p>Schimbările între depunere și contractare pot afecta dimensiunea IMM, datoriile, ajutoarele cumulate, echipa sau locația. Dosarul trebuie monitorizat după transmitere, nu arhivat până la rezultat.</p></section>
      <section><h2>Greșeli de documentare și punctaj</h2><ul><li>noutatea este declarată, dar nu comparată cu soluțiile existente;</li><li>planul de afaceri și arhitectura descriu produse diferite;</li><li>Product-Market Fit se bazează numai pe opinii interne;</li><li>CV-urile nu susțin rolurile sau echipa minimă lipsește;</li><li>indicatorii nu au dovezi, termene ori valori realiste;</li><li>veniturile prognozate nu se leagă de modelul comercial;</li><li>ofertele nu sunt comparabile sau nu identifică emitentul și data;</li><li>autoevaluarea acordă punctaje intermediare pe criterii fixe;</li><li>dosarul urmărește pragul de 70 fără marjă pentru corecții;</li><li>clarificările sunt folosite pentru a reface elemente esențiale lipsă.</li></ul></section>
      <section><h2>Checklist înainte de transmitere</h2><ul><li>verifică lista completă a celor 18 categorii de documente;</li><li>aliniază cererea, planul de afaceri, bugetul și monitorizarea;</li><li>confirmă echipa minimă și dovezile de experiență;</li><li>recalculează indicatorii și performanța investiției;</li><li>testează fiecare punct din autoevaluare cu documentul suport;</li><li>verifică pragul de calitate, excelență și criteriile eliminatorii;</li><li>pregătește documentele de contractare care pot expira;</li><li>revizuiește drepturile asupra rezultatului și dovezile de piață.</li></ul></section>
      <section><h2>Întrebări frecvente</h2>${faqHtml(page)}</section>
${sourcesHtml(page)}
      <section><h2>Verifică dosarul și punctajul</h2><p>Trimite planul de afaceri, arhitectura, echipa, indicatorii, bugetul și autoevaluarea. <a href="/verificare-eligibilitate-fonduri-europene">Solicită o verificare PoCIDIF 2.1</a> înainte de transmiterea în MySMIS.</p></section>`;
}

function renderPocidifContent(page) {
  if (page.slug === "pocidif-21") return renderPocidifMain(page);
  if (page.slug === "eligibilitate-pocidif-21") return renderPocidifEligibility(page);
  if (page.slug === "cheltuieli-eligibile-pocidif-21") return renderPocidifExpenses(page);
  if (page.slug === "documente-punctaj-pocidif-21") return renderPocidifDocumentsScoring(page);
  return "";
}

module.exports = { renderPocidifContent };
