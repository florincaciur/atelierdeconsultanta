/* Specific service information maintained outside the funding-status registry.
   This module makes no new claims about approvals, staff or past projects. */
const fs = require('node:fs');
const path = require('node:path');
const cheerio = require('cheerio');
const { fileForRoute } = require('./structured-data-utils');
const ROOT = path.resolve(__dirname, '..');
const START = '<!-- SEARCH_QUALITY_START -->';
const END = '<!-- SEARCH_QUALITY_END -->';
const blocks = {
 '/proiectare-fonduri-europene': `<section class="search-quality" id="documentatii-proiectare" aria-labelledby="documentatii-proiectare-title">
 <h2 id="documentatii-proiectare-title">Servicii de proiectare: de la temă la documentația tehnică</h2>
 <p>Pentru o construcție nouă, o modernizare sau o instalație, pornim de la amplasament, tema de proiectare și etapa investiției. Oferta precizează documentațiile, specialitățile, verificările și avizele incluse, precum și datele pe care le asigură beneficiarul.</p>
 <div class="search-quality__table" role="region" aria-label="Comparație între documentațiile de proiectare" tabindex="0"><table><thead><tr><th scope="col">Documentație</th><th scope="col">Întrebarea la care răspunde</th><th scope="col">Date de pregătit</th></tr></thead><tbody>
 <tr><th scope="row"><a href="/studiu-fezabilitate-fonduri-europene">Studiu de fezabilitate (SF)</a></th><td>Ce soluție și ce investiție sunt justificate pentru un obiectiv nou?</td><td>Tema, amplasamentul, capacitatea urmărită și constrângerile tehnice.</td></tr>
 <tr><th scope="row">DALI</th><td>Ce intervenții sunt necesare asupra unei construcții existente?</td><td>Actele și documentația existentă, relevee și expertizele necesare.</td></tr>
 <tr><th scope="row">DTAC</th><td>Ce documentație este necesară în etapa autorizării?</td><td>Certificatul de urbanism, avizele cerute și soluția de proiectare.</td></tr>
 <tr><th scope="row">Proiect tehnic și detalii de execuție (PT/DE)</th><td>Cum se detaliază soluția pentru realizarea lucrărilor?</td><td>Soluția aprobată, condițiile avizatorilor și coordonarea specialităților.</td></tr>
 </tbody></table></div>
 <h3>Ce trimiți pentru o ofertă de proiectare</h3>
 <p>Trimite localitatea și amplasamentul, destinația construcției, suprafața sau capacitatea estimată, situația juridică a imobilului, documentele deja obținute și termenul urmărit. Menționează programul de finanțare dacă este ales. Încadrarea documentației și responsabilitățile specialiștilor se stabilesc pentru investiția concretă.</p>
 <p><strong>Exemplu orientativ:</strong> o hală nouă și reabilitarea unei clădiri existente cer analize diferite. Nu se reutilizează automat aceeași documentație sau același deviz doar pentru că investițiile urmăresc același apel.</p>
 <p><a class="btn" href="/contact#source_page=%2Fproiectare-fonduri-europene">Solicită ofertă de proiectare</a></p>
 </section>`,
 '/studiu-fezabilitate-fonduri-europene': `<section class="search-quality" id="pregatire-studiu" aria-labelledby="pregatire-studiu-title">
 <h2 id="pregatire-studiu-title">Ce pregătești pentru studiul de fezabilitate</h2>
 <p>Pregătește tema investiției, actele amplasamentului, capacitatea urmărită, situația utilităților, documentele de urbanism disponibile și bugetul estimat. Lista studiilor și avizelor se stabilește după amplasament și natura lucrărilor.</p>
 <h3>Ce trebuie să poți verifica la predare</h3>
 <ul><li>Variantele tehnice analizate și justificarea soluției recomandate.</li><li>Legătura dintre capacități, costuri, deviz și indicatorii investiției.</li><li>Ipotezele privind terenul, utilitățile și condițiile de realizare.</li><li>Concordanța cu cererea de finanțare și documentele cerute de apel.</li></ul>
 <p>Un SF fundamentează investiția; detalierea pentru execuție aparține etapei de proiect tehnic. Pentru o construcție existentă, clarifică mai întâi dacă investiția necesită DALI și documentații suplimentare.</p>
 <p><a href="/proiectare-fonduri-europene#documentatii-proiectare">Compară SF, DALI, DTAC și PT/DE</a> sau <a href="/contact#source_page=%2Fstudiu-fezabilitate-fonduri-europene">trimite tema pentru o ofertă</a>.</p>
 </section>`,
 '/consultanta-pnrr-digitalizare': `<section class="search-quality" aria-labelledby="pnrr-servicii-title"><h2 id="pnrr-servicii-title">Ai un proiect PNRR contractat sau cauți o finanțare nouă?</h2>
 <p>Pentru un proiect contractat, analiza pornește de la contractul de finanțare, bugetul aprobat, termene, achiziții și obligațiile de raportare. O modificare a ghidului pentru proiectele existente nu înseamnă că se pot depune cereri noi.</p>
 <p>Pentru o investiție nouă, compară <a href="/fonduri-europene-digitalizare">programele de digitalizare și inovare</a> după regiune, activitate, tipul soluției și statutul apelului. <a href="/digitalizare-imm">Pagina Digitalizare IMM</a> prezintă separat situația PNRR și implementarea.</p>
 <p><strong>Exemplu:</strong> dacă vrei un ERP și echipamente IT, descrie procesele actuale, utilizatorii și integrarea necesară. Bugetul trebuie să separe licențele, configurarea, echipamentele și instruirea; eligibilitatea fiecărei poziții se verifică în documentele apelului.</p></section>`,
 '/consultanta-afir': `<section class="search-quality" aria-labelledby="afir-pregatire-title"><h2 id="afir-pregatire-title">Ce analizăm înaintea unui dosar AFIR</h2>
 <p>Trimite forma juridică, localitatea, sectorul fermei, suprafețele sau efectivele, investiția propusă și documentele disponibile. Comparăm aceste date cu intervenția și componenta sectorială potrivite; dimensiunea economică se verifică prin <a href="/calculator-soc">calculul SO al exploatației</a>.</p>
 <p>Dacă proiectul include clădiri sau instalații, verificarea documentației tehnice începe înaintea definitivării bugetului. Vezi <a href="/proiectare-fonduri-europene">serviciile de proiectare SF, DALI și proiect tehnic</a> și <a href="/studiu-fezabilitate-fonduri-europene">datele necesare studiului de fezabilitate</a>.</p>
 <p><strong>Exemplu:</strong> achiziția unui utilaj și construirea unui adăpost nu au aceeași listă de documente. Pentru construcție trebuie clarificate amplasamentul, dreptul asupra imobilului, urbanismul și soluția tehnică; oferta consultantului trebuie să precizeze aceste responsabilități.</p></section>`,
 '/cum-alegi-consultant-fonduri-europene': `<section class="search-quality" aria-labelledby="consultant-comparatie-title"><h2 id="consultant-comparatie-title">Compară două oferte pe aceleași livrabile</h2>
 <p>Cere fiecărui consultant să precizeze în scris dacă prețul include analiza eligibilității, planul de afaceri, cererea, anexele, răspunsurile la clarificări și implementarea. Verifică separat TVA, cheltuielile terților, condițiile de plată și ce se întâmplă dacă proiectul nu se depune sau nu este selectat.</p>
 <p>Pentru investiții cu lucrări, întreabă cine pregătește studiul de fezabilitate, devizul, avizele și proiectul tehnic. <a href="/proiectare-fonduri-europene">Proiectarea</a> trebuie corelată cu dosarul și delimitată în ofertă. Cere exemple verificabile de proiecte similare și rolul efectiv al echipei în fiecare exemplu.</p></section>`
};
function main() {
 const check=process.argv.includes('--check');let changed=0;
 for(const [route,content] of Object.entries(blocks)) {
  const file=fileForRoute(ROOT,route),before=fs.readFileSync(file,'utf8');
  if(check) {
   const current=before.match(new RegExp(START+'([\\s\\S]*?)'+END,'u'))?.[1]||'';
   const semantic=html=>{const $=cheerio.load(html);return JSON.stringify({text:$.text().replace(/\s+/g,' ').trim(),links:$('a[href]').map((i,e)=>$(e).attr('href')).get()});};
   // Analytics and long-form generators may decorate the HTML with attributes.
   // Validate the content and destinations without rejecting those enrichments.
   const $=cheerio.load(before);
   const inMainArticle=$('main > article.panel > .search-quality').length===1;
   if(!inMainArticle||semantic(current)!==semantic(content)||!before.includes('/assets/search-quality.css'))changed++;
   continue;
  }
  let after=before.replace(new RegExp('\\s*'+START+'[\\s\\S]*?'+END+'\\s*','u'),'\n');
  const block=`\n${START}\n${content}\n${END}\n`;
  // The article owns the substantive content; section insertion is independent
  // of the managed FAQ, status, provenance and related-link blocks.
  // AEO answers contain nested <article> elements. Resolve the outer content
  // article structurally, otherwise a later AEO sync removes the service block.
  const $=cheerio.load(after,{sourceCodeLocationInfo:true});
  const end=$('main > article.panel').first().get(0)?.sourceCodeLocation?.endTag?.startOffset;
  if(!Number.isInteger(end))throw new Error(`${route}: main article missing`);
  after=after.slice(0,end).trimEnd()+block+after.slice(end);
  if(!after.includes('/assets/search-quality.css'))after=after.replace('</head>','  <link rel="stylesheet" href="/assets/search-quality.css?v=20261105">\n</head>');
  if(before.replace(/\r\n/g,'\n')!==after.replace(/\r\n/g,'\n')) {changed++;if(!check)fs.writeFileSync(file,after);}
 }
 if(check&&changed)throw new Error(`Search quality: ${changed} unsynchronized pages`);
 console.log(`Search quality ${check?'check':'sync'}: ${Object.keys(blocks).length} pages, ${changed} changed.`);
}
if(require.main===module)main();
module.exports={blocks};
