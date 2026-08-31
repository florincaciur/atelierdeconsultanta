#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { serializeJsonLd } = require("./schema-helpers");

const ROOT = path.resolve(__dirname, "..");
const CHECK_ONLY = process.argv.includes("--check");
const TARGET = path.resolve(process.argv.slice(2).find((arg) => !arg.startsWith("--")) || ROOT);

const EXCLUDED_DIRS = new Set([
  ".git",
  ".github",
  ".wrangler",
  "dist",
  "node_modules",
  "reports",
]);

const ROMANIAN_COPY_REPLACEMENTS = [
  [/Țîn/g, "Țin"],
  [/țîn/g, "țin"],
  [/\bMicrointreprinderi\b/g, "Microîntreprinderi"],
  [/\bmicrointreprinderi\b/g, "microîntreprinderi"],
  [/\bAcasa\b/g, "Acasă"],
  [/\bacasa\b/g, "acasă"],
  [/\bSolicita(?=\s+(?:verificarea|o verificare|analiza|oferta|detalii))\b/g, "Solicită"],
  [/\bSa(?=\s+(?:fie|poată|se|verifice|pregătească|depună))\b/g, "Să"],
  [/\b(?:ca|poate|trebuie|astfel încât) sa\b/g, (match) => match.replace(/sa$/, "să")],
  [/\bDaca\b/g, "Dacă"],
  [/\bdaca\b/g, "dacă"],
  [/\bColectie\b/g, "Colecție"],
  [/\bcolectie\b/g, "colecție"],
  [/\binitiala\b/g, "inițială"],
  [/\binitial\b/g, "inițial"],
  [/\boficiala\b/g, "oficială"],
  [/\boficial\b/g, "oficial"],
  [/\bfinala\b/g, "finală"],
  [/\bpractica\b/g, "practică"],
  [/\breala\b/g, "reală"],
  [/\brealistă\b/g, "realistă"],
  [/\brealista\b/g, "realistă"],
  [/\bprudenta\b/g, "prudentă"],
  [/\bAceasta\b/g, "Această"],
  [/\baceasta\b/g, "această"],
  [/\bAgricultura\b/g, "Agricultură"],
  [/\bagricultura\b/g, "agricultură"],
  [/\borientativa\b/g, "orientativă"],
  [/\butila\b/g, "utilă"],
  [/\bagricola\b/g, "agricolă"],
  [/\beconomica\b/g, "economică"],
  [/\bjuridica\b/g, "juridică"],
  [/\btehnica\b/g, "tehnică"],
  [/\boperationala\b/g, "operațională"],
  [/\bdisponibila\b/g, "disponibilă"],
  [/\bestimata\b/g, "estimată"],
  [/\bposibila\b/g, "posibilă"],
  [/\bpotrivita\b/g, "potrivită"],
  [/\bneclara\b/g, "neclară"],
  [/\bneeligibila\b/g, "neeligibilă"],
  [/\bConsultanta\b/g, "Consultanță"],
  [/\bconsultanta\b/g, "consultanță"],
  [/\bFinantare\b/g, "Finanțare"],
  [/\bfinantare\b/g, "finanțare"],
  [/\bfinantari\b/g, "finanțări"],
  [/\bfinantarea\b/g, "finanțarea"],
  [/\bfinantarii\b/g, "finanțării"],
  [/\bfinantata\b/g, "finanțată"],
  [/\bfinantat\b/g, "finanțat"],
  [/\bfinantate\b/g, "finanțate"],
  [/\bfinantator\b/g, "finanțator"],
  [/\bCofinantare\b/g, "Cofinanțare"],
  [/\bcofinantare\b/g, "cofinanțare"],
  [/\bcofinantarea\b/g, "cofinanțarea"],
  [/\bcofinantarii\b/g, "cofinanțării"],
  [/\bInvestitii\b/g, "Investiții"],
  [/\bInvestitie\b/g, "Investiție"],
  [/\binvestitii\b/g, "investiții"],
  [/\binvestitie\b/g, "investiție"],
  [/\binvestitia\b/g, "investiția"],
  [/\binvestitiei\b/g, "investiției"],
  [/\binvestitiile\b/g, "investițiile"],
  [/\bFunctie\b/g, "Funcție"],
  [/\bfunctie\b/g, "funcție"],
  [/\beligibilitatii\b/g, "eligibilității"],
  [/\bincadrare\b/g, "încadrare"],
  [/\bdiferita\b/g, "diferită"],
  [/\bmecanica\b/g, "mecanică"],
  [/\brecomandam\b/g, "recomandăm"],
  [/\bpasii\b/g, "pașii"],
  [/\bintampla\b/g, "întâmplă"],
  [/\bsolutia\b/g, "soluția"],
  [/\bConditii\b/g, "Condiții"],
  [/\bconditii\b/g, "condiții"],
  [/\bconditiile\b/g, "condițiile"],
  [/\bconditie\b/g, "condiție"],
  [/\bPregatire\b/g, "Pregătire"],
  [/\bpregatire\b/g, "pregătire"],
  [/\bPregati\b/g, "Pregăti"],
  [/\bpregati\b/g, "pregăti"],
  [/\bpregatirea\b/g, "pregătirea"],
  [/\bPregatirea\b/g, "Pregătirea"],
  [/\bincepe\b/g, "începe"],
  [/\bpregatirii\b/g, "pregătirii"],
  [/\bpregateste\b/g, "pregătește"],
  [/\bpregatesti\b/g, "pregătești"],
  [/\bpregatesc\b/g, "pregătesc"],
  [/\bpregatite\b/g, "pregătite"],
  [/\bpregatit\b/g, "pregătit"],
  [/\bpregatita\b/g, "pregătită"],
  [/\bpregatim\b/g, "pregătim"],
  [/\bSe verifica\b/g, "Se verifică"],
  [/\bse verifica\b/g, "se verifică"],
  [/\bVerifica\b/g, "Verifică"],
  [/\bverifica\b/g, "verifică"],
  [/\bverificari\b/g, "verificări"],
  [/\bverificarile\b/g, "verificările"],
  [/\bverificata\b/g, "verificată"],
  [/\bverificat\b/g, "verificat"],
  [/\bverificate\b/g, "verificate"],
  [/\bIntrebari\b/g, "Întrebări"],
  [/\bintrebari\b/g, "întrebări"],
  [/\bintrebarea\b/g, "întrebarea"],
  [/\bintai\b/g, "întâi"],
  [/\bInainte\b/g, "Înainte"],
  [/\binainte\b/g, "înainte"],
  [/\bPana\b/g, "Până"],
  [/\bpana\b/g, "până"],
  [/\bDupa\b/g, "După"],
  [/\bdupa\b/g, "după"],
  [/\bCand\b/g, "Când"],
  [/\bcand\b/g, "când"],
  [/\bCat\b/g, "Cât"],
  [/\bcat\b/g, "cât"],
  [/\bCatre\b/g, "Către"],
  [/\bcatre\b/g, "către"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])In(?![A-Za-zĂÂÎȘȚăâîșț])/g, "În"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])in(?![A-Za-zĂÂÎȘȚăâîșț])/g, "în"],
  [/(?<![A-Za-zĂÂÎȘȚăâîșț])si(?![A-Za-zĂÂÎȘȚăâîșț])/g, "și"],
  [/\bEste\b/g, "Este"],
  [/\bexista\b/g, "există"],
  [/\bExista\b/g, "Există"],
  [/\binseamna\b/g, "înseamnă"],
  [/\bInseamna\b/g, "Înseamnă"],
  [/\bobtin\b/g, "obțin"],
  [/\bobtine\b/g, "obține"],
  [/\bobtinut\b/g, "obținut"],
  [/\bobtinere\b/g, "obținere"],
  [/\bfermei\b/g, "fermei"],
  [/\bexploatatie\b/g, "exploatație"],
  [/\bexploatatia\b/g, "exploatația"],
  [/\bexploatatiei\b/g, "exploatației"],
  [/\bexploatatii\b/g, "exploatații"],
  [/\bexploatatiile\b/g, "exploatațiile"],
  [/\bcomparatie\b/g, "comparație"],
  [/\bTanar\b/g, "Tânăr"],
  [/\btanar\b/g, "tânăr"],
  [/\btineri\b/g, "tineri"],
  [/\bvarsta\b/g, "vârstă"],
  [/\bvarstei\b/g, "vârstei"],
  [/\bLocatie\b/g, "Locație"],
  [/\blocatie\b/g, "locație"],
  [/\blocatia\b/g, "locația"],
  [/\bspatiu\b/g, "spațiu"],
  [/\bspatiul\b/g, "spațiul"],
  [/\bspatii\b/g, "spații"],
  [/\bcladire\b/g, "clădire"],
  [/\bcladiri\b/g, "clădiri"],
  [/\bfolosinta\b/g, "folosință"],
  [/\bfolosintei\b/g, "folosinței"],
  [/\badaposturi\b/g, "adăposturi"],
  [/\bsuprafete\b/g, "suprafețe"],
  [/\bsuprafetele\b/g, "suprafețele"],
  [/\bdotari\b/g, "dotări"],
  [/\bdotarile\b/g, "dotările"],
  [/\beficienta\b/g, "eficiență"],
  [/\bproductie\b/g, "producție"],
  [/\bproductiei\b/g, "producției"],
  [/\binstalatii\b/g, "instalații"],
  [/\bincarcare\b/g, "încărcare"],
  [/\belectrica\b/g, "electrică"],
  [/\bregenerabila\b/g, "regenerabilă"],
  [/\bprivati\b/g, "privați"],
  [/\bLocala\b/g, "Locală"],
  [/\blocala\b/g, "locală"],
  [/\bAdresa\b/g, "Adresă"],
  [/\badresa\b/g, "adresă"],
  [/\bsituatii\b/g, "situații"],
  [/\bsituatiile\b/g, "situațiile"],
  [/\bselectie\b/g, "selecție"],
  [/\bselectia\b/g, "selecția"],
  [/\bachizitii\b/g, "achiziții"],
  [/\bachizitie\b/g, "achiziție"],
  [/\bplati\b/g, "plăți"],
  [/\b(o|fiecare|această) plata\b/g, "$1 plată"],
  [/\braportari\b/g, "raportări"],
  [/\bobligatii\b/g, "obligații"],
  [/\bautorizari\b/g, "autorizări"],
  [/\bclarificari\b/g, "clarificări"],
  [/\bsemnaturi\b/g, "semnături"],
  [/\bfisiere\b/g, "fișiere"],
  [/\bInformatii\b/g, "Informații"],
  [/\bInformatiile\b/g, "Informațiile"],
  [/\binformatii\b/g, "informații"],
  [/\binformatiile\b/g, "informațiile"],
  [/\bIncadrarea\b/g, "Încadrarea"],
  [/\bincadrarea\b/g, "încadrarea"],
  [/\bUrmatorul\b/g, "Următorul"],
  [/\burmatorul\b/g, "următorul"],
  [/\bUrmatoarea\b/g, "Următoarea"],
  [/\burmatoarea\b/g, "următoarea"],
  [/\bUrmatorii\b/g, "Următorii"],
  [/\burmatorii\b/g, "următorii"],
  [/\bUrmatoarele\b/g, "Următoarele"],
  [/\burmatoarele\b/g, "următoarele"],
  [/\bUrmator\b/g, "Următor"],
  [/\burmator\b/g, "următor"],
  [/\braspuns\b/g, "răspuns"],
  [/\braspunsuri\b/g, "răspunsuri"],
  [/\braspunda\b/g, "răspundă"],
  [/\braspunde\b/g, "răspunde"],
  [/\blipseste\b/g, "lipsește"],
  [/\b(o|fiecare|această) lipsa\b/g, "$1 lipsă"],
  [/\bfoloseste\b/g, "folosește"],
  [/\bfolosesti\b/g, "folosești"],
  [/\bcauta\b/g, "caută"],
  [/\bcauti\b/g, "cauți"],
  [/\bcitesti\b/g, "citești"],
  [/\bnoteaza\b/g, "notează"],
  [/\bconstruieste\b/g, "construiește"],
  [/\brevizuieste\b/g, "revizuiește"],
  [/\btrimiti\b/g, "trimiți"],
  [/\bpoti\b/g, "poți"],
  [/\bpoata\b/g, "poată"],
  [/\bfata\b/g, "față"],
  [/\bFara\b/g, "Fără"],
  [/\bfara\b/g, "fără"],
  [/\bAceeasi\b/g, "Aceeași"],
  [/\baceeasi\b/g, "aceeași"],
  [/\bdiscutia\b/g, "discuția"],
  [/\bDiscutie\b/g, "Discuție"],
  [/\bdiscutie\b/g, "discuție"],
  [/\bIntentie\b/g, "Intenție"],
  [/\bintentie\b/g, "intenție"],
  [/\bintentiei\b/g, "intenției"],
  [/\bCautare\b/g, "Căutare"],
  [/\bcautare\b/g, "căutare"],
  [/\bStie\b/g, "Știe"],
  [/\bstie\b/g, "știe"],
  [/\bStim\b/g, "Știm"],
  [/\bstim\b/g, "știm"],
  [/\bfolosita\b/g, "folosită"],
  [/\bfolosite\b/g, "folosite"],
  [/\bInlocuieste\b/g, "Înlocuiește"],
  [/\binlocuieste\b/g, "înlocuiește"],
  [/\binlocuiesc\b/g, "înlocuiesc"],
  [/\binlocui\b/g, "înlocui"],
  [/\bContributie\b/g, "Contribuție"],
  [/\bcontributie\b/g, "contribuție"],
  [/\bcontributia\b/g, "contribuția"],
  [/\bcontributiei\b/g, "contribuției"],
  [/\bcontributii\b/g, "contribuții"],
  [/\bcontinut\b/g, "conținut"],
  [/\bcontinutul\b/g, "conținutul"],
  [/\bSolicitanti\b/g, "Solicitanți"],
  [/\bsolicitanti\b/g, "solicitanți"],
  [/\bactivitatii\b/g, "activității"],
  [/\bSpecificatii\b/g, "Specificații"],
  [/\bspecificatii\b/g, "specificații"],
  [/\bAmenajari\b/g, "Amenajări"],
  [/\bamenajari\b/g, "amenajări"],
  [/\bLucrari\b/g, "Lucrări"],
  [/\blucrari\b/g, "lucrări"],
  [/\bEnergetica\b/g, "Energetică"],
  [/\benergetica\b/g, "energetică"],
  [/\bImpreuna\b/g, "Împreună"],
  [/\bimpreuna\b/g, "împreună"],
  [/\bBuna\b/g, "Bună"],
  [/\bbuna\b/g, "bună"],
  [/\bcorecta\b/g, "corectă"],
  [/\bincorecta\b/g, "incorectă"],
  [/\bDiferente\b/g, "Diferențe"],
  [/\bdiferente\b/g, "diferențe"],
  [/\bmodificari\b/g, "modificări"],
  [/\bjustificata\b/g, "justificată"],
  [/\bincepute\b/g, "începute"],
  [/\baparea\b/g, "apărea"],
  [/\braspunsul\b/g, "răspunsul"],
  [/\bRaspunsul\b/g, "Răspunsul"],
  [/\bInlocuiesc\b/g, "Înlocuiesc"],
  [/\breprezinta\b/g, "reprezintă"],
  [/\bgenerala\b/g, "generală"],
  [/\bresponsabila\b/g, "responsabilă"],
  [/\bsuficienta\b/g, "suficientă"],
  [/\bInterventia\b/g, "Intervenția"],
  [/\binterventia\b/g, "intervenția"],
  [/\baceleasi\b/g, "aceleași"],
  [/\bincadreaza\b/g, "încadrează"],
  [/\bdimensioneaza\b/g, "dimensionează"],
  [/\bpregateasca\b/g, "pregătească"],
  [/\brurala\b/g, "rurală"],
  [/\bafecteaza\b/g, "afectează"],
  [/\burmeaza\b/g, "urmează"],
  [/\bprioritara\b/g, "prioritară"],
  [/\bintreaga\b/g, "întreaga"],
  [/\bOfera\b/g, "Oferă"],
  [/\bofera\b/g, "oferă"],
  [/\bDiferenta\b/g, "Diferența"],
  [/\bdiferenta\b/g, "diferența"],
  [/\bDoua\b/g, "Două"],
  [/\bdoua\b/g, "două"],
  [/\bcoerentei\b/g, "coerenței"],
  [/\bgrupeaza\b/g, "grupează"],
  [/\bverificarii\b/g, "verificării"],
  [/\bincepi\b/g, "începi"],
  [/\bcumparaturi\b/g, "cumpărături"],
  [/\bsigura\b/g, "sigură"],
  [/\burmarite\b/g, "urmărite"],
  [/\bactualizata\b/g, "actualizată"],
  [/\bInstitutie\b/g, "Instituție"],
  [/\binstitutie\b/g, "instituție"],
  [/\binstitutia\b/g, "instituția"],
  [/\binstitutii\b/g, "instituții"],
  [/\binstitutiile\b/g, "instituțiile"],
  [/\bnecesara\b/g, "necesară"],
  [/\bgestioneaza\b/g, "gestionează"],
  [/\bdescarcate\b/g, "descărcate"],
  [/\bcompleteaza\b/g, "completează"],
  [/\binceputa\b/g, "începută"],
  [/\bcontinuata\b/g, "continuată"],
  [/\bnationala\b/g, "națională"],
  [/\bnationale\b/g, "naționale"],
  [/\btrateaza\b/g, "tratează"],
  [/\barata\b/g, "arată"],
  [/\bpastreaza\b/g, "păstrează"],
  [/\bestimeaza\b/g, "estimează"],
  [/\bconteaza\b/g, "contează"],
  [/\brapida\b/g, "rapidă"],
  [/\bPret\b/g, "Preț"],
  [/\bpret\b/g, "preț"],
  [/\blegata\b/g, "legată"],
  [/\bimplementari\b/g, "implementări"],
  [/\bmasurabile\b/g, "măsurabile"],
  [/\bclarificarile\b/g, "clarificările"],
  [/\bresponsabilitati\b/g, "responsabilități"],
  [/\bsustina\b/g, "susțină"],
  [/\bpiesa\b/g, "piesă"],
  [/\bajustari\b/g, "ajustări"],
  [/\blicente\b/g, "licențe"],
  [/\bcompleta\b/g, "completă"],
  [/\bcumparate\b/g, "cumpărate"],
  [/\bnumarul\b/g, "numărul"],
  [/\bjustificarii\b/g, "justificării"],
  [/\binsuficienta\b/g, "insuficientă"],
  [/\binformarii\b/g, "informării"],
  [/\btraduca\b/g, "traducă"],
  [/\bIntrebarile\b/g, "Întrebările"],
  [/\bintrebarile\b/g, "întrebările"],
  [/\braspunsurile\b/g, "răspunsurile"],
  [/\bintr-un\b/g, "într-un"],
  [/\bintr-o\b/g, "într-o"],
  [/\boperational\b/g, "operațional"],
  [/\baudienta\b/g, "audiența"],
  [/\bprincipala\b/g, "principală"],
  [/\beditia\b/g, "ediția"],
  [/\btrimita\b/g, "trimită"],
  [/\bparea\b/g, "părea"],
  [/\bIntrebare\b/g, "Întrebare"],
  [/\bintrebare\b/g, "întrebare"],
  [/\binsa\b/g, "însă"],
  [/\bsingura\b/g, "singură"],
  [/\bplatit\b/g, "plătit"],
  [/\bsanatoasa\b/g, "sănătoasă"],
  [/\btesteaza\b/g, "testează"],
  [/\bamanat\b/g, "amânat"],
  [/\bevitam\b/g, "evităm"],
  [/\bspecializata\b/g, "specializată"],
  [/\bstabileste\b/g, "stabilește"],
  [/\badauga\b/g, "adaugă"],
  [/\bcalculeaza\b/g, "calculează"],
  [/\banalizeaza\b/g, "analizează"],
  [/\bajusteaza\b/g, "ajustează"],
  [/\bdeconteaza\b/g, "decontează"],
  [/\bcentralizeaza\b/g, "centralizează"],
  [/\beligibila\b/g, "eligibilă"],
  [/\bincompleta\b/g, "incompletă"],
  [/\binformatia\b/g, "informația"],
  [/\bSelectia\b/g, "Selecția"],
  [/\bselectia\b/g, "selecția"],
  [/\bconcreta\b/g, "concretă"],
  [/\bautorizatii\b/g, "autorizații"],
  [/\bdirecta\b/g, "directă"],
  [/\balimentatie\b/g, "alimentație"],
  [/\bschita\b/g, "schița"],
  [/\bbucatarie\b/g, "bucătărie"],
  [/\bsiguranta\b/g, "siguranță"],
  [/\balimentara\b/g, "alimentară"],
  [/\bspatiului\b/g, "spațiului"],
  [/\bsanse\b/g, "șanse"],
  [/\bcibernetica\b/g, "cibernetică"],
  [/\bContinutul\b/g, "Conținutul"],
  [/\bintrebarilor\b/g, "întrebărilor"],
  [/\bcontine\b/g, "conține"],
  [/\bincarcate\b/g, "încărcate"],
  [/\bajunga\b/g, "ajungă"],
  [/\bmentioneaza\b/g, "menționează"],
  [/\burmarit\b/g, "urmărit"],
  [/\burmareste\b/g, "urmărește"],
  [/\bschimba\b/g, "schimbă"],
  [/\bactualizari\b/g, "actualizări"],
  [/\baprobari\b/g, "aprobări"],
  [/\bintalnire\b/g, "întâlnire"],
  [/\bdistanta\b/g, "distanță"],
  [/\bStiu\b/g, "Știu"],
  [/\bstiu\b/g, "știu"],
  [/\bramane\b/g, "rămâne"],
  [/\braman\b/g, "rămân"],
  [/\bpromisiune\b/g, "promisiune"],
  [/\bgaranteaza\b/g, "garantează"],
  [/\bgarantata\b/g, "garantată"],
  [/\bGreseli\b/g, "Greșeli"],
  [/\bgreseli\b/g, "greșeli"],
  [/\bgresit\b/g, "greșit"],
  [/\bgresita\b/g, "greșită"],
  [/\blegatura\b/g, "legătura"],
  [/\bslaba\b/g, "slabă"],
  [/\bsustin\b/g, "susțin"],
  [/\bsustine\b/g, "susține"],
  [/\bsustinuta\b/g, "susținută"],
  [/\bsustinute\b/g, "susținute"],
  [/\bsursa oficiala\b/g, "sursa oficială"],
  [/\bofertare\b/g, "ofertare"],
  [/\bactiuni\b/g, "acțiuni"],
  [/\bactiunile\b/g, "acțiunile"],
  [/\bactiune\b/g, "acțiune"],
  [/\bActiune\b/g, "Acțiune"],
  [/\bautoritatii\b/g, "autorității"],
  [/\bjudet\b/g, "județ"],
  [/\bjudetul\b/g, "județul"],
  [/\bjudetului\b/g, "județului"],
  [/\bjudete\b/g, "județe"],
  [/\bIasi\b/g, "Iași"],
  [/\bBacau\b/g, "Bacău"],
  [/\bBucuresti\b/g, "București"],
  [/\bRomania\b/g, "România"],
];

function normalizeRomanianCopy(value) {
  let text = String(value ?? "");
  for (const [pattern, replacement] of ROMANIAN_COPY_REPLACEMENTS) {
    text = text.replace(pattern, replacement);
  }
  // The negative imperative uses the infinitive, not the adjective "completă".
  text = text.replace(/\b(Nu|nu) completă(?=\s|[?!.,;:]|$)/gu, "$1 completa");
  text = text.replace(
    /\b(Pot|pot|Poți|poți|Poate|poate|Putem|putem|Puteți|puteți|Vor|vor|Va|va|Ar|ar) verifică(?=\s|[?!.,;:]|$)/gu,
    (match) => match.replace(/verifică$/, "verifica")
  );
  text = text.replace(/\b(pentru|fără) a verifică(?=\s|[?!.,;:]|$)/gu, (match) => match.replace(/verifică$/, "verifica"));
  text = text.replace(
    /\b(Pot|pot|Poți|poți|Poate|poate|Putem|putem|Puteți|puteți|Vor|vor|Va|va|Ar|ar) schimbă(?=\s|[?!.,;:]|$)/gu,
    (match) => match.replace(/schimbă$/, "schimba")
  );
  text = text.replace(/\b(pentru|fără) a schimbă(?=\s|[?!.,;:]|$)/gu, (match) => match.replace(/schimbă$/, "schimba"));
  text = text.replace(/\b(Se|se)(\s+va)?\s+aplica(?=\s|[?!.,;:]|$)/gu, (_, prefix, future = "") => `${prefix}${future} aplică`);
  text = text.replace(/\b(Cine|cine) aplica(?=\s|[?!.,;:]|$)/gu, (_, prefix) => `${prefix} aplică`);
  text = text.replace(/\b(Se|se)(\s+va)?\s+confirma(?=\s|[?!.,;:]|$)/gu, (_, prefix, future = "") => `${prefix}${future} confirmă`);
  text = text.replace(/\b(și|apoi) confirma(?=\s|[?!.,;:]|$)/gu, (_, prefix) => `${prefix} confirmă`);
  text = text.replace(/\b(Se|se)(\s+va)?\s+identifica(?=\s|[?!.,;:]|$)/gu, (_, prefix, future = "") => `${prefix}${future} identifică`);
  text = text.replace(/\b(nu|hub-ul|ghidul|planul|documentul|raportul) explica(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} explică`);
  text = text.replace(/\b(pagina|pagină|calculatorul|istoricul|SO|ele) ajuta(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} ajută`);
  text = text.replace(/\b(eroare|întrebare|intrebare|greșeală) frecventa(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} frecventă`);
  text = text.replace(/\b(autoritatea|instituția|ministerul|DGPET|site-ul) publica(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} publică`);
  text = text.replace(/\b(achiziție|consultare|dezbatere|pagină|sursă) publica(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} publică`);
  text = text.replace(/\b(proiectul|aplicarea|pregătirea|pregatirea) merita(?=\s|[?!.,;:]|$)/giu, (_, prefix) => `${prefix} merită`);
  text = text.replace(/\b(O|o) analiza(?=\s|[?!.,;:]|$)/gu, (_, prefix) => `${prefix} analiză`);
  text = text.replace(/^(\s*)([^.!?\n]{2,140}) trebuie analizat ca o decizie de investiție/gu, "$1Tema „$2” trebuie analizată ca o decizie de investiție");
  text = text.replace(/\b(Pagină|Pagina)(?=\s+(?:răspunde|ajută|este|include|oferă|trimite|insistă|rămâne|explică|centralizează|nu))/gu, "Pagina");
  text = text.replace(/(^|[.!?]\s+)Pagină(?=\s+(?:răspunde|ajută|este|include|oferă|trimite|insistă|rămâne|explică|centralizează|nu))/gu, "$1Pagina");
  text = text.replace(/\bPagină această\b/gu, "Pagina aceasta");
  text = text.replace(/\b(pagină|pagina)\s+(programului|apelului|instituției|institutiei|serviciului|formularului)/gu, "pagina $2");
  text = text.replace(/\b(această|o|fiecare) pagina\b/gu, "$1 pagină");
  text = text.replace(/\bfirmă\s+(ta|are|vrea|trebuie|propune|deține|detine|poate)(?=\s|[?!.,;:]|$)/gu, "firma $1");
  text = text.replace(/\b(această|o|fiecare) firma\b/gu, "$1 firmă");
  text = text.replace(/(?<![Oo] )\bfermă(?=\s+(?:reală|poate|are|trebuie|propune|compară))/gu, "ferma");
  text = text.replace(/\bplatformă\s+(de depunere|indicată|oficială)/gu, "platforma $1");
  text = text.replace(/\b(o|fiecare) platforma\b/gu, "$1 platformă");
  text = text.replace(/\bprocedură\s+(ediției|activă|o cere|permite|stabilește)/gu, "procedura $1");
  text = text.replace(/\b(o|fiecare) procedura\b/gu, "$1 procedură");
  text = text.replace(/\bRută(?=\s+(?:nu|principală|rămâne))/gu, "Ruta");
  text = text.replace(/\brută\s+(principală|de program)(?=\s|[?!.,;:]|$)/gu, "ruta $1");
  text = text.replace(/\b(o|fiecare) ruta\b/gu, "$1 rută");
  text = text.replace(/\blogică\s+(ei|investiției|proiectului|programului|unei)/gu, "logica $1");
  text = text.replace(/(?<!o )\blogică de\b/gu, "logica de");
  text = text.replace(/\bmăsură\s+(locală|potrivită)/gu, "măsura $1");
  text = text.replace(/\b(o|fiecare) măsura\b/gu, "$1 măsură");
  text = text.replace(/\blipsă\s+(justificării|documentelor|dovezii|unui|unei)/gu, "lipsa $1");
  text = text.replace(/\b(o|această|fiecare) metoda\b/gu, "$1 metodă");
  text = text.replace(/\b(fiecare|o|această) componenta\b/gu, "$1 componentă");
  text = text.replace(/\b(o|această) singură lista\b/gu, "$1 singură listă");
  text = text.replace(/\b(faptul|automat) ca\b/gu, "$1 că");
  text = text.replace(/\b(vrea|este|poate|trebuie|urmează|fără) sa\b/gu, "$1 să");
  for (const [plain, accented] of [
    ["aplica", "aplică"],
    ["ajuta", "ajută"],
    ["confirma", "confirmă"],
    ["explica", "explică"],
    ["identifica", "identifică"],
    ["publica", "publică"],
    ["continua", "continuă"],
    ["evita", "evită"],
    ["indica", "indică"],
    ["insista", "insistă"],
    ["justifica", "justifică"],
    ["merita", "merită"],
    ["separa", "separă"],
    ["compara", "compară"]
  ]) {
    text = text.replace(new RegExp(`\\b${plain}(?![A-Za-zĂÂÎȘȚăâîșț])`, "gu"), accented);
    text = text.replace(
      new RegExp(`\\b(Pot|pot|Poate|poate|Putem|putem|Puteți|puteți|Va|va|Vor|vor|Ar|ar|pentru a|fără a|de a) ${accented}(?=\\s|[?!.,;:]|$)`, "gu"),
      (match) => match.replace(accented, plain)
    );
  }
  text = text.replace(/\bwebsite(?:-ul|ul)\b/giu, (match) => (/^[A-Z]/u.test(match) ? "Site-ul" : "site-ul"));
  text = text.replace(/\bwebsite\b/giu, (match) => (/^[A-Z]/u.test(match) ? "Site" : "site"));
  text = text.replace(/\b(un|acest|orice) site-ul\b/giu, "$1 site");
  return text;
}

const JSON_LD_PROTECTED_KEYS = new Set([
  "@context",
  "@id",
  "@type",
  "applicationCategory",
  "addressCountry",
  "availableLanguage",
  "contentUrl",
  "dateCreated",
  "dateModified",
  "datePublished",
  "email",
  "embedUrl",
  "identifier",
  "image",
  "inLanguage",
  "item",
  "latitude",
  "logo",
  "longitude",
  "openingHours",
  "operatingSystem",
  "position",
  "price",
  "priceCurrency",
  "query-input",
  "sameAs",
  "telephone",
  "termCode",
  "thumbnailUrl",
  "url",
]);

function isProtectedJsonLdValue(key, value) {
  if (JSON_LD_PROTECTED_KEYS.has(key)) return true;
  if (/^(?:https?:|mailto:|tel:|\/)/i.test(value)) return true;
  if (/^\d{4}-\d{2}-\d{2}(?:T.*)?$/.test(value)) return true;
  if (/^[A-Z0-9][A-Z0-9._/-]{1,15}$/.test(value)) return true;
  if (/^[+\d][\d\s().-]+$/.test(value)) return true;
  return false;
}

function normalizeJsonLdValue(value, key = "") {
  if (Array.isArray(value)) return value.map((item) => normalizeJsonLdValue(item, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, normalizeJsonLdValue(child, childKey)]));
  }
  if (typeof value !== "string") return value;

  if (key === "inLanguage" || key === "availableLanguage") {
    if (/^(?:Romanian|română|ro|ro-RO)$/i.test(value.trim())) return "ro-RO";
  }
  if (isProtectedJsonLdValue(key, value)) return value;
  return normalizeRomanianCopy(value);
}

function normalizeJsonLdScripts(html) {
  let changed = false;
  const errors = [];
  let blockIndex = 0;
  const output = html.replace(
    /(<script\b[^>]*\btype=["']application\/ld\+json["'][^>]*>)([\s\S]*?)(<\/script>)/gi,
    (full, opening, raw, closing) => {
      blockIndex += 1;
      const source = raw.trim();
      if (!source) return full;
      let parsed;
      try {
        parsed = JSON.parse(source);
      } catch (error) {
        errors.push({ blockIndex, message: error.message });
        return full;
      }
      const serialized = serializeJsonLd(normalizeJsonLdValue(parsed));
      const comparableSource = source.replace(/\r\n?/gu, "\n");
      if (serialized === comparableSource) return full;
      changed = true;
      return `${opening}${serialized}${closing}`;
    }
  );
  return { html: output, changed, errors, blocksChecked: blockIndex };
}

function normalizeHtmlCopy(html) {
  const preferredEol = html.includes("\r\n") ? "\r\n" : "\n";
  const jsonLdResult = normalizeJsonLdScripts(html);
  const $ = cheerio.load(jsonLdResult.html, { decodeEntities: false });
  let domChanged = false;

  function normalizeValue(value) {
    const next = normalizeRomanianCopy(value);
    if (next !== value) domChanged = true;
    return next;
  }

  $("title").each((_, element) => {
    const current = $(element).text();
    const next = normalizeValue(current);
    if (next !== current) $(element).text(next);
  });

  $("meta[name='description'], meta[property='og:title'], meta[property='og:description'], meta[name='twitter:title'], meta[name='twitter:description']").each((_, element) => {
    const content = $(element).attr("content");
    if (!content) return;
    const next = normalizeValue(content);
    if (next !== content) $(element).attr("content", next);
  });

  $("[aria-label], [alt], [title], [placeholder]").each((_, element) => {
    for (const attr of ["aria-label", "alt", "title", "placeholder"]) {
      const value = $(element).attr(attr);
      if (!value) continue;
      const next = normalizeValue(value);
      if (next !== value) $(element).attr(attr, next);
    }
  });

  $("body")
    .find("*")
    .addBack()
    .contents()
    .each((_, node) => {
      if (node.type !== "text") return;
      const parent = node.parent && node.parent.name ? String(node.parent.name).toLowerCase() : "";
      if (["script", "style", "code", "pre", "textarea"].includes(parent)) return;
      const next = normalizeValue(node.data);
      if (next !== node.data) node.data = next;
    });

  const output = (domChanged ? $.html() : jsonLdResult.html).replace(/[ \t]+$/gm, "");
  return preferredEol === "\r\n" ? output.replace(/\r?\n/g, "\r\n") : output;
}

function* walkHtml(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (target.toLowerCase().endsWith(".html")) yield target;
    return;
  }

  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) {
      yield* walkHtml(full);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".html")) {
      yield full;
    }
  }
}

function main() {
  const changed = [];
  const jsonLdChanged = [];
  const jsonLdErrors = [];
  for (const file of walkHtml(TARGET)) {
    const input = fs.readFileSync(file, "utf8");
    const jsonLdAudit = normalizeJsonLdScripts(input);
    const relative = path.relative(ROOT, file);
    if (jsonLdAudit.changed) jsonLdChanged.push(relative);
    for (const error of jsonLdAudit.errors) jsonLdErrors.push({ file: relative, ...error });
    const output = normalizeHtmlCopy(input);
    const semanticInput = input.replace(/\r\n/g, "\n");
    const semanticOutput = output.replace(/\r\n/g, "\n");
    if (semanticInput === semanticOutput) continue;
    changed.push(relative);
    if (!CHECK_ONLY) fs.writeFileSync(file, output, "utf8");
  }

  if (jsonLdErrors.length) {
    console.error(`Invalid JSON-LD detected in ${jsonLdErrors.length} block(s):`);
    for (const error of jsonLdErrors) console.error(` - ${error.file} block ${error.blockIndex}: ${error.message}`);
  }

  if (CHECK_ONLY && changed.length) {
    console.error(`Romanian copy issues detected in ${changed.length} file(s):`);
    const jsonLdFiles = new Set(jsonLdChanged);
    for (const file of changed) console.error(` - ${file}${jsonLdFiles.has(file) ? " [JSON-LD]" : ""}`);
  }

  if (jsonLdErrors.length || (CHECK_ONLY && changed.length)) {
    process.exitCode = 1;
    return;
  }

  console.log(
    CHECK_ONLY
      ? "Romanian copy check passed."
      : `Romanian copy normalized in ${changed.length} file(s).`
  );
}

if (require.main === module) main();

module.exports = {
  ROMANIAN_COPY_REPLACEMENTS,
  normalizeHtmlCopy,
  normalizeJsonLdScripts,
  normalizeJsonLdValue,
  normalizeRomanianCopy,
};
