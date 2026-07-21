# Hartă de consolidare URL — pentru aprobare

Data analizei: 2026-07-21

GSC Performance disponibil: 2026-04-11–2026-07-10

Stare globală: **APROBARE_UMANĂ_NECESARĂ**

Redirecturi/canonicale implementate prin acest task: **niciunul**

## Limitări care blochează decizia finală

- Conectorul Ahrefs necesar skill-ului nu este disponibil; backlink-urile sunt `DE_VALIDAT_UMAN` pentru fiecare URL.
- Repository-ul nu conține un export de conversii analytics/CRM pe URL; conversiile sunt `DE_VALIDAT_UMAN`.
- GSC Performance este istoric și nu confirmă indexarea prezentă. Este necesar URL Inspection pentru fiecare sursă și țintă.
- Paginile Digitalizare, DR12 și DR14 sunt local `noindex` și absente din sitemap din cauza porților factuale P0.02. Niciun redirect nu trebuie activat către ele cât timp ținta nu este publicabilă/indexabilă.

## Decizii propuse

| Source | Target / acțiune | Semnal principal | Conținut de migrat | Risc | Stare |
|---|---|---|---|---|---|
| `/fonduri-europene` | **KEEP principal** | 0 clicuri / 87 impresii; 503 linkuri interne; hub general | Primește numai rezumate generale utile | Poate deveni prea larg și concura cu pagina 2026 | APROBARE_UMANĂ_NECESARĂ |
| `/fonduri-nerambursabile` | **KEEP cu rol unic condiționat** | 0/185; poziție 37,63; similaritate lexicală doar 16%; 17 H2 distincte | Rămâne exclusiv ghid grant, cash-flow, contribuție, rambursare și obligații | Fără KPI distinct poate rămâne o pagină slabă; atunci se mută conținutul unic și se face 301 la `/fonduri-europene` | APROBARE_UMANĂ_NECESARĂ |
| `/digitalizare-imm` | **KEEP candidat principal** | 1/248; țintă cerută de brief; momentan noindex | Primește exemple, FAQ și explicații validate | Nu poate primi redirect cât timp este pending/noindex | APROBARE_UMANĂ_NECESARĂ |
| `/granturi-digitalizare-imm` | **MERGE 301 condiționat** → `/digitalizare-imm` | 2/65, poziție 6,46; conținutul public curent are 74% similaritate și este redus de poarta factuală | Tipuri de grant, ERP/CRM/cloud, cheltuieli și FAQ unice validate | Are semnal organic mai bun decât ținta; trebuie GSC Page+Query și backlink înainte de merge | APROBARE_UMANĂ_NECESARĂ |
| `/consultanta-fonduri-europene` | **KEEP comercial principal** | 0/111, poziție 6,41; 510 linkuri interne | Primește criterii/dovezi/FAQ unice | Importul integral ar dilua landing-ul | APROBARE_UMANĂ_NECESARĂ |
| `/firma-consultanta-fonduri-europene` | **MERGE 301 condiționat** → `/consultanta-fonduri-europene` | 0/20, poziție 20,3; există și `/cum-alegi-consultant-fonduri-europene` | Criterii de alegere, întrebări pentru furnizor, limitele serviciului | Poate pierde un rol de ghid numai dacă acel rol nu este preluat de pagina „cum alegi” | APROBARE_UMANĂ_NECESARĂ |
| `/eligibilitate-fonduri-europene` | **KEEP unic: ghid/checklist** | 0/10, poziție 6,2; 8 H2 distincte | Criterii, checklist și autoevaluare | Rolurile actuale sunt parțial suprapuse | APROBARE_UMANĂ_NECESARĂ |
| `/verificare-eligibilitate-fonduri-europene` | **KEEP unic: serviciu/proces/formular** | 1/66, poziție 7,64; 142 linkuri interne | Proces, date necesare, livrabil, limite și CTA | Trebuie eliminate checklisturile duplicate și măsurate conversiile | APROBARE_UMANĂ_NECESARĂ |
| `/politica-de-confidentialitate` | **KEEP legal principal** | 0/18; URL cerut drept canonic legal | Primește procedura și drepturile unice aprobate din `/gdpr` | Datele operatorului sunt încă blocate juridic | APROBARE_UMANĂ_NECESARĂ |
| `/gdpr` | **MERGE 301 după aviz juridic** → `/politica-de-confidentialitate` | 0/24; două pagini legale self-canonical | Drepturi, termene, canale și istoric aprobate | Redirect prematur către un text incomplet/neavizat | APROBARE_UMANĂ_NECESARĂ + AVIZ_JURIDIC |
| `/dr12-afir` | **KEEP program principal, hold** | 32/1.008, poziție 8,1; noindex factual temporar | Numai faptele canonice ale programului | Ținta nu este încă aprobată factual | APROBARE_UMANĂ_NECESARĂ |
| `/dr-12-afir-instalarea-tinerilor-fermieri` | **KEEP suport temporar; nu decide merge** | 0/47, poziție 17,3; conținutul curent este redus de hold | Condiții, documente, exemple și FAQ, dacă ulterior se aprobă merge | Lipsesc backlink, conversii și query-uri pe pagină | APROBARE_UMANĂ_NECESARĂ |
| `/dr14` | **KEEP program principal, hold** | 27/734, poziție 7,76; noindex factual temporar | Numai faptele canonice ale programului | Nu destabiliza pagina cu semnal organic înainte de aprobarea factuală | APROBARE_UMANĂ_NECESARĂ |
| `/dr-14-afir-conditii-eligibilitate-greseli-frecvente` | **KEEP suport condiționat** | 3/214, poziție 9,94 — semnal organic propriu | Greșeli, riscuri, exemple și checklist | Un 301 fără backlink/query poate pierde clusterul deja vizibil | APROBARE_UMANĂ_NECESARĂ |

## Ordine propusă după aprobare

1. Export GSC Page+Query și backlink-uri pentru toate cele 14 URL-uri; export conversii pe `page_path`.
2. Aprobarea rolurilor unice pentru fonduri nerambursabile și eligibilitate.
3. Validarea factuală/indexabilitatea țintei Digitalizare.
4. Migrarea conținutului pentru perechile aprobate, apoi actualizarea linkurilor interne/canonical/sitemap.
5. Implementarea fiecărui 301 într-un singur hop și QA pentru status, canonical, JSON-LD și GSC.
6. `/gdpr` se procesează numai după avizul juridic.

## Semnături necesare

| Rol | Nume | Decizie | Data | Observații |
|---|---|---|---|---|
| Proprietar / decident business | DE_VALIDAT_UMAN | ☐ aprobă ☐ cere modificări ☐ respinge | DE_VALIDAT_UMAN | |
| SEO lead | DE_VALIDAT_UMAN | ☐ aprobă ☐ cere modificări ☐ respinge | DE_VALIDAT_UMAN | |
| Consultant FABER — Digitalizare/DR12/DR14 | DE_VALIDAT_UMAN | ☐ aprobă ☐ cere modificări ☐ respinge | DE_VALIDAT_UMAN | |
| Jurist — exclusiv perechea GDPR | DE_VALIDAT_UMAN | ☐ aprobă ☐ cere modificări ☐ respinge | DE_VALIDAT_UMAN | |

Nicio bifă nu se completează automat. Implementarea redirecturilor este un task separat după aprobarea nominală.
