# FABER — sistem vizual P1.07

Versiune: `p1.07-v1` · sursă canonică: `config/design-system.json` · implementare: `assets/design-system.css`.

Pilotul este limitat prin `data-design-system="p1_07"` la homepage, Contact și AFIR Autoconsum Agroalimentar. Nu este un rebranding și nu reprezintă încă un rollout general.

## Token-uri

| Grup | Token-uri principale | Regulă |
|---|---|---|
| Culoare | `background`, `surface`, `text`, `muted`, `border`, `accent`, `success`, `warning`, `closed`, `focus` | portocaliul este rezervat CTA-urilor, linkurilor și accentelor scurte; nu se folosește pentru corpuri lungi |
| Tipografie | body `17px/1.65`, H1/H2/H3 responsive, măsură `68ch` | titlurile au contrast și spațiere, corpul rămâne lizibil la zoom |
| Spațiere | 4, 8, 12, 16, 24, 32, 48, 64, 96 px | se folosește scala, nu valori izolate |
| Formă | raze 8, 12, 18 px și pill | 18 px pentru panouri/carduri, 8 px pentru controale |
| Umbre | small, medium, large | umbra nu înlocuiește conturul componentelor |
| Containere | text 68ch, content 760px, wide 1180px, full 1280px | textul lung nu depășește 68ch |

## Stări

- `hover`: schimbă suprafața/conturul, fără să fie singurul indiciu semantic.
- `focus-visible`: outline de 3px, albastru pe fundal deschis și galben pe bleumarin; outline-ul nu schimbă layout-ul.
- `active`: feedback de apăsare de maximum 1px.
- `disabled`: contrast de componentă, cursor indisponibil și fără transformări.
- `loading`: `aria-busy="true"` sau `.is-loading`; spinner-ul este decorativ, iar controlul rămâne descris textual.
- `error`: `aria-invalid="true"`, contur, fundal și mesaj textual; culoarea nu este singurul semnal.
- `prefers-reduced-motion`: animațiile și tranzițiile sunt reduse la aproape zero.

## Statusuri

Textul vine în continuare exclusiv din registrul programelor. Simbolurile sunt redundante vizual:

| Status registru | Model vizual |
|---|---|
| `apel_deschis` | `● Apel deschis` — verde |
| `ghid_aprobat_nedeschis`, `consultare_publica`, `calendar_estimativ` | `◐ …` — galben/maro |
| `apel_inchis`, `arhivat` | `○ …` — gri |

## Exemple de componente

```html
<article class="finantare-card" data-program-status="apel_deschis">
  <span class="finantare-badge">Apel deschis</span>
  <h3>Numele programului</h3>
</article>
```

```html
<button class="btn btn-primary" aria-busy="true" disabled>Se trimite</button>
<input aria-invalid="true" aria-describedby="email-error">
<p id="email-error" class="error-message">Introduceți o adresă validă.</p>
```

```html
<details>
  <summary>Ce trebuie verificat?</summary>
  <p>Conținutul răspunsului.</p>
</details>
```

Sticky CTA este doar definit în contract în această etapă; nu este injectat în paginile pilot deoarece componenta nu exista acolo și taskul nu justifică introducerea unei interacțiuni noi.

## Matrice de audit

| Componentă | Pilot | Contract |
|---|---|---|
| header | toate trei | suprafață bleumarin, focus pe dark, target 44px |
| hero | toate trei | un singur dark dominant, titluri responsive |
| card program | homepage | surface, border, hover/active |
| badge status | homepage + program | simbol + text + culoare |
| tabel | program | header dark, rânduri alternate, border 3:1 |
| accordion | toate trei | summary 44px, focus și open |
| formular | Contact | label existent, focus/error/loading/disabled |
| CTA | toate trei | primary, secondary, active, disabled, loading |
| breadcrumb | Contact + program | link subliniat, current text |
| carousel | homepage | control 44px, stare curentă |
| footer | toate trei | focus/link cu contrast pe dark |
| sticky CTA | absent | contract documentat, fără injectare |

## Rollout

1. Se adaugă ruta în lista `TARGETS` din sincronizator și se aplică atributul de scope.
2. Se rulează `npm run test:design-system`.
3. Se verifică vizual la 320/390/768/1024/1366 px, zoom 200%, tastatură și reduced motion.
4. Se verifică raportul de contrast și componentele detectate.
5. Abia după PASS se extinde scope-ul la următoarea familie de pagini.
