# Logo vectorial pentru navbar — 6 septembrie 2026

Sursa este imaginea originală furnizată de utilizator, păstrată în `assets/faber-navbar-20260906.jpg`. SVG-ul furnizat ulterior conținea numai un dreptunghi de fundal; contururile au fost vectorizate din imagine la cererea utilizatorului.

Cele trei componente sunt monograma, cuvântul FABER și inscripția completă ATELIER DE CONSULTANȚĂ, inclusiv diacriticele. Nu sunt folosite fonturi de substituție, imagini raster încorporate sau text generat. Spațiile interioare ale literelor sunt păstrate prin regula de umplere evenodd. Înaintea trasării au fost reduse artefactele de compresie JPEG printr-o filtrare de 0,75 px; curbele sunt o reconstrucție vectorială, nu fișierul vectorial original al designerului.

- `assets/faber-navbar-vector.svg`: compoziția orizontală, fundal transparent, monogramă `#f5a623`, litere `#ffffff`, pentru navbarul bleumarin `#0d1f3c`.
- `assets/faber-navbar-vector-compact.svg`: compoziția pentru ecrane de maximum 600 px. Cele trei contururi sunt identice cu cele ale variantei orizontale; se schimbă numai amplasarea și scalarea. Inscripția este mutată sub FABER pentru lizibilitate.
- Au fost eliminate filtrele CSS de contrast și modul de amestecare folosite pentru vechiul JPEG. Resursele CSS/JS au o versiune nouă pentru cache.

Verificări: control vizual la rezoluție mare și în navbar la 320/1366 px; test de navigare la 320, 360, 390, 768, 1024 și 1366 px; încărcare SVG, dimensiuni, încadrare, navigare cu tastatura; identitatea contururilor între cele două compoziții; propagarea antetului în 183 de fișiere HTML publice; regresia celor șapte pagini de programe; validarea pachetului Cloudflare. Testele menționate au trecut. Publicarea este verificată separat pe domeniul public după deploy.

## Refinement after desktop/mobile review

The navbar now uses `faber-navbar-refined.svg` at 224 × 56 CSS pixels on desktop and mobile. The original monogram and FABER path contours are preserved. The complete descriptor, including Romanian diacritics, was rebuilt as clean vector outlines for legibility; no embedded raster or runtime font is required. Colors remain gold #f5a623 and white on navy.

Removed homepage-specific navbar padding/height overrides. Below 600px the compact CTA is omitted from the top bar to reserve room for the complete logo and 44px menu button; the mobile menu retains its CTA. Updated asset versions prevent stale layout CSS.

Validation: navigation keyboard/focus contract at six widths (320–1366px); all 183 source navbars share the asset; seven program SEO regression checks; real homepage and e-drive rendering at 320, 390, 768 and 1366px with DPR 2. Logo dimensions were 224 × 56 with no clipping, foreground filter or menu overlap in all eight cases. Cloudflare assets validation passed.
