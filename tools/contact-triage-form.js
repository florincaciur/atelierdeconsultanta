"use strict";

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function programOptions(programs, aliasesByProgram = {}) {
  const ordered = [...programs]
    .filter((program) => program && program.slug && program.shortName && program.pageUrl)
    .sort((left, right) => {
      const leftOrder = Number(left.presentation?.order ?? 999);
      const rightOrder = Number(right.presentation?.order ?? 999);
      return leftOrder - rightOrder || left.shortName.localeCompare(right.shortName, "ro");
    });

  return ordered.map((program) => {
    const aliases = (aliasesByProgram[program.slug] || [])
      .filter((route) => typeof route === "string" && route.startsWith("/") && route !== program.pageUrl)
      .join("|");
    return `<option value="${escapeHtml(program.slug)}" data-program-family="${escapeHtml(program.family || "")}" data-page-url="${escapeHtml(program.pageUrl)}"${aliases ? ` data-page-aliases="${escapeHtml(aliases)}"` : ""}>${escapeHtml(program.shortName)}</option>`;
  }).join("\n");
}

function renderContactTriageLayout(programs, aliasesByProgram = {}) {
  return `
      <div class="contact-layout contact-triage-layout">
        <section class="contact-form-panel" aria-labelledby="contact-form-title">
          <div class="contact-triage-heading">
            <span class="core-kicker">Triage inițial</span>
            <h2 id="contact-form-title">Spune-ne pe scurt ce vrei să realizezi</h2>
            <p id="contact-form-intro">Pasul 1 cere patru răspunsuri operaționale și confirmarea citirii informării. Detaliile din pasul 2 sunt opționale.</p>
          </div>

          <form id="contact-triage-form" class="contact-form contact-triage" action="/api/contact-triage" method="post" accept-charset="UTF-8" data-analytics-form="contact_triage" data-analytics-form-version="short_v1" data-analytics-component="public_form" data-clarity-mask="true" data-legal-copy-state="pending_validation" aria-describedby="contact-form-intro">
            <input type="hidden" name="schema_version" value="1.0.0">
            <input type="hidden" name="lead_id" value="">
            <input type="hidden" name="form_started_at" value="">
            <input type="hidden" name="page_url" value="/contact">
            <input type="hidden" name="source_page" value="">
            <input type="hidden" name="referrer_path" value="">
            <input type="hidden" name="program_context" value="">
            <input type="hidden" name="program_family" value="">
            <input type="hidden" name="source_channel" value="">
            <input type="hidden" name="utm_source" value="">
            <input type="hidden" name="utm_medium" value="">
            <input type="hidden" name="utm_campaign" value="">
            <input type="hidden" name="utm_term" value="">
            <input type="hidden" name="utm_content" value="">
            <input type="hidden" name="landing_referrer" value="">
            <input type="hidden" name="landing_page_path" value="">
            <input type="hidden" name="calculator_so_result" value="">

            <div class="contact-honeypot" aria-hidden="true" hidden>
              <label for="contact-website">Nu completa acest câmp</label>
              <input id="contact-website" type="text" name="website" tabindex="-1" autocomplete="off" aria-hidden="true">
            </div>

            <div class="contact-form-alert" data-form-alert role="alert" aria-live="assertive" tabindex="-1" hidden>
              <p data-form-alert-message></p>
              <button class="btn btn-secondary" type="button" data-retry-submit hidden>Încearcă din nou</button>
            </div>

            <div class="contact-error-summary" data-error-summary role="alert" aria-labelledby="contact-error-summary-title" tabindex="-1" hidden>
              <h3 id="contact-error-summary-title">Verifică următoarele câmpuri</h3>
              <ul data-error-summary-list></ul>
            </div>

            <section class="contact-form-step" data-form-step="1" aria-labelledby="contact-step-1-title">
              <div class="contact-progress" aria-label="Progres formular">
                <strong id="contact-step-1-title">Pasul 1 din 2</strong>
                <span>aprox. 60–90 secunde</span>
              </div>

              <div class="form-grid">
                <div class="form-group">
                  <label for="contact-applicant-type">Tip solicitant <span aria-hidden="true">*</span></label>
                  <select id="contact-applicant-type" name="applicant_type" required autocomplete="organization-title" aria-describedby="contact-applicant-type-error">
                    <option value="">Alege tipul solicitantului</option>
                    <option value="societate">Societate / IMM</option>
                    <option value="pfa_ii_if">PFA / II / IF</option>
                    <option value="ferma_exploatatie">Fermă / exploatație agricolă</option>
                    <option value="startup">Start-up / firmă în curs de înființare</option>
                    <option value="ong">ONG</option>
                    <option value="institutie_publica">Instituție publică</option>
                    <option value="alta">Alt tip de solicitant</option>
                  </select>
                  <p id="contact-applicant-type-error" class="error-message" data-field-error-for="contact-applicant-type" aria-hidden="true" hidden></p>
                </div>

                <div class="form-group">
                  <label for="contact-location">Județ / localitate <span aria-hidden="true">*</span></label>
                  <input id="contact-location" name="location" type="text" required minlength="2" maxlength="120" autocomplete="address-level2" placeholder="Ex.: Iași, Pașcani" aria-describedby="contact-location-error">
                  <p id="contact-location-error" class="error-message" data-field-error-for="contact-location" aria-hidden="true" hidden></p>
                </div>

                <div class="form-group full">
                  <label for="contact-investment">Ce investiție doriți să realizați? <span aria-hidden="true">*</span></label>
                  <input id="contact-investment" name="investment" type="text" required minlength="5" maxlength="300" autocomplete="off" placeholder="Ex.: utilaje, hală, software sau modernizarea fermei" aria-describedby="contact-investment-help contact-investment-error">
                  <small id="contact-investment-help">Un răspuns scurt este suficient în această etapă.</small>
                  <p id="contact-investment-error" class="error-message" data-field-error-for="contact-investment" aria-hidden="true" hidden></p>
                </div>

                <fieldset class="form-group full contact-method" aria-describedby="contact-method-help contact-method-error">
                  <legend>Email sau telefon <span aria-hidden="true">*</span></legend>
                  <p id="contact-method-help" class="field-help">Completează cel puțin unul. Nu sunt obligatorii ambele.</p>
                  <div class="contact-method-grid">
                    <div>
                      <label for="contact-email">Email</label>
                      <input id="contact-email" name="email" type="email" maxlength="254" autocomplete="email" inputmode="email" placeholder="nume@exemplu.ro" aria-describedby="contact-method-help contact-method-error">
                    </div>
                    <div>
                      <label for="contact-phone">Telefon</label>
                      <input id="contact-phone" name="phone" type="tel" maxlength="30" autocomplete="tel" inputmode="tel" placeholder="07xx xxx xxx" aria-describedby="contact-method-help contact-method-error">
                    </div>
                  </div>
                  <p id="contact-method-error" class="error-message" data-contact-method-error aria-hidden="true" hidden>Completează o adresă de email validă sau un număr de telefon.</p>
                </fieldset>

                <details class="form-group full contact-optional">
                  <summary id="contact-optional-summary">Date opționale, dacă le cunoști</summary>
                  <div class="form-grid contact-optional-grid">
                    <div class="form-group full">
                      <label for="contact-program">Program vizat <span class="optional-label">(opțional)</span></label>
                      <select id="contact-program" name="program_slug">
                        <option value="unknown">Nu știu încă</option>
${programOptions(programs, aliasesByProgram)}
                      </select>
                    </div>
                    <div class="form-group">
                      <label for="contact-caen-so">CAEN sau dimensiune economică SO <span class="optional-label">(opțional)</span></label>
                      <input id="contact-caen-so" name="caen_or_so" type="text" value="Nu știu încă" maxlength="120" autocomplete="off" list="contact-unknown-options">
                    </div>
                    <div class="form-group">
                      <label for="contact-budget">Buget estimat / contribuție proprie <span class="optional-label">(opțional)</span></label>
                      <input id="contact-budget" name="budget_estimate" type="text" value="Nu știu încă" maxlength="160" autocomplete="off" list="contact-unknown-options">
                    </div>
                    <datalist id="contact-unknown-options"><option value="Nu știu încă"></option></datalist>
                  </div>
                </details>

                <div class="form-group full consent-row">
                  <input id="privacy-notice-acknowledged" name="privacy_notice_acknowledged" type="checkbox" value="true" required aria-describedby="privacy-legal-copy-note privacy-notice-error">
                  <label class="consent-label" for="privacy-notice-acknowledged">Confirm că am citit informarea privind prelucrarea datelor din <a href="/politica-de-confidentialitate" target="_blank" rel="noopener">Politica de confidențialitate</a>. <span aria-hidden="true">*</span></label>
                  <p id="privacy-legal-copy-note" class="legal-copy-note" data-legal-copy-note>Formularea este pregătită tehnic și rămâne supusă avizului juridic înainte de publicare.</p>
                  <p id="privacy-notice-error" class="error-message" data-field-error-for="privacy-notice-acknowledged" aria-hidden="true" hidden></p>
                </div>
              </div>

              <div class="contact-actions contact-progressive-actions" hidden>
                <button class="btn btn-primary" type="button" data-action="review-short">Verifică și trimite</button>
                <button class="btn btn-secondary" type="button" data-action="add-details">Adaugă detalii</button>
              </div>
            </section>

            <section class="contact-form-step" data-form-step="2" aria-labelledby="contact-step-2-title">
              <div class="contact-progress" aria-label="Progres formular">
                <strong id="contact-step-2-title">Pasul 2 din 2</strong>
                <span>opțional</span>
              </div>
              <p>Poți trimite solicitarea fără aceste detalii. Nu introduce parole, date medicale sau alte date sensibile.</p>
              <div class="form-grid">
                <div class="form-group full">
                  <label for="contact-description">Descriere extinsă <span class="optional-label">(opțional)</span></label>
                  <textarea id="contact-description" name="extended_description" maxlength="3000" rows="5" placeholder="Context, obiective și constrângeri relevante"></textarea>
                </div>
                <div class="form-group full">
                  <label for="contact-documents">Ce documente aveți disponibile? <span class="optional-label">(opțional)</span></label>
                  <textarea id="contact-documents" name="documents_summary" maxlength="1000" rows="3" placeholder="Ex.: certificat constatator, bilanț, acte spațiu. Documentele se transmit ulterior prin canalul stabilit."></textarea>
                </div>
                <div class="form-group full">
                  <label for="contact-expenses">Buget / listă de cheltuieli <span class="optional-label">(opțional)</span></label>
                  <textarea id="contact-expenses" name="expenses_summary" maxlength="1500" rows="3" placeholder="Principalele achiziții și valorile aproximative, dacă sunt cunoscute"></textarea>
                </div>
                <div class="form-group">
                  <label for="contact-preference">Preferință de contact <span class="optional-label">(opțional)</span></label>
                  <select id="contact-preference" name="contact_preference">
                    <option value="no_preference">Fără preferință</option>
                    <option value="email">Email</option>
                    <option value="phone">Telefon</option>
                  </select>
                </div>
              </div>
              <div class="contact-actions contact-progressive-actions" hidden>
                <button class="btn btn-secondary" type="button" data-action="back-to-step-1">Înapoi la pasul 1</button>
                <button class="btn btn-primary" type="button" data-action="review-full">Vezi rezumatul</button>
              </div>
            </section>

            <section class="contact-form-step contact-summary" data-form-summary aria-labelledby="contact-summary-title" hidden>
              <div class="contact-progress">
                <strong id="contact-summary-title">Rezumat înainte de trimitere</strong>
                <span>verifică informațiile</span>
              </div>
              <dl data-summary-list></dl>
              <div class="contact-actions">
                <button class="btn btn-secondary" type="button" data-action="edit-form">Modifică</button>
                <button class="btn btn-primary" type="submit" data-final-submit>
                  <span data-submit-label>Trimite solicitarea</span>
                  <span class="contact-submit-spinner" data-submit-spinner aria-hidden="true" hidden></span>
                </button>
                <span class="contact-submit-status" data-submit-status aria-live="polite"></span>
              </div>
            </section>

            <div class="contact-actions contact-no-js-submit">
              <button class="btn btn-primary" type="submit">Trimite solicitarea</button>
              <small>Fără JavaScript, ambele etape sunt afișate și validate din nou pe server.</small>
            </div>
          </form>

          <section class="contact-success" data-form-success role="status" aria-live="polite" aria-atomic="true" tabindex="-1" hidden>
            <h2>Solicitarea a fost trimisă</h2>
            <p>Următorul pas este citirea contextului și stabilirea informațiilor sau documentelor care mai trebuie verificate. Confirmarea nu reprezintă un verdict de eligibilitate și nu promite un termen de răspuns.</p>
          </section>
        </section>

        <aside class="contact-note" aria-labelledby="contact-note-title">
          <h2 id="contact-note-title">Ce ne ajută să răspundem util</h2>
          <p>Scrie concret ce vrei să cumperi, să construiești sau să schimbi. Programul, CAEN-ul și bugetul pot rămâne „Nu știu încă”.</p>
          <ul>
            <li>forma solicitantului;</li>
            <li>județul sau localitatea investiției;</li>
            <li>investiția descrisă într-o propoziție;</li>
            <li>un singur canal de răspuns: email sau telefon;</li>
            <li>detalii și documente numai dacă sunt deja disponibile.</li>
          </ul>
          <p class="contact-note__privacy"><strong>Nu trimite date sensibile în formular.</strong> Pentru documente, stabilim ulterior canalul potrivit.</p>
        </aside>
      </div>`;
}

module.exports = { renderContactTriageLayout };
