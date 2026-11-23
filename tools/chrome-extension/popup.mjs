import { calendarUrl, parseCalendar, normalize, isPast, deadlineLabel, statusFor, canExport, makeCalendarFile } from "./calendar.mjs";

const ui = Object.fromEntries(
  ["search", "audience", "region", "programs", "feedback", "results", "empty", "refresh", "calendar-link", "program-template"]
    .map((id) => [id, document.getElementById(id)])
);
const cacheKey = "calendar-cache-v1";
const favoritePrefix = "favorite:";
const favorites = new Set();
let programs = [];
let isCached = true;
let fetchedAt = null;

const audiencePatterns = {
  business: /\bimm\b|imm-uri|intreprinder|transportatori|societat|companii/,
  farming: /fermier|cooperativ|agricol|exploata|crescatori|productori/,
  public: /\buat\b|entitat.{1,3} public|instituti.{1,3} public/
};

function audienceMatches(program, category) {
  if (!category) return true;
  const audience = normalize(program.audience);
  if (category === "other") return Object.values(audiencePatterns).every((pattern) => !pattern.test(audience));
  return audiencePatterns[category].test(audience);
}

function siteLink(href) {
  const url = new URL(href);
  url.searchParams.set("utm_source", "chrome_extension");
  url.searchParams.set("utm_medium", "referral");
  url.searchParams.set("utm_campaign", "calendar_faber");
  return url.href;
}

function render(focusFavorite) {
  const now = new Date();
  const view = document.querySelector('input[name="view"]:checked').value;
  const query = normalize(ui.search.value).trim().split(/\s+/).filter(Boolean);
  const future = (program) => ["submission", "preparation"].includes(program.phase)
    ? program.deadlines.filter((deadline) => !deadline.closed && !isPast(deadline.date, now))
    : [];
  const options = programs.filter((program) => {
    if (view === "favorites" && !favorites.has(program.id)) return false;
    if (view === "upcoming" && !future(program).length) return false;
    if (!audienceMatches(program, ui.audience.value)) return false;
    if (ui.region.value && ui.region.value !== program.region) return false;
    const searchable = normalize([program.title, program.audience, program.region, ...program.deadlines.map(({ component }) => component)].join(" "));
    return query.every((word) => searchable.includes(word));
  });
  if (view === "upcoming") {
    const next = (program) => Math.min(...future(program).map(({ date }) => Date.parse(date)));
    options.sort((a, b) => next(a) - next(b));
  }
  const list = document.createDocumentFragment();
  for (const program of options) list.append(renderProgram(program, now));
  const scrollTop = ui.programs.scrollTop;
  ui.programs.replaceChildren(list);
  ui.programs.scrollTop = scrollTop;
  if (focusFavorite) {
    const button = ui.programs.querySelector(`[data-favorite-id="${CSS.escape(focusFavorite)}"]`);
    (button ?? document.querySelector('input[name="view"]:checked')).focus({ preventScroll: true });
  }
  ui.results.textContent = programs.length ? `${options.length} din ${programs.length} programe` : "";
  ui.empty.hidden = !programs.length || !!options.length;
  ui.empty.textContent = view === "favorites" && !favorites.size
    ? "Salvează un program cu steluța pentru a-l găsi aici."
    : "Niciun program nu corespunde filtrelor selectate.";
}

function renderProgram(program, now) {
  const row = ui["program-template"].content.cloneNode(true);
  const [state, label] = statusFor(program, now, isCached);
  const status = row.querySelector(".status");
  status.textContent = label;
  status.dataset.state = state;
  const favorite = row.querySelector(".favorite");
  favorite.dataset.favoriteId = program.id;
  favorite.setAttribute("aria-label", `Favorit: ${program.title}`);
  favorite.setAttribute("aria-pressed", String(favorites.has(program.id)));
  favorite.firstElementChild.textContent = favorites.has(program.id) ? "★" : "☆";
  favorite.addEventListener("click", () => toggleFavorite(program.id, favorite));
  row.querySelector("h2").textContent = program.title;
  row.querySelector(".program-details").textContent = [program.audience, program.region].filter(Boolean).join(" · ");
  row.querySelector(".official").href = program.source;
  row.querySelector(".guide").href = siteLink(program.page);
  const verified = row.querySelector(".verified");
  verified.hidden = !program.verified;
  if (program.verified) verified.textContent = `Verificare în calendar: ${deadlineLabel(program.verified)}`;

  const deadlines = row.querySelector(".deadlines");
  for (const deadline of program.deadlines) {
    const item = document.createElement("li");
    const caption = document.createElement("span");
    const time = document.createElement("time");
    const label = deadline.component || (deadline.kind === "consultation" ? "Consultare" : "Termen");
    caption.append(label + " · ", time);
    time.dateTime = deadline.date;
    time.textContent = deadlineLabel(deadline.date);
    item.append(caption);
    item.toggleAttribute("data-expired", deadline.closed || isPast(deadline.date, now));
    if (deadline.closed) caption.append(" · închis");
    if (canExport(deadline, program, now, isCached)) {
      const download = document.createElement("button");
      download.type = "button";
      download.textContent = "Descarcă .ics";
      download.setAttribute("aria-label", `Descarcă termenul ${program.title} ${deadline.component} în format ICS`.replace(/\s+/g, " "));
      download.addEventListener("click", () => downloadDeadline(program, deadline));
      item.append(download);
    }
    deadlines.append(item);
  }
  return row;
}

async function toggleFavorite(id, button) {
  button.disabled = true;
  try {
    const key = favoritePrefix + id;
    if (favorites.has(id)) {
      await chrome.storage.local.remove(key);
      favorites.delete(id);
    } else {
      await chrome.storage.local.set({ [key]: true });
      favorites.add(id);
    }
    render(id);
  } catch {
    ui.feedback.textContent = "Preferința nu a putut fi salvată. Încearcă din nou.";
    button.disabled = false;
  }
}

function downloadDeadline(program, deadline) {
  const now = new Date();
  if (!canExport(deadline, program, now, isCached)) {
    render();
    return;
  }
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([makeCalendarFile(program, deadline, now)], { type: "text/calendar;charset=utf-8" }));
  const url = link.href;
  link.download = `${program.id}-${deadline.date.slice(0, 10)}.ics`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function setPrograms(items) {
  const currentRegion = ui.region.value;
  const regions = [...new Set(items.map(({ region }) => region).filter(Boolean))].sort((a, b) => a.localeCompare(b, "ro"));
  ui.region.replaceChildren(new Option("Toate zonele", ""), ...regions.map((region) => new Option(region, region)));
  if (regions.includes(currentRegion)) ui.region.value = currentRegion;
  programs = items;
  render();
}

async function refresh() {
  ui.refresh.disabled = true;
  ui.feedback.textContent = "Se citește calendarul FABER…";
  try {
    const response = await fetch(calendarUrl, {
      credentials: "omit", redirect: "error", cache: "no-cache", signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) throw new Error("Calendar indisponibil.");
    const items = parseCalendar(await response.text());
    isCached = false;
    fetchedAt = new Date().toISOString();
    setPrograms(items);
    ui.feedback.textContent = "Calendarul FABER a fost actualizat.";
    await chrome.storage.local.set({ [cacheKey]: { programs: items, fetchedAt } }).catch(() => {});
  } catch {
    isCached = true;
    render();
    ui.feedback.textContent = programs.length
      ? `Calendar indisponibil. Copie locală${fetchedAt ? " din " + deadlineLabel(fetchedAt) : ""}. Verifică sursa.`
      : "Calendarul este momentan indisponibil. Apasă Actualizează pentru a reîncerca.";
  } finally {
    ui.refresh.disabled = false;
  }
}

async function initialize() {
  const stored = await chrome.storage.local.get(null).catch(() => ({}));
  for (const key of Object.keys(stored)) {
    if (key.startsWith(favoritePrefix) && stored[key] === true) favorites.add(key.slice(favoritePrefix.length));
  }
  const items = stored[cacheKey]?.programs;
  const storedDate = stored[cacheKey]?.fetchedAt;
  if (Number.isFinite(Date.parse(storedDate))) fetchedAt = storedDate;
  if (Array.isArray(items) && items.length) setPrograms(items);
  await refresh();
}

ui["calendar-link"].href = siteLink(calendarUrl);
ui.search.addEventListener("input", () => render());
ui.audience.addEventListener("change", () => render());
ui.region.addEventListener("change", () => render());
document.querySelector(".views").addEventListener("change", () => render());
ui.refresh.addEventListener("click", refresh);
initialize();
