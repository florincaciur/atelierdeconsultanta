export const origin = "https://atelierdeconsultanta.ro";
export const calendarUrl = `${origin}/calendar-fonduri-europene`;
const timeZone = "Europe/Bucharest";
const localDay = new Intl.DateTimeFormat("sv-SE", { timeZone, dateStyle: "short" });
const dayLabel = new Intl.DateTimeFormat("ro-RO", { timeZone: "UTC", day: "numeric", month: "short", year: "numeric" });
const timeLabel = new Intl.DateTimeFormat("ro-RO", { timeZone, day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateOnly = /^\d{4}-\d{2}-\d{2}$/;
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})$/;
const phases = ["submission", "preparation", "implementation", "per_call"];
const encoder = new TextEncoder();

const text = (element) => (element?.textContent ?? "").replace(/\s+/g, " ").trim();
export const normalize = (value) => value.toLowerCase().normalize("NFD").replace(/\p{M}+/gu, "");

function secureUrl(element) {
  const href = element?.getAttribute("href");
  if (!href) return null;
  try {
    const url = new URL(href, calendarUrl);
    return url.protocol === "https:" && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

function dateValue(element) {
  const value = element?.getAttribute("datetime") ?? "";
  return (dateOnly.test(value) || timestamp.test(value)) && Number.isFinite(Date.parse(value)) ? value : null;
}

export function parseCalendar(html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  const rows = template.content.querySelectorAll("#calendar-apeluri .funding-calendar tr[data-calendar-program]");
  const programs = new Map();
  for (const row of rows) {
    const id = row.dataset.calendarProgram;
    const phase = row.closest("tbody")?.dataset.calendarPhase;
    const [heading, audience, region, dates, sources] = row.cells;
    const page = secureUrl(heading?.querySelector("a"));
    const title = text(heading?.querySelector("a"));
    const source = secureUrl(sources?.querySelector("a"));
    if (!/^[a-z0-9-]+$/.test(id) || !phases.includes(phase) || page?.origin !== origin || !title || !source) {
      throw new Error("Structura calendarului s-a schimbat.");
    }
    const times = Array.from(dates.querySelectorAll("time[datetime]"));
    const start = dateValue(times.find((time) => /^deschidere\b/.test(normalize(text(time.closest("p, li"))))));
    const deadlines = times.flatMap((time) => {
      const context = time.closest("p, li");
      const wording = normalize(text(context));
      const date = dateValue(time);
      if (!date || !/\b(inchidere|observatii la ghid pana la)\b/.test(wording)) return [];
      const component = text(context.querySelector("strong"));
      return [{
        date,
        component,
        kind: wording.includes("observatii la ghid") ? "consultation" : "submission",
        closed: /expirat|epuizat|inchisa la/.test(wording)
      }];
    });
    programs.set(id, {
      id, title, phase, start, deadlines,
      audience: text(audience),
      region: text(region),
      verified: dateValue(sources.querySelector("time")),
      source: source.href,
      page: page.href
    });
  }
  if (!programs.size) throw new Error("Calendarul nu conține programe.");
  return [...programs.values()];
}

export function isPast(deadline, now) {
  return dateOnly.test(deadline) ? deadline < localDay.format(now) : Date.parse(deadline) <= now.getTime();
}

export function deadlineLabel(value) {
  const date = new Date(value);
  return dateOnly.test(value) ? dayLabel.format(date) : timeLabel.format(date);
}

export function statusFor(program, now, isCached) {
  if (program.phase === "implementation") return ["post", "După depunere"];
  if (program.phase === "per_call") return ["per-call", "Verifică fiecare apel"];
  const deadlines = program.deadlines.filter((deadline) => deadline.kind === "submission" && !deadline.closed);
  if (deadlines.length && deadlines.every(({ date }) => isPast(date, now))) return ["review", "Termen trecut · de reverificat"];
  const started = !program.start || (dateOnly.test(program.start)
    ? program.start <= localDay.format(now)
    : Date.parse(program.start) <= now.getTime());
  if (program.phase === "submission") {
    return !isCached && deadlines.length && started
      ? ["open", "În depunere"]
      : ["review", "De reverificat"];
  }
  if (!started && !isCached) return ["scheduled", "Programat"];
  return ["review", "De reverificat"];
}

export function canExport(deadline, program, now, isCached) {
  return !isCached && !deadline.closed && !isPast(deadline.date, now)
    && (deadline.kind === "consultation" || ["open", "scheduled"].includes(statusFor(program, now, isCached)[0]));
}

function foldLine(line) {
  let length = 0;
  let result = "";
  for (const character of line) {
    const size = encoder.encode(character).length;
    if (length + size > 75) {
      result += "\r\n ";
      length = 1;
    }
    result += character;
    length += size;
  }
  return result;
}

const escaped = (value) => value.replace(/\\/g, "\\\\").replace(/\r\n|\r|\n/g, "\\n").replace(/([,;])/g, "\\$1");
const compactDate = (value) => value.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

export function makeCalendarFile(program, deadline, now) {
  const label = deadline.kind === "consultation" ? "Consultare" : "Termen de depunere";
  const title = [label + " – " + program.title, deadline.component].filter(Boolean).join(" · ");
  const day = dateOnly.test(deadline.date);
  const start = day ? compactDate(deadline.date) : compactDate(new Date(deadline.date).toISOString());
  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//FABER//Calendar Fonduri Europene//RO",
    "BEGIN:VEVENT",
    `UID:${program.id}-${deadline.kind}-${start}@atelierdeconsultanta.ro`,
    `DTSTAMP:${compactDate(now.toISOString())}`,
    `${day ? "DTSTART;VALUE=DATE" : "DTSTART"}:${start}`,
    `SUMMARY:${escaped(title)}`,
    `DESCRIPTION:${escaped(`Verifică termenul și disponibilitatea înainte de depunere.\nSursa oficială: ${program.source}\nCalendar FABER: ${program.page}`)}`,
    `URL:${program.page}`,
    "END:VEVENT",
    "END:VCALENDAR",
    ""
  ].map(foldLine).join("\r\n");
}
