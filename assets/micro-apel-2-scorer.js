(function (scope) {
  "use strict";

  const CAEN_GROUPS = [
    {
      key: "highTech",
      label: "Producție / Înaltă tehnologie",
      points: 10,
      codes: "2110,2120,2611,2612,2620,2630,2640,2651,2652,2660,2670"
    },
    {
      key: "mediumHigh",
      label: "Producție / Tehnologie medie–înaltă",
      points: 9,
      codes: "2011,2012,2013,2014,2015,2016,2017,2020,2030,2041,2042,2051,2059,2060,2711,2712,2720,2731,2732,2733,2740,2751,2752,2790,2811,2812,2813,2814,2815,2821,2822,2823,2824,2825,2829,2830,2841,2842,2891,2892,2893,2894,2895,2896,2897,2899,2910,2920,2931,2932,3020,3091,3092,3099,3250"
    },
    {
      key: "mediumLow",
      label: "Producție / Tehnologie medie–scăzută",
      points: 7,
      codes: "1820,2211,2212,2221,2222,2223,2224,2225,2226,2311,2312,2313,2314,2315,2320,2331,2332,2341,2342,2343,2344,2345,2351,2352,2361,2362,2363,2364,2365,2366,2370,2391,2399,2410,2420,2431,2432,2433,2434,2441,2442,2443,2444,2445,2451,2452,2453,2454,2511,2512,2521,2522,2540,2551,2552,2553,2561,2562,2563,2591,2592,2593,2594,2599,3011,3012,3311,3312,3313,3314,3315,3316,3317,3319,3320"
    },
    {
      key: "highTechServices",
      label: "Servicii de tehnologie înaltă și intensive în cunoștințe",
      points: 6,
      codes: "5911,5912,5913,5914,5920,6010,6020,6031,6039,6110,6120,6190,6210,6220,6290,6310,6391,6392,7210,7220"
    },
    {
      key: "lowTech",
      label: "Producție / Tehnologie scăzută",
      points: 5,
      codes: "1011,1012,1013,1031,1032,1039,1041,1042,1051,1052,1061,1062,1071,1072,1073,1081,1082,1083,1084,1085,1086,1089,1091,1092,1101,1102,1103,1104,1105,1106,1107,1310,1320,1330,1391,1392,1393,1394,1395,1396,1399,1410,1421,1422,1423,1424,1429,1511,1512,1520,1611,1612,1621,1622,1623,1624,1625,1626,1627,1628,1711,1712,1721,1722,1723,1724,1725,1811,1812,1813,1814,3100,3211,3212,3213,3220,3230,3240,3291,3299"
    },
    {
      key: "marketKnowledge",
      label: "Servicii de piață intensive în cunoștințe",
      points: 4,
      codes: "5010,5020,5030,5040,5110,5121,5122,6910,6920,7010,7020,7111,7112,7120,7311,7312,7320,7330,7411,7412,7413,7414,7420,7430,7491,7499,7810,7820,8001,8009"
    },
    {
      key: "otherKnowledge",
      label: "Alte servicii intensive în cunoștințe",
      points: 3,
      codes: "5811,5812,5813,5819,5821,5829,7500,8510,8520,8531,8532,8533,8540,8551,8552,8553,8559,8561,8569,8610,8621,8622,8623,8691,8692,8693,8694,8695,8696,8697,8699,8710,8720,8730,8791,8799,8810,8891,8899,9011,9012,9013,9020,9031,9039,9111,9112,9121,9122,9130,9141,9142,9311,9312,9313,9319,9321,9329"
    },
    {
      key: "other",
      label: "Alte domenii",
      points: 2,
      codes: "0710,0729,0811,0812,0891,0893,0899,0990,3031,3512,3514,3516,3530,3600,3700,3811,3812,3821,3823,3831,3832,3833,3900,4100,4211,4212,4213,4221,4222,4291,4299,4311,4312,4313,4321,4322,4323,4324,4331,4332,4333,4334,4335,4341,4342,4350,4360,4391,4399,4911,4912,4920,4931,4932,4933,4934,4939,4941,4942,4950,5210,5221,5222,5223,5224,5225,5226,5231,5232,5310,5320,5330,5510,5520,5530,5540,5590,5611,5612,5621,5622,5640,7911,7912,7990,8110,8121,8122,8123,8130,8210,8220,8230,8240,8291,8292,8299,9510,9521,9522,9523,9524,9525,9529,9531,9532,9540,9610,9621,9622,9623,9630,9640,9691,9699"
    }
  ].map(function (group) {
    return Object.assign({}, group, { codes: new Set(group.codes.split(",")) });
  });

  const COUNTY_GROUP = Object.freeze({ bt: "priority", vs: "priority", bc: "standard", nt: "standard", sv: "standard", is: "iasi" });
  const QUALITATIVE_ESTIMATE = 25;
  const OBJECTIVE_MAX = 75;

  function round2(value) {
    return Math.round((Number(value) + 1e-10) * 100) / 100;
  }

  function numberOrNull(value) {
    if (value === "" || value === null || typeof value === "undefined") return null;
    const number = Number(String(value).replace(",", "."));
    return Number.isFinite(number) ? number : null;
  }

  function normalizeCaen(value) {
    const digits = String(value || "").replace(/\D/g, "");
    if (!digits) return "";
    return digits.length === 3 ? "0" + digits : digits;
  }

  function scoreCaen(value) {
    const code = normalizeCaen(value);
    if (code.length !== 4) return { points: null, max: 10, label: "Cod CAEN necompletat", code: code, rejection: false };
    const group = CAEN_GROUPS.find(function (entry) { return entry.codes.has(code); });
    if (!group) return { points: 0, max: 10, label: "Codul nu apare în Anexa 5", code: code, rejection: true };
    return { points: group.points, max: 10, label: group.label, code: code, rejection: false };
  }

  function scoreJobs(value) {
    const jobs = numberOrNull(value);
    if (jobs === null) return null;
    if (jobs >= 3) return 10;
    if (jobs >= 2) return 5;
    return 0;
  }

  function scoreLocation(headquarters, implementation) {
    if (!headquarters || !implementation) return { points: null, max: 3, rejection: false, warning: "Completează ambele județe." };
    if (implementation === "outside") return { points: 0, max: 3, rejection: true, warning: "Un loc de implementare din afara regiunii Nord-Est conduce la respingere." };
    if (headquarters === "outside") return { points: 0, max: 3, rejection: false, warning: "Sediul social din afara regiunii primește 0 puncte; verifică angajamentul de mutare prevăzut de ghid." };
    const headGroup = COUNTY_GROUP[headquarters];
    const implementationGroup = COUNTY_GROUP[implementation];
    if (headGroup === "iasi" || implementationGroup === "iasi") return { points: 0, max: 3, rejection: false, warning: "Prezența județului Iași în combinația evaluată conduce la 0 puncte la subcriteriul 1.3." };
    if (headGroup === "priority" && implementationGroup === "priority") return { points: 3, max: 3, rejection: false, warning: "" };
    return { points: 2, max: 3, rejection: false, warning: "" };
  }

  function scoreContribution(value) {
    const percent = numberOrNull(value);
    if (percent === null) return null;
    if (percent <= 10) return 0;
    if (percent >= 30) return 6;
    return round2(0.3 * percent - 3);
  }

  function scoreGrantTurnover(grantValue, turnoverValue) {
    const grant = numberOrNull(grantValue);
    const turnover = numberOrNull(turnoverValue);
    if (grant === null || turnover === null) return { points: null, ratio: null };
    if (turnover <= 0) return { points: 0, ratio: null };
    const ratio = grant / turnover;
    if (ratio <= 0.5) return { points: 10, ratio: round2(ratio) };
    if (ratio >= 3) return { points: 0, ratio: round2(ratio) };
    return { points: round2(12 - 4 * ratio), ratio: round2(ratio) };
  }

  function scoreProfitability(netProfitValue, turnoverValue) {
    const profit = numberOrNull(netProfitValue);
    const turnover = numberOrNull(turnoverValue);
    if (profit === null || turnover === null) return { points: null, rate: null };
    if (turnover <= 0) return { points: 0, rate: null };
    const rate = profit / turnover * 100;
    if (rate <= 0) return { points: 0, rate: round2(rate) };
    if (rate >= 6) return { points: 7, rate: round2(rate) };
    return { points: round2(1.1667 * rate), rate: round2(rate) };
  }

  function scoreSolvency(assetsValue, debtsValue) {
    const assets = numberOrNull(assetsValue);
    const debts = numberOrNull(debtsValue);
    if (assets === null || debts === null) return { points: null, ratio: null };
    if (debts === 0 && assets > 0) return { points: 7, ratio: Infinity };
    if (debts <= 0) return { points: 0, ratio: null };
    const ratio = assets / debts;
    if (ratio < 1) return { points: 0, ratio: round2(ratio) };
    if (ratio >= 2) return { points: 7, ratio: round2(ratio) };
    return { points: round2(6.93 * ratio - 6.86), ratio: round2(ratio) };
  }

  function scoreAge(value) {
    const date = String(value || "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return { points: null, rejection: false };
    if (date <= "2021-01-01") return { points: 6, rejection: false };
    if (date <= "2022-01-01") return { points: 5, rejection: false };
    if (date <= "2023-01-01") return { points: 4, rejection: false };
    if (date <= "2024-01-01") return { points: 2, rejection: false };
    if (date <= "2025-01-03") return { points: 0, rejection: false };
    return { points: 0, rejection: true };
  }

  function scoreTurnoverGrowth(value2023, value2024, value2025) {
    const ca2023 = numberOrNull(value2023);
    const ca2024 = numberOrNull(value2024);
    const ca2025 = numberOrNull(value2025);
    if ([ca2023, ca2024, ca2025].some(function (value) { return value === null; })) return null;
    const growth2024 = ca2024 > ca2023 && ca2023 > 0;
    const growth2025 = ca2025 > ca2024 && ca2024 > 0;
    return (growth2024 ? 3 : 0) + (growth2025 ? 3 : 0);
  }

  function scoreEmployees(value) {
    const employees = numberOrNull(value);
    if (employees === null) return { points: null, rejection: false };
    if (employees <= 0) return { points: 0, rejection: true };
    if (employees >= 7) return { points: 6, rejection: false };
    if (employees >= 4) return { points: 4, rejection: false };
    if (employees >= 2) return { points: 2, rejection: false };
    return { points: 0, rejection: false };
  }

  function scoreDisadvantagedHire(value) {
    if (!value) return null;
    return value === "yes" ? 4 : 0;
  }

  function calculate(input) {
    const caen = scoreCaen(input.caen);
    const location = scoreLocation(input.headquartersCounty, input.implementationCounty);
    const grantTurnover = scoreGrantTurnover(input.grant, input.turnover2025);
    const profitability = scoreProfitability(input.netProfit2025, input.turnover2025);
    const solvency = scoreSolvency(input.assets2025, input.debts2025);
    const age = scoreAge(input.establishedAt);
    const employees = scoreEmployees(input.employees2025);
    const breakdown = [
      { id: "caen", label: "1.1 Domeniul CAEN", points: caen.points, max: 10, detail: caen.code ? caen.code + " · " + caen.label : caen.label },
      { id: "jobs", label: "1.2 Creșterea numărului mediu de salariați", points: scoreJobs(input.newJobs), max: 10 },
      { id: "location", label: "1.3 Sediu social și loc de implementare", points: location.points, max: 3 },
      { id: "contribution", label: "2.3 Contribuția proprie eligibilă", points: scoreContribution(input.ownContribution), max: 6 },
      { id: "grantTurnover", label: "2.4 Raport AFN / cifra de afaceri", points: grantTurnover.points, max: 10, detail: grantTurnover.ratio === null ? "" : "Raport: " + grantTurnover.ratio },
      { id: "profitability", label: "2.5 Rata profitabilității", points: profitability.points, max: 7, detail: profitability.rate === null ? "" : "RP: " + profitability.rate + "%" },
      { id: "solvency", label: "2.6 Solvabilitatea generală", points: solvency.points, max: 7, detail: solvency.ratio === Infinity ? "RSG: fără datorii" : (solvency.ratio === null ? "" : "RSG: " + solvency.ratio) },
      { id: "age", label: "2.7 Vechimea întreprinderii", points: age.points, max: 6 },
      { id: "turnoverGrowth", label: "2.8 Dinamica cifrei de afaceri", points: scoreTurnoverGrowth(input.turnover2023, input.turnover2024, input.turnover2025), max: 6 },
      { id: "employees", label: "2.9 Numărul mediu de salariați în 2025", points: employees.points, max: 6 },
      { id: "disadvantagedHire", label: "2.10 Angajare lucrător defavorizat / cu handicap", points: scoreDisadvantagedHire(input.disadvantagedHire), max: 4 }
    ];
    const completed = breakdown.filter(function (item) { return item.points !== null; }).length;
    const objectivePoints = round2(breakdown.reduce(function (sum, item) { return sum + (item.points === null ? 0 : item.points); }, 0));
    const estimatedTotal = round2(objectivePoints + QUALITATIVE_ESTIMATE);
    const rejections = [];
    const warnings = [];

    if (caen.rejection) rejections.push("Codul CAEN introdus nu apare în Anexa 5; 0 puncte la 1.1 conduce la respingere.");
    if (location.rejection) rejections.push(location.warning);
    else if (location.warning && location.points !== null) warnings.push(location.warning);
    if (age.rejection) rejections.push("Întreprinderea este înființată după 03.01.2025; 0 puncte la opțiunea 2.7.f conduce la respingere.");
    if (employees.rejection) rejections.push("Întreprinderea nu are salariați în 2025; 0 puncte la opțiunea 2.9.e conduce la respingere.");
    if (numberOrNull(input.ownContribution) !== null && numberOrNull(input.ownContribution) < 10) rejections.push("Contribuția proprie eligibilă este sub minimul de 10%.");
    const grant = numberOrNull(input.grant);
    if (grant !== null && (grant < 100000 || grant > 300000)) rejections.push("Finanțarea nerambursabilă trebuie să fie între 100.000 și 300.000 EUR.");

    const gateLabels = {
      microenterprise: "încadrarea ca microîntreprindere, inclusiv întreprinderile partenere și legate",
      activityHistory: "un an fiscal integral, profit din exploatare pozitiv în 2025 și activitate nesuspendată în 2025–2026",
      fixedAssets: "includerea obligatorie a echipamentelor sau a altor mijloace fixe corporale",
      deMinimis: "plafonul de minimis disponibil la nivelul întreprinderii unice",
      siteRights: "dreptul asupra spațiului pentru implementare și cei 3 ani de durabilitate",
      annexes: "toate anexele obligatorii complete la momentul depunerii",
      cashFlow: "fluxul de numerar net cumulat pozitiv în fiecare dintre cei 3 ani analizați"
    };
    Object.keys(gateLabels).forEach(function (key) {
      if (input[key] === "no") rejections.push("Nu este confirmată condiția: " + gateLabels[key] + ".");
      if (!input[key]) warnings.push("De verificat: " + gateLabels[key] + ".");
    });
    if (completed < breakdown.length) warnings.push("Completează toate cele 11 criterii calculabile pentru o estimare integrală.");
    warnings.push("Cele 25 de puncte pentru subcriteriile 2.1, 2.2 și 3.1–3.4 sunt adăugate numai ca ipoteză de autoevaluare ADR; evaluatorii pot acorda un punctaj diferit.");

    return {
      breakdown: breakdown,
      completed: completed,
      totalCriteria: breakdown.length,
      objectivePoints: objectivePoints,
      objectiveMax: OBJECTIVE_MAX,
      qualitativeEstimate: QUALITATIVE_ESTIMATE,
      estimatedTotal: estimatedTotal,
      thresholdMet: estimatedTotal >= 70,
      rejections: rejections,
      warnings: warnings
    };
  }

  function value(form, name) {
    const field = form.elements.namedItem(name);
    return field ? field.value : "";
  }

  function readForm(form) {
    const names = [
      "caen", "newJobs", "headquartersCounty", "implementationCounty", "ownContribution", "grant",
      "turnover2023", "turnover2024", "turnover2025", "netProfit2025", "assets2025", "debts2025",
      "establishedAt", "employees2025", "disadvantagedHire", "microenterprise", "activityHistory",
      "fixedAssets", "deMinimis", "siteRights", "annexes", "cashFlow"
    ];
    return names.reduce(function (result, name) {
      result[name] = value(form, name);
      return result;
    }, {});
  }

  function formatPoints(value) {
    return value === null ? "—" : new Intl.NumberFormat("ro-RO", { maximumFractionDigits: 2 }).format(value);
  }

  function render(form, result) {
    const root = form.closest("[data-micro-apel-2-simulator]");
    if (!root) return;
    const score = root.querySelector("[data-score-total]");
    const objective = root.querySelector("[data-score-objective]");
    const completion = root.querySelector("[data-score-completion]");
    const verdict = root.querySelector("[data-score-verdict]");
    const meter = root.querySelector("[data-score-meter]");
    const list = root.querySelector("[data-score-breakdown]");
    const alerts = root.querySelector("[data-score-alerts]");

    score.textContent = formatPoints(result.estimatedTotal);
    objective.textContent = formatPoints(result.objectivePoints) + " / " + result.objectiveMax;
    completion.textContent = result.completed + " / " + result.totalCriteria + " criterii calculabile completate";
    meter.style.setProperty("--score", Math.max(0, Math.min(100, result.estimatedTotal)));
    meter.setAttribute("aria-valuenow", String(result.estimatedTotal));
    meter.setAttribute("aria-valuetext", formatPoints(result.estimatedTotal) + " puncte estimate din 100");

    if (result.rejections.length) {
      verdict.textContent = "Există cel puțin o condiție eliminatorie sau de eligibilitate neîndeplinită.";
      verdict.dataset.state = "danger";
    } else if (result.completed < result.totalCriteria) {
      verdict.textContent = "Estimare parțială: completează toate datele înainte de a interpreta pragul.";
      verdict.dataset.state = "pending";
    } else if (result.thresholdMet) {
      verdict.textContent = "Estimarea atinge pragul de 70 de puncte, fără a garanta ierarhizarea sau finanțarea.";
      verdict.dataset.state = "success";
    } else {
      verdict.textContent = "Estimarea este sub pragul minim de 70 de puncte.";
      verdict.dataset.state = "danger";
    }

    list.innerHTML = result.breakdown.map(function (item) {
      const detail = item.detail ? '<small>' + item.detail + '</small>' : "";
      return '<li><span><strong>' + item.label + '</strong>' + detail + '</span><b>' + formatPoints(item.points) + ' / ' + item.max + '</b></li>';
    }).join("");

    const entries = result.rejections.map(function (message) { return { type: "danger", message: message }; })
      .concat(result.warnings.map(function (message) { return { type: "warning", message: message }; }));
    alerts.innerHTML = entries.map(function (entry) {
      return '<li data-alert="' + entry.type + '">' + entry.message + '</li>';
    }).join("");
  }

  function init() {
    if (typeof document === "undefined") return;
    document.querySelectorAll("[data-micro-apel-2-form]").forEach(function (form) {
      const update = function () { render(form, calculate(readForm(form))); };
      form.addEventListener("input", update);
      form.addEventListener("change", update);
      form.addEventListener("reset", function () { setTimeout(update, 0); });
      update();
    });
  }

  const api = Object.freeze({
    CAEN_GROUPS: CAEN_GROUPS,
    calculate: calculate,
    normalizeCaen: normalizeCaen,
    scoreAge: scoreAge,
    scoreCaen: scoreCaen,
    scoreContribution: scoreContribution,
    scoreEmployees: scoreEmployees,
    scoreGrantTurnover: scoreGrantTurnover,
    scoreLocation: scoreLocation,
    scoreProfitability: scoreProfitability,
    scoreSolvency: scoreSolvency,
    scoreTurnoverGrowth: scoreTurnoverGrowth
  });

  scope.MicroApel2Scorer = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init, { once: true });
    else init();
  }
}(typeof window !== "undefined" ? window : globalThis));
