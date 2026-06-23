// =======================================================================
// ThreatLens Enterprise SOC Dashboard
// Google Apps Script. Paste this entire file into Apps Script as Code.gs.
// =======================================================================

var TL = {
  version: "2026.06.15",
  sheets: {
    dashboard: "Dashboard",
    raw: "Raw Events",
    malicious: "Malicious",
    neutral: "Neutral",
    policy: "Policy Insights",
    chartData: "_ChartData",
    eventIndex: "_EventIndex",
    errors: "_Errors"
  },
  theme: {
    navy: "#0B2347",
    blue: "#10356E",
    royal: "#2563EB",
    cyan: "#38BDF8",
    red: "#DC2626",
    orange: "#D97706",
    amber: "#F59E0B",
    green: "#16A34A",
    purple: "#7C3AED",
    slate900: "#0F172A",
    slate700: "#334155",
    slate500: "#64748B",
    slate200: "#E2E8F0",
    slate100: "#F1F5F9",
    white: "#FFFFFF"
  }
};

var EVENT_HEADERS = [
  "Event ID",
  "Received At",
  "Event Time",
  "User Email",
  "Action",
  "Decision Source",
  "Event Type",
  "Risk Level",
  "Risk Score",
  "Risk Band",
  "File Name",
  "Extension",
  "MIME Type",
  "Target URL",
  "Source Host",
  "File Hash",
  "Hash Status",
  "Origin IP",
  "Origin Country",
  "URL VT Malicious",
  "URL VT Suspicious",
  "URL VT Total",
  "File VT Malicious",
  "File VT Suspicious",
  "File VT Total",
  "urlscan Verdict",
  "urlscan Score",
  "Domain Age Days",
  "Domain Registrar",
  "Policy Action",
  "Policy Category",
  "Policy Type",
  "Policy Value",
  "Policy Matched Value",
  "Matched Policy",
  "Policy Enforced",
  "User Override",
  "Ephemeral URL",
  "Security Token",
  "Reason",
  "Download ID",
  "Extension Version",
  "Raw JSON"
];

var POLICY_HEADERS = [
  "Policy",
  "Action",
  "Category",
  "Type",
  "Value",
  "Matched Value",
  "Times Enforced",
  "Blocked",
  "Allowed",
  "Risky Allows",
  "Last Seen"
];

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu("ThreatLens SOC")
    .addItem("Initialize / Rebuild Dashboard", "setup")
    .addItem("Generate Sample Data", "generateSampleData")
    .addSeparator()
    .addItem("Clear Event Data", "clearEventData")
    .addItem("Rebuild Dashboard Only", "rebuildDashboard")
    .addToUi();
}

function setup() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureWorkbook_(ss);
  buildDashboard_(ss);
  refreshPolicyInsights_(ss);

  var dash = ss.getSheetByName(TL.sheets.dashboard);
  if (dash) {
    ss.setActiveSheet(dash);
    ss.moveActiveSheet(1);
  }
  SpreadsheetApp.flush();
}

function rebuildDashboard() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureWorkbook_(ss);
  buildDashboard_(ss);
  refreshPolicyInsights_(ss);
  SpreadsheetApp.flush();
}

function doGet() {
  return json_({
    success: true,
    product: "ThreatLens Enterprise SOC Dashboard",
    version: TL.version,
    message: "Webhook is online. Send POST JSON from the ThreatLens Enterprise extension."
  });
}

function doPost(e) {
  var lock = LockService.getScriptLock();
  var locked = false;

  try {
    lock.waitLock(30000);
    locked = true;

    var ss = SpreadsheetApp.getActiveSpreadsheet();
    ensureWorkbook_(ss);

    var payload = parsePostBody_(e);
    var event = normalizeEvent_(payload);

    if (isDuplicateEvent_(ss, event.eventId)) {
      return json_({
        success: true,
        duplicate: true,
        eventId: event.eventId
      });
    }

    appendEvent_(ss, event);
    rememberEvent_(ss, event);
    refreshPolicyInsights_(ss);

    return json_({
      success: true,
      eventId: event.eventId,
      bucket: event.isThreat ? TL.sheets.malicious : TL.sheets.neutral,
      riskBand: event.riskBand,
      action: event.action
    });
  } catch (err) {
    try {
      logError_(SpreadsheetApp.getActiveSpreadsheet(), err, e);
    } catch (ignored) {}

    return json_({
      success: false,
      error: String(err && err.stack ? err.stack : err)
    });
  } finally {
    if (locked) {
      lock.releaseLock();
    }
  }
}

function ensureWorkbook_(ss) {
  var raw = ensureSheet_(ss, TL.sheets.raw);
  var malicious = ensureSheet_(ss, TL.sheets.malicious);
  var neutral = ensureSheet_(ss, TL.sheets.neutral);
  var policy = ensureSheet_(ss, TL.sheets.policy);
  var chart = ensureSheet_(ss, TL.sheets.chartData);
  var index = ensureSheet_(ss, TL.sheets.eventIndex);
  var errors = ensureSheet_(ss, TL.sheets.errors);

  setupEventSheet_(raw, TL.theme.blue);
  setupEventSheet_(malicious, TL.theme.red);
  setupEventSheet_(neutral, TL.theme.green);
  setupPolicySheet_(policy);

  index.clear();
  index.getRange(1, 1, 1, 3).setValues([["Event ID", "Received At", "Download ID"]]);
  styleHeader_(index.getRange(1, 1, 1, 3), TL.theme.slate700);
  index.hideSheet();

  errors.getRange(1, 1, 1, 4).setValues([["Timestamp", "Error", "Body", "Stack"]]);
  styleHeader_(errors.getRange(1, 1, 1, 4), TL.theme.red);
  errors.hideSheet();

  chart.clear();
  chart.hideSheet();
}

function ensureSheet_(ss, name) {
  return ss.getSheetByName(name) || ss.insertSheet(name);
}

function setupEventSheet_(sheet, tabColor) {
  sheet.clearFormats();
  if (sheet.getLastRow() === 0 || sheet.getRange(1, 1).getValue() !== EVENT_HEADERS[0]) {
    sheet.clear();
    sheet.getRange(1, 1, 1, EVENT_HEADERS.length).setValues([EVENT_HEADERS]);
  } else {
    sheet.getRange(1, 1, 1, EVENT_HEADERS.length).setValues([EVENT_HEADERS]);
  }

  sheet.setFrozenRows(1);
  sheet.setTabColor(tabColor);
  styleHeader_(sheet.getRange(1, 1, 1, EVENT_HEADERS.length), TL.theme.blue);
  sheet.getRange(1, 1, Math.max(2, sheet.getMaxRows()), EVENT_HEADERS.length)
    .setFontFamily("Arial")
    .setFontSize(10)
    .setVerticalAlignment("middle")
    .setHorizontalAlignment("center");

  var widths = [
    230, 165, 165, 230, 92, 120, 140, 105, 95, 95, 230, 80, 150, 360, 180,
    210, 110, 140, 110, 120, 120, 100, 120, 120, 100, 120, 105, 120, 180,
    125, 125, 105, 190, 190, 230, 120, 115, 110, 110, 520, 110, 120, 600
  ];
  for (var i = 0; i < widths.length; i++) {
    sheet.setColumnWidth(i + 1, widths[i]);
  }

  sheet.getRange("N:N").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);
  sheet.getRange("P:P").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);
  sheet.getRange("AN:AN").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);
  sheet.getRange("AQ:AQ").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);

  applyEventConditionalFormatting_(sheet);
}

function setupPolicySheet_(sheet) {
  sheet.clear();
  sheet.setTabColor(TL.theme.purple);
  sheet.getRange(1, 1, 1, POLICY_HEADERS.length).setValues([POLICY_HEADERS]);
  styleHeader_(sheet.getRange(1, 1, 1, POLICY_HEADERS.length), TL.theme.purple);
  sheet.setFrozenRows(1);
  sheet.getRange("A:K").setFontFamily("Arial").setFontSize(10).setVerticalAlignment("middle");
  var widths = [260, 105, 120, 110, 230, 230, 120, 90, 90, 110, 170];
  for (var i = 0; i < widths.length; i++) {
    sheet.setColumnWidth(i + 1, widths[i]);
  }
}

function styleHeader_(range, color) {
  range
    .setBackground(color)
    .setFontColor(TL.theme.white)
    .setFontWeight("bold")
    .setFontFamily("Arial")
    .setFontSize(10)
    .setHorizontalAlignment("center")
    .setVerticalAlignment("middle")
    .setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP);
}

function applyEventConditionalFormatting_(sheet) {
  var rules = [];
  var riskRange = sheet.getRange("H2:H");
  var actionRange = sheet.getRange("E2:E");
  var bandRange = sheet.getRange("J2:J");
  var policyRange = sheet.getRange("AJ2:AJ");

  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Malicious").setBackground("#FEE2E2").setFontColor(TL.theme.red).setBold(true).setRanges([riskRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Suspicious").setBackground("#FEF3C7").setFontColor(TL.theme.orange).setBold(true).setRanges([riskRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Elevated").setBackground("#FFFBEB").setFontColor(TL.theme.amber).setBold(true).setRanges([riskRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Blocked").setBackground("#F3E8FF").setFontColor(TL.theme.purple).setBold(true).setRanges([riskRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Clean").setBackground("#DCFCE7").setFontColor(TL.theme.green).setBold(true).setRanges([riskRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("BLOCKED").setBackground("#FEE2E2").setFontColor(TL.theme.red).setBold(true).setRanges([actionRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("ALLOW").setBackground("#DCFCE7").setFontColor(TL.theme.green).setBold(true).setRanges([actionRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("ESCALATED").setBackground("#DBEAFE").setFontColor(TL.theme.royal).setBold(true).setRanges([actionRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Critical").setBackground("#7F1D1D").setFontColor(TL.theme.white).setBold(true).setRanges([bandRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("High").setBackground("#FEE2E2").setFontColor(TL.theme.red).setBold(true).setRanges([bandRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Medium").setBackground("#FEF3C7").setFontColor(TL.theme.orange).setBold(true).setRanges([bandRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("TRUE").setBackground("#EEF2FF").setFontColor(TL.theme.purple).setBold(true).setRanges([policyRange]).build());

  sheet.setConditionalFormatRules(rules);
}

function buildDashboard_(ss) {
  var dash = ensureSheet_(ss, TL.sheets.dashboard);
  var chart = ensureSheet_(ss, TL.sheets.chartData);

  dash.getCharts().forEach(function(c) { dash.removeChart(c); });
  dash.clear();
  dash.clearFormats();
  dash.setTabColor(TL.theme.blue);
  dash.setHiddenGridlines(true);

  for (var col = 1; col <= 14; col++) {
    dash.setColumnWidth(col, col === 1 || col === 14 ? 22 : 112);
  }
  for (var row = 1; row <= 120; row++) {
    dash.setRowHeight(row, 24);
  }
  dash.getRange("A1:N120").setBackground(TL.theme.slate100).setFontFamily("Arial");

  dash.getRange("B2:M3").merge()
    .setValue("ThreatLens Enterprise SOC Command Center")
    .setFontFamily("Arial")
    .setFontSize(24)
    .setFontWeight("bold")
    .setFontColor(TL.theme.white)
    .setBackground(TL.theme.blue)
    .setHorizontalAlignment("center")
    .setVerticalAlignment("middle");
  dash.getRange("B4:M4").merge()
    .setValue("Real-time browser download interception, policy enforcement, threat reputation, user overrides, and SOC telemetry.")
    .setFontSize(10)
    .setFontColor(TL.theme.slate500)
    .setHorizontalAlignment("center")
    .setBackground(TL.theme.white);

  buildKpiCard_(dash, "B6:D8", "TOTAL EVENTS", "=COUNTA('Raw Events'!A2:A)", TL.theme.blue);
  buildKpiCard_(dash, "E6:G8", "THREATS BLOCKED", '=COUNTIF(\'Raw Events\'!E:E,"BLOCKED")', TL.theme.red);
  buildKpiCard_(dash, "H6:J8", "RISKY USER ALLOWS", '=COUNTIFS(\'Raw Events\'!E:E,"ALLOW",\'Raw Events\'!J:J,"Critical")+COUNTIFS(\'Raw Events\'!E:E,"ALLOW",\'Raw Events\'!J:J,"High")', TL.theme.orange);
  buildKpiCard_(dash, "K6:M8", "POLICIES ENFORCED", '=COUNTIF(\'Raw Events\'!AJ:AJ,TRUE)', TL.theme.purple);

  buildKpiCard_(dash, "B10:D12", "UNIQUE USERS", '=IFERROR(COUNTA(UNIQUE(FILTER(\'Raw Events\'!D2:D,\'Raw Events\'!D2:D<>""))),0)', TL.theme.royal);
  buildKpiCard_(dash, "E10:G12", "COUNTRIES OBSERVED", '=IFERROR(COUNTA(UNIQUE(FILTER(\'Raw Events\'!S2:S,\'Raw Events\'!S2:S<>"",\'Raw Events\'!S2:S<>"Unknown"))),0)', TL.theme.cyan);
  buildKpiCard_(dash, "H10:J12", "MALICIOUS VT HITS", '=SUM(\'Raw Events\'!T:T)+SUM(\'Raw Events\'!W:W)', TL.theme.red);
  buildKpiCard_(dash, "K10:M12", "POLICY SAVES", '=COUNTIFS(\'Raw Events\'!E:E,"BLOCKED",\'Raw Events\'!AJ:AJ,TRUE)', TL.theme.green);

  buildChartData_(chart);
  insertDashboardCharts_(dash, chart);
  buildDashboardTables_(dash);

  chart.hideSheet();
}

function buildKpiCard_(sheet, rangeA1, label, formula, color) {
  var range = sheet.getRange(rangeA1);
  range.breakApart(); // Clear any existing merges to prevent conflicts
  range.setBackground(TL.theme.white)
    .setBorder(true, true, true, true, false, false, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);

  var parts = rangeA1.split(":");
  var start = parseCell_(parts[0]);
  var end = parseCell_(parts[1]);
  var top = sheet.getRange(start.row, start.col, 1, end.col - start.col + 1);
  var bottom = sheet.getRange(start.row + 1, start.col, end.row - start.row, end.col - start.col + 1);
  top.merge().setValue(label)
    .setFontSize(9)
    .setFontWeight("bold")
    .setFontColor(TL.theme.slate500)
    .setBackground(TL.theme.white)
    .setHorizontalAlignment("center");
  bottom.merge().setFormula(formula)
    .setFontSize(30)
    .setFontWeight("bold")
    .setFontColor(color)
    .setBackground(TL.theme.white)
    .setHorizontalAlignment("center")
    .setVerticalAlignment("middle");
}

function parseCell_(a1) {
  var match = String(a1).match(/^([A-Z]+)(\d+)$/);
  var colLetters = match[1];
  var col = 0;
  for (var i = 0; i < colLetters.length; i++) {
    col = col * 26 + colLetters.charCodeAt(i) - 64;
  }
  return { col: col, row: Number(match[2]) };
}

function buildChartData_(sheet) {
  sheet.clear();
  sheet.getRange("A1:Z80").setBackground(TL.theme.slate100).setFontColor(TL.theme.slate100);

  // Chart 1: Risk Distribution (A1:B6) — static labels + COUNTIF, never shifts
  sheet.getRange("A1:B1").setValues([["Risk Band", "Events"]]);
  sheet.getRange("A2:A6").setValues([["Critical"], ["High"], ["Medium"], ["Low"], ["Unknown"]]);
  sheet.getRange("B2").setFormula('=COUNTIF(\'Raw Events\'!J:J,"Critical")');
  sheet.getRange("B3").setFormula('=COUNTIF(\'Raw Events\'!J:J,"High")');
  sheet.getRange("B4").setFormula('=COUNTIF(\'Raw Events\'!J:J,"Medium")');
  sheet.getRange("B5").setFormula('=COUNTIF(\'Raw Events\'!J:J,"Low")');
  sheet.getRange("B6").setFormula('=COUNTIF(\'Raw Events\'!J:J,"Unknown")');

  // Chart 2: Enforcement Outcomes (D1:E5) — static labels + COUNTIF, never shifts
  sheet.getRange("D1:E1").setValues([["Action", "Count"]]);
  sheet.getRange("D2:D5").setValues([["BLOCKED"], ["ALLOW"], ["ESCALATED"], ["REVIEW"]]);
  sheet.getRange("E2").setFormula('=COUNTIF(\'Raw Events\'!E:E,"BLOCKED")');
  sheet.getRange("E3").setFormula('=COUNTIF(\'Raw Events\'!E:E,"ALLOW")');
  sheet.getRange("E4").setFormula('=COUNTIF(\'Raw Events\'!E:E,"ESCALATED")');
  sheet.getRange("E5").setFormula('=COUNTIF(\'Raw Events\'!E:E,"REVIEW")');

  // Charts 3-8: QUERY-based — embed header inside formula so range is always stable
  // The {"Header1","Header2"; QUERY(...)} trick keeps row 1 as a true header always.
  sheet.getRange("G1").setFormula(
    '=IFERROR({"Country","Events";QUERY({\'Raw Events\'!S2:S},"select Col1,count(Col1) where Col1 is not null and Col1 <> \'\' and Col1 <> \'Unknown\' group by Col1 order by count(Col1) desc limit 10 label Col1 \'\',count(Col1) \'\'",0)},{"No data",0})');

  // Chart 4: Most Enforced Policies — uses AI (Matched Policy)
  sheet.getRange("J1").setFormula(
    '=IFERROR({"Policy","Times";QUERY({\'Raw Events\'!AI2:AI},"select Col1,count(Col1) where Col1 is not null and Col1 <> \'\' and Col1 <> \'N/A\' group by Col1 order by count(Col1) desc limit 10 label Col1 \'\',count(Col1) \'\'",0)},{"No data",0})');

  // Chart 5: Most Active Users
  sheet.getRange("M1").setFormula(
    '=IFERROR({"User","Events";QUERY({\'Raw Events\'!D2:D},"select Col1,count(Col1) where Col1 is not null and Col1 <> \'\' and Col1 <> \'Anonymous\' and Col1 <> \'Not Logged In\' group by Col1 order by count(Col1) desc limit 10 label Col1 \'\',count(Col1) \'\'",0)},{"No data",0})');

  // Chart 6: Most Intercepted Files
  sheet.getRange("P1").setFormula(
    '=IFERROR({"File","Events";QUERY({\'Raw Events\'!K2:K},"select Col1,count(Col1) where Col1 is not null and Col1 <> \'\' and Col1 <> \'Unknown\' group by Col1 order by count(Col1) desc limit 10 label Col1 \'\',count(Col1) \'\'",0)},{"No data",0})');

  // Chart 7: High-Risk Origin IPs
  sheet.getRange("S1").setFormula(
    '=IFERROR({"Origin IP","Threats";QUERY({\'Raw Events\'!R2:R,\'Raw Events\'!J2:J},"select Col1,count(Col1) where Col1 is not null and Col1 <> \'\' and Col1 <> \'Unknown\' and (Col2 = \'Critical\' or Col2 = \'High\') group by Col1 order by count(Col1) desc limit 10 label Col1 \'\',count(Col1) \'\'",0)},{"No data",0})');

  // Chart 8: Override Actions
  sheet.getRange("V1").setFormula(
    '=IFERROR({"Override","Count";QUERY({\'Raw Events\'!AK2:AK,\'Raw Events\'!E2:E},"select Col2,count(Col2) where Col1 = true group by Col2 label Col2 \'\',count(Col2) \'\'",0)},{"No risky allows",0})');
}

function setQueryFormula_(sheet, rangeA1, col1, col2, formula) {
  var range = sheet.getRange(rangeA1);
  range.clearContent();
  var start = parseCell_(rangeA1.split(":")[0]);
  sheet.getRange(start.row, start.col, 1, 2).setValues([[col1, col2]]);
  sheet.getRange(start.row + 1, start.col).setFormula(formula);
}

function insertDashboardCharts_(dash, chart) {
  var bg = { fill: TL.theme.white, stroke: "#CBD5E1", strokeWidth: 1 };
  var ttl = { fontSize: 13, bold: true, color: TL.theme.blue, fontName: "Arial" };
  var W = 650;
  var H = 330;

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.PIE)
    .addRange(chart.getRange("A1:B6"))
    .setPosition(14, 2, 0, 0)
    .setOption("title", "Risk Distribution")
    .setOption("titleTextStyle", ttl)
    .setOption("pieHole", 0.48)
    .setOption("colors", ["#7F1D1D", "#DC2626", "#F59E0B", "#16A34A", "#94A3B8"])
    .setOption("legend", { position: "bottom", textStyle: { fontSize: 10 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "8%", top: "14%", width: "84%", height: "70%" })
    .setOption("width", W).setOption("height", H).build());

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.COLUMN)
    .addRange(chart.getRange("D1:E5"))
    .setPosition(14, 8, 0, 0)
    .setOption("title", "Enforcement Outcomes")
    .setOption("titleTextStyle", ttl)
    .setOption("colors", [TL.theme.royal])
    .setOption("legend", { position: "none" })
    .setOption("vAxis", { minValue: 0, gridlines: { color: TL.theme.slate200 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "12%", top: "14%", width: "80%", height: "68%" })
    .setOption("width", W).setOption("height", H).build());

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.BAR)
    .addRange(chart.getRange("G1:H15"))
    .setPosition(31, 2, 0, 0)
    .setOption("title", "Top Origin Countries")
    .setOption("titleTextStyle", ttl)
    .setOption("colors", [TL.theme.cyan])
    .setOption("legend", { position: "none" })
    .setOption("hAxis", { minValue: 0, gridlines: { color: TL.theme.slate200 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "26%", top: "14%", width: "68%", height: "76%" })
    .setOption("width", W).setOption("height", H).build());

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.BAR)
    .addRange(chart.getRange("J1:K15"))
    .setPosition(31, 8, 0, 0)
    .setOption("title", "Most Enforced Policies")
    .setOption("titleTextStyle", ttl)
    .setOption("colors", [TL.theme.purple])
    .setOption("legend", { position: "none" })
    .setOption("hAxis", { minValue: 0, gridlines: { color: TL.theme.slate200 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "34%", top: "14%", width: "60%", height: "76%" })
    .setOption("width", W).setOption("height", H).build());

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.BAR)
    .addRange(chart.getRange("M1:N15"))
    .setPosition(48, 2, 0, 0)
    .setOption("title", "Most Active Users")
    .setOption("titleTextStyle", ttl)
    .setOption("colors", [TL.theme.royal])
    .setOption("legend", { position: "none" })
    .setOption("hAxis", { minValue: 0, gridlines: { color: TL.theme.slate200 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "38%", top: "14%", width: "58%", height: "76%" })
    .setOption("width", W).setOption("height", H).build());

  dash.insertChart(dash.newChart().setChartType(Charts.ChartType.BAR)
    .addRange(chart.getRange("S1:T15"))
    .setPosition(48, 8, 0, 0)
    .setOption("title", "High-Risk Origin IPs")
    .setOption("titleTextStyle", ttl)
    .setOption("colors", [TL.theme.red])
    .setOption("legend", { position: "none" })
    .setOption("hAxis", { minValue: 0, gridlines: { color: TL.theme.slate200 } })
    .setOption("useFirstColumnAsDomain", true)
    .setOption("backgroundColor", bg)
    .setOption("chartArea", { left: "30%", top: "14%", width: "64%", height: "76%" })
    .setOption("width", W).setOption("height", H).build());
}

function buildDashboardTables_(dash) {
  dash.getRange("B66:M66").merge()
    .setValue("Live Threat Feed - Last 20 High-Risk Events")
    .setFontSize(15)
    .setFontWeight("bold")
    .setFontColor(TL.theme.red)
    .setBackground(TL.theme.white)
    .setHorizontalAlignment("center")
    .setBorder(true, true, false, true, false, false, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);

  dash.getRange("B67:M67").setValues([["Time", "User", "Action", "Risk", "File", "Host", "IP", "Country", "URL VT", "File VT", "Policy", "Reason"]]);
  styleHeader_(dash.getRange("B67:M67"), TL.theme.blue);
  dash.getRange("B68").setFormula("=IFERROR(QUERY({'Raw Events'!B2:B,'Raw Events'!D2:D,'Raw Events'!E2:E,'Raw Events'!H2:H,'Raw Events'!K2:K,'Raw Events'!O2:O,'Raw Events'!R2:R,'Raw Events'!S2:S,'Raw Events'!T2:T,'Raw Events'!W2:W,'Raw Events'!AI2:AI,'Raw Events'!AN2:AN,'Raw Events'!J2:J}, \"select Col1,Col2,Col3,Col4,Col5,Col6,Col7,Col8,Col9,Col10,Col11,Col12 where Col13 = 'Critical' or Col13 = 'High' order by Col1 desc limit 20\", 0), \"No high-risk events recorded yet.\")");
  dash.getRange("B68:M88").setBackground(TL.theme.white).setFontSize(9).setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP)
    .setBorder(false, true, true, true, true, true, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);
  dash.getRange("M68:M88").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);

  dash.getRange("B92:M92").merge()
    .setValue("Risky User Allows - Malicious or High-Risk Files Released by a User")
    .setFontSize(15)
    .setFontWeight("bold")
    .setFontColor(TL.theme.orange)
    .setBackground(TL.theme.white)
    .setHorizontalAlignment("center")
    .setBorder(true, true, false, true, false, false, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);

  dash.getRange("B93:M93").setValues([["Time", "User", "Risk", "File", "Host", "URL VT M", "File VT M", "IP", "Country", "Policy", "Hash", "Reason"]]);
  styleHeader_(dash.getRange("B93:M93"), TL.theme.orange);
  dash.getRange("B94").setFormula("=IFERROR(QUERY({'Raw Events'!B2:B,'Raw Events'!D2:D,'Raw Events'!H2:H,'Raw Events'!K2:K,'Raw Events'!O2:O,'Raw Events'!T2:T,'Raw Events'!W2:W,'Raw Events'!R2:R,'Raw Events'!S2:S,'Raw Events'!AI2:AI,'Raw Events'!P2:P,'Raw Events'!AN2:AN,'Raw Events'!AK2:AK}, \"select Col1,Col2,Col3,Col4,Col5,Col6,Col7,Col8,Col9,Col10,Col11,Col12 where Col13 = true order by Col1 desc limit 20\", 0), \"No risky user allows recorded yet.\")");
  dash.getRange("B94:M114").setBackground(TL.theme.white).setFontSize(9).setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP)
    .setBorder(false, true, true, true, true, true, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);
  dash.getRange("M94:M114").setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP);
}

function parsePostBody_(e) {
  if (!e || !e.postData || !e.postData.contents) {
    throw new Error("Missing POST body.");
  }
  try {
    return JSON.parse(e.postData.contents);
  } catch (err) {
    throw new Error("Invalid JSON body: " + err.message);
  }
}

function normalizeEvent_(data) {
  data = data || {};

  var now = new Date();
  var urlStats = extractVtStats_(data.urlReputation);
  var fileStats = extractVtStats_(data.fileReputation);
  var urlscan = data.urlscanReputation || {};
  var ipRep = data.ipReputation || {};
  var domain = data.domainReputation || {};
  var rule = data.ruleMatch || {};

  var action = normalizeAction_(data.action || data.decision || data.event);
  var risk = normalizeRisk_(data.riskIndicator, action, urlStats, fileStats);
  var riskScore = computeRiskScore_(risk, action, urlStats, fileStats, urlscan, rule);
  var riskBand = computeRiskBand_(risk, riskScore);
  var isThreat = isThreatEvent_(risk, riskBand, action, urlStats, fileStats);
  var isOverride = action === "ALLOW" && (riskBand === "Critical" || riskBand === "High" || risk === "Malicious" || risk === "Suspicious" || risk === "Blocked");

  var policyAction = clean_(data.policyAction) || derivePolicyActionFromPayload_(rule, action);
  var policyCategory = clean_(data.policyCategory || rule.category || rule.type || "");
  var policyType = clean_(data.policyType || rule.typeLabel || rule.type || "");
  var policyValue = clean_(data.policyValue || rule.value || "");
  var policyMatchedValue = clean_(data.policyMatchedValue || rule.matchedValue || "");
  var matchedPolicy = buildPolicyLabel_(policyAction, policyCategory, policyType, policyValue);
  var policyEnforced = Boolean(policyValue || policyAction || data.policyEnforced === true);

  var eventTime = parseDate_(data.updatedAt || data.createdAt || data.timestamp || data.eventTime) || now;
  var downloadId = clean_(data.downloadId || "");
  var eventType = clean_(data.event || "");
  var eventId = clean_(data.eventId || "") || buildEventId_(data, eventType, downloadId, action, risk, eventTime);
  var targetUrl = clean_(data.url || data.finalUrl || data.sourceUrl || data.originalUrl || "");
  var sourceHost = clean_(data.sourceHostname || hostFromUrl_(targetUrl) || hostFromUrl_(data.sourceUrl) || "");
  var ip = clean_(ipRep.ip || data.targetIp || data.originIp || "");
  var country = normalizeCountry_(ipRep.country || data.originCountry || data.country || "");
  var ageDays = getDomainAgeDays_(domain);
  var reason = sanitizeReason_(data.reason);

  return {
    eventId: eventId,
    receivedAt: now,
    eventTime: eventTime,
    userEmail: clean_(data.userEmail || "Anonymous"),
    action: action,
    decisionSource: clean_(data.decisionSource || ""),
    eventType: eventType || "download_event",
    risk: risk,
    riskScore: riskScore,
    riskBand: riskBand,
    fileName: clean_(data.fileName || "Unknown"),
    extension: normalizeExtension_(data.extension || ""),
    mime: clean_(data.mime || ""),
    targetUrl: targetUrl,
    sourceHost: sourceHost,
    fileHash: clean_(data.fileHash || ""),
    fileHashStatus: clean_(data.fileHashStatus || ""),
    originIp: ip || "Unknown",
    originCountry: country || "Unknown",
    urlVtMalicious: urlStats.malicious,
    urlVtSuspicious: urlStats.suspicious,
    urlVtTotal: urlStats.total,
    fileVtMalicious: fileStats.malicious,
    fileVtSuspicious: fileStats.suspicious,
    fileVtTotal: fileStats.total,
    urlscanVerdict: clean_(urlscan.verdict || urlscan.status || ""),
    urlscanScore: Number(urlscan.score || 0),
    domainAgeDays: ageDays,
    domainRegistrar: clean_(domain.registrar || domain.domainRegistrar || ""),
    policyAction: policyAction,
    policyCategory: policyCategory,
    policyType: policyType,
    policyValue: policyValue,
    policyMatchedValue: policyMatchedValue,
    matchedPolicy: matchedPolicy || "N/A",
    policyEnforced: policyEnforced,
    userOverride: isOverride,
    ephemeralUrl: Boolean(data.isEphemeralUrl),
    securityToken: Boolean(data.hasSecurityToken),
    reason: reason,
    downloadId: downloadId,
    extensionVersion: clean_(data.extensionVersion || ""),
    rawJson: JSON.stringify(data),
    isThreat: isThreat
  };
}

function appendEvent_(ss, event) {
  var raw = ss.getSheetByName(TL.sheets.raw);
  var bucket = ss.getSheetByName(event.isThreat ? TL.sheets.malicious : TL.sheets.neutral);
  var row = eventToRow_(event);

  appendRowFast_(raw, row);
  appendRowFast_(bucket, row);
  formatEventRow_(raw, raw.getLastRow(), event);
  formatEventRow_(bucket, bucket.getLastRow(), event);
}

function appendRowFast_(sheet, row) {
  sheet.getRange(sheet.getLastRow() + 1, 1, 1, row.length).setValues([row]);
}

function eventToRow_(event) {
  return [
    event.eventId,
    event.receivedAt,
    event.eventTime,
    event.userEmail,
    event.action,
    event.decisionSource,
    event.eventType,
    event.risk,
    event.riskScore,
    event.riskBand,
    event.fileName,
    event.extension,
    event.mime,
    event.targetUrl,
    event.sourceHost,
    event.fileHash,
    event.fileHashStatus,
    event.originIp,
    event.originCountry,
    event.urlVtMalicious,
    event.urlVtSuspicious,
    event.urlVtTotal,
    event.fileVtMalicious,
    event.fileVtSuspicious,
    event.fileVtTotal,
    event.urlscanVerdict,
    event.urlscanScore,
    event.domainAgeDays,
    event.domainRegistrar,
    event.policyAction,
    event.policyCategory,
    event.policyType,
    event.policyValue,
    event.policyMatchedValue,
    event.matchedPolicy,
    event.policyEnforced,
    event.userOverride,
    event.ephemeralUrl,
    event.securityToken,
    event.reason,
    event.downloadId,
    event.extensionVersion,
    event.rawJson
  ];
}

function formatEventRow_(sheet, rowNumber, event) {
  if (rowNumber <= 1) return;
  var bg = event.action === "BLOCKED" ? "#FEF2F2" : event.userOverride ? "#FFF7ED" : event.isThreat ? "#FFFBEB" : "#F0FDF4";
  sheet.getRange(rowNumber, 1, 1, EVENT_HEADERS.length).setBackground(bg);
  sheet.getRange(rowNumber, 2, 1, 2).setNumberFormat("yyyy-mm-dd hh:mm:ss");
  sheet.getRange(rowNumber, 8).setFontWeight("bold");
  sheet.getRange(rowNumber, 10).setFontWeight("bold");
  sheet.getRange(rowNumber, 40).setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP);
}

function isDuplicateEvent_(ss, eventId) {
  if (!eventId) return false;
  var index = ss.getSheetByName(TL.sheets.eventIndex);
  if (!index || index.getLastRow() < 2) return false;
  return Boolean(index.getRange(2, 1, index.getLastRow() - 1, 1).createTextFinder(eventId).matchEntireCell(true).findNext());
}

function rememberEvent_(ss, event) {
  var index = ss.getSheetByName(TL.sheets.eventIndex);
  appendRowFast_(index, [event.eventId, event.receivedAt, event.downloadId]);
}

function refreshPolicyInsights_(ss) {
  var sheet = ss.getSheetByName(TL.sheets.policy);
  if (!sheet) return;

  setupPolicySheet_(sheet);

  // Group by Policy Value (AG=Col4) — the actual rule value like "angryip.org" or ".exe".
  // This is the key fix: real events have a policyValue even when matchedPolicy says N/A.
  // Columns: AD=PolicyAction, AE=PolicyCategory, AF=PolicyType, AG=PolicyValue,
  //          AH=PolicyMatchedValue, AI=MatchedPolicy(display), AJ=PolicyEnforced,
  //          AK=UserOverride, E=Action, B=ReceivedAt
  // Fix: Google Sheets QUERY does not support sum(Col='Value'). We must convert to 1s and 0s first.
  sheet.getRange("A2").setFormula(
    "=IFERROR(QUERY({" +
    "'Raw Events'!AG2:AG," +   // Col1 = Policy Value (the actual rule: domain / hash / file-type)
    "'Raw Events'!AD2:AD," +   // Col2 = Policy Action (BLOCKLIST / ALLOWLIST)
    "'Raw Events'!AE2:AE," +   // Col3 = Policy Category
    "'Raw Events'!AF2:AF," +   // Col4 = Policy Type
    "'Raw Events'!AI2:AI," +   // Col5 = Matched Policy (display label)
    "'Raw Events'!AH2:AH," +   // Col6 = Policy Matched Value
    "ARRAYFORMULA(IF('Raw Events'!E2:E=\"BLOCKED\", 1, 0))," + // Col7 = Blocked count
    "ARRAYFORMULA(IF('Raw Events'!E2:E=\"ALLOW\", 1, 0))," +   // Col8 = Allowed count
    "ARRAYFORMULA(IF('Raw Events'!AK2:AK=TRUE, 1, 0))," +      // Col9 = Override count
    "'Raw Events'!B2:B}," +    // Col10 = Received At (for max/last seen)
    "\"select Col1,Col2,Col3,Col4,Col5,Col6,count(Col1)," +
    "sum(Col7),sum(Col8),sum(Col9),max(Col10) " +
    "where Col1 is not null and Col1 <> '' and Col1 <> 'N/A' " +
    "group by Col1,Col2,Col3,Col4,Col5,Col6 " +
    "order by count(Col1) desc " +
    "label count(Col1) '',sum(Col7) '',sum(Col8) '',sum(Col9) '',max(Col10) ''\", 0)," +
    "\"No policy events yet.\")");

  sheet.getRange("A2:K100")
    .setBackground(TL.theme.white)
    .setFontFamily("Arial")
    .setFontSize(10)
    .setVerticalAlignment("middle")
    .setHorizontalAlignment("center")
    .setBorder(false, true, true, true, true, true, "#CBD5E1", SpreadsheetApp.BorderStyle.SOLID);

  // Highlight rows with BLOCKLIST actions in red, ALLOWLIST in green
  var rules = [
    SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo("BLOCKLIST").setBackground("#FEE2E2").setFontColor(TL.theme.red).setBold(true)
      .setRanges([sheet.getRange("B2:B100")]).build(),
    SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo("ALLOWLIST").setBackground("#DCFCE7").setFontColor(TL.theme.green).setBold(true)
      .setRanges([sheet.getRange("B2:B100")]).build()
  ];
  sheet.setConditionalFormatRules(rules);
}

function clearEventData() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureWorkbook_(ss);
  [TL.sheets.raw, TL.sheets.malicious, TL.sheets.neutral, TL.sheets.eventIndex, TL.sheets.errors].forEach(function(name) {
    var sheet = ss.getSheetByName(name);
    if (!sheet) return;
    var last = sheet.getLastRow();
    if (last > 1) {
      sheet.getRange(2, 1, last - 1, sheet.getMaxColumns()).clearContent().clearFormat();
    }
  });
  buildDashboard_(ss);
  refreshPolicyInsights_(ss);
  SpreadsheetApp.flush();
}

function generateSampleData() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ensureWorkbook_(ss);

  var users = [
    "sarah.chen@company.com",
    "james.rodriguez@company.com",
    "ayush.soc@company.com",
    "contractor.lee@company.com",
    "cfo@company.com",
    "hr.wilson@company.com",
    "devops@company.com"
  ];
  var files = ["invoice.exe", "chrome_update.msi", "salary_report.pdf", "vpn_client.dmg", "customer_data.zip", "script.ps1", "design_export.png", "meeting_notes.docx"];
  var hosts = ["evil-phish.net", "github.com", "docs.google.com", "angryip.org", "cdn.vendor.com", "pastebin.com", "fake-adobe.com"];
  var countries = ["US", "IN", "DE", "BR", "RU", "CN", "SG", "NL"];
  var policies = [
    { action: "BLOCKLIST", category: "domains", type: "domain", value: "angryip.org" },
    { action: "BLOCKLIST", category: "fileTypes", type: "file-type", value: ".ps1" },
    { action: "BLOCKLIST", category: "hashes", type: "hash", value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
    { action: "ALLOWLIST", category: "domains", type: "domain", value: "github.com" },
    null
  ];

  for (var i = 0; i < 80; i++) {
    var policy = policies[Math.floor(Math.random() * policies.length)];
    var host = hosts[Math.floor(Math.random() * hosts.length)];
    var file = files[Math.floor(Math.random() * files.length)];
    var riskRoll = Math.random();
    var risk = riskRoll > 0.78 ? "Malicious" : riskRoll > 0.58 ? "Suspicious" : riskRoll > 0.40 ? "Elevated" : "Clean";
    var action = policy && policy.action === "BLOCKLIST" ? "BLOCKED" : (risk === "Malicious" && Math.random() > 0.72 ? "ALLOW" : risk === "Clean" ? "ALLOW" : "BLOCKED");
    var urlMal = risk === "Malicious" ? rand_(2, 28) : risk === "Suspicious" ? rand_(0, 2) : 0;
    var fileMal = risk === "Malicious" ? rand_(1, 18) : risk === "Suspicious" ? rand_(0, 2) : 0;
    var country = countries[Math.floor(Math.random() * countries.length)];
    var data = {
      schemaVersion: 2,
      eventId: "sample:" + new Date().getTime() + ":" + i,
      userEmail: users[Math.floor(Math.random() * users.length)],
      event: action === "BLOCKED" ? "auto_block" : "user_allow",
      action: action,
      decision: action === "BLOCKED" ? "block" : "allow",
      decisionSource: policy ? "policy" : "user",
      riskIndicator: risk,
      fileName: file,
      url: "https://" + host + "/downloads/" + file,
      sourceHostname: host,
      fileHash: Math.random().toString(36).substring(2, 34),
      fileHashStatus: "complete",
      extension: file.indexOf(".") >= 0 ? file.substring(file.lastIndexOf(".")) : "",
      mime: "application/octet-stream",
      urlReputation: { status: "complete", stats: { malicious: urlMal, suspicious: risk === "Suspicious" ? 2 : 0, harmless: 70, undetected: 20 } },
      fileReputation: { status: "complete", stats: { malicious: fileMal, suspicious: risk === "Suspicious" ? 1 : 0, harmless: 65, undetected: 24 } },
      urlscanReputation: { verdict: risk === "Malicious" ? "malicious" : "clean", score: risk === "Malicious" ? rand_(70, 100) : rand_(0, 20) },
      ipReputation: { ip: "203.0.113." + rand_(1, 240), country: country },
      domainReputation: { creationDate: Math.floor((Date.now() - rand_(30, 1800) * 86400000) / 1000), registrar: "Example Registrar" },
      policyAction: policy ? policy.action : "",
      policyCategory: policy ? policy.category : "",
      policyType: policy ? policy.type : "",
      policyValue: policy ? policy.value : "",
      ruleMatch: policy ? { category: policy.category, typeLabel: policy.type, value: policy.value, matchedValue: host } : null,
      reason: policy ? "Matched enterprise policy: " + policy.value : "Threat intelligence and user decision telemetry.",
      downloadId: "sample-" + i,
      extensionVersion: "2.6"
    };
    var event = normalizeEvent_(data);
    if (!isDuplicateEvent_(ss, event.eventId)) {
      appendEvent_(ss, event);
      rememberEvent_(ss, event);
    }
  }

  refreshPolicyInsights_(ss);
  SpreadsheetApp.flush();
}

function rand_(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function extractVtStats_(input) {
  var result = { malicious: 0, suspicious: 0, total: 0 };
  if (!input) return result;

  if (typeof input === "string") {
    var m = input.match(/M\s*:\s*(\d+)/i);
    var s = input.match(/S\s*:\s*(\d+)/i);
    result.malicious = m ? Number(m[1]) : 0;
    result.suspicious = s ? Number(s[1]) : 0;
    result.total = result.malicious + result.suspicious;
    return result;
  }

  var stats = input.stats || input.last_analysis_stats || input;
  result.malicious = Number(stats.malicious || 0);
  result.suspicious = Number(stats.suspicious || 0);
  var total = 0;
  Object.keys(stats || {}).forEach(function(key) {
    if (typeof stats[key] === "number") total += Number(stats[key] || 0);
  });
  result.total = total;
  return result;
}

function normalizeAction_(value) {
  var text = String(value || "").toLowerCase();
  if (text.indexOf("block") !== -1 || text === "blocked") return "BLOCKED";
  if (text.indexOf("allow") !== -1 || text === "allowed") return "ALLOW";
  if (text.indexOf("escalation") !== -1 || text.indexOf("escalated") !== -1) return "ESCALATED";
  return "REVIEW";
}

function normalizeRisk_(value, action, urlStats, fileStats) {
  var text = String(value || "").trim().toLowerCase();
  if (text === "malicious") return "Malicious";
  if (text === "suspicious") return "Suspicious";
  if (text === "elevated") return "Elevated";
  if (text === "blocked" || text === "high") return "Blocked";
  if (text === "trusted") return "Trusted";
  if (text === "clean" || text === "reviewed" || text === "safe") return "Clean";
  if (urlStats.malicious > 0 || fileStats.malicious > 0) return "Malicious";
  if (urlStats.suspicious > 0 || fileStats.suspicious > 0) return "Suspicious";
  if (action === "BLOCKED") return "Blocked";
  return "Unknown";
}

function computeRiskScore_(risk, action, urlStats, fileStats, urlscan, rule) {
  var score = 0;
  if (risk === "Malicious") score += 70;
  if (risk === "Suspicious") score += 48;
  if (risk === "Elevated") score += 30;
  if (risk === "Blocked") score += 36;
  score += Math.min(24, (urlStats.malicious + fileStats.malicious) * 4);
  score += Math.min(10, (urlStats.suspicious + fileStats.suspicious) * 2);
  score += Math.min(12, Number(urlscan && urlscan.score ? urlscan.score : 0) / 8);
  if (rule && rule.value) score += 12;
  if (action === "ALLOW" && (risk === "Malicious" || risk === "Suspicious" || risk === "Blocked")) score += 18;
  return Math.min(100, Math.round(score));
}

function computeRiskBand_(risk, score) {
  if (risk === "Malicious" || score >= 75) return "Critical";
  if (risk === "Suspicious" || risk === "Blocked" || score >= 45) return "High";
  if (risk === "Elevated" || score >= 20) return "Medium";
  if (risk === "Clean" || risk === "Trusted") return "Low";
  return "Unknown";
}

function isThreatEvent_(risk, band, action, urlStats, fileStats) {
  if (band === "Critical" || band === "High") return true;
  if (risk === "Malicious" || risk === "Suspicious" || risk === "Elevated" || risk === "Blocked") return true;
  if (action === "BLOCKED") return true;
  return urlStats.malicious > 0 || fileStats.malicious > 0;
}

function derivePolicyActionFromPayload_(rule, action) {
  if (!rule || !rule.value) return "";
  return action === "ALLOW" ? "ALLOWLIST" : "BLOCKLIST";
}

function buildPolicyLabel_(policyAction, category, type, value) {
  if (!value) return "";
  return [policyAction || "POLICY", category || type || "rule", value].join(" / ");
}

function getDomainAgeDays_(domain) {
  if (!domain) return "";
  var raw = domain.creationDate || domain.domainCreationDate || "";
  if (!raw) return "";
  var date;
  if (typeof raw === "number") {
    date = new Date(raw * 1000);
  } else {
    date = parseDate_(raw);
  }
  if (!date) return "";
  return Math.max(0, Math.round((Date.now() - date.getTime()) / 86400000));
}

function parseDate_(value) {
  if (!value) return null;
  if (Object.prototype.toString.call(value) === "[object Date]" && !isNaN(value.getTime())) return value;
  var parsed = new Date(value);
  return isNaN(parsed.getTime()) ? null : parsed;
}

function buildEventId_(data, eventType, downloadId, action, risk, eventTime) {
  var seed = [
    downloadId || "no-download",
    eventType || "event",
    action || "action",
    risk || "risk",
    data.fileHash || "",
    data.url || data.finalUrl || data.sourceUrl || "",
    eventTime ? eventTime.toISOString() : new Date().toISOString()
  ].join("|");
  return Utilities.base64EncodeWebSafe(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, seed)).substring(0, 44);
}

function normalizeCountry_(value) {
  var text = clean_(value).toUpperCase();
  if (!text || text === "UNKNOWN") return "Unknown";
  return text.substring(0, 2);
}

function normalizeExtension_(value) {
  var text = clean_(value).toLowerCase();
  if (!text) return "";
  return text.charAt(0) === "." ? text : "." + text;
}

function sanitizeReason_(reason) {
  var text = Array.isArray(reason) ? reason.join(". ") : String(reason || "");
  return text.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
}

function hostFromUrl_(url) {
  try {
    return url ? new URL(url).hostname : "";
  } catch (err) {
    return "";
  }
}

function clean_(value) {
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function logError_(ss, err, e) {
  var sheet = ensureSheet_(ss, TL.sheets.errors);
  var body = "";
  try {
    body = e && e.postData && e.postData.contents ? e.postData.contents : "";
  } catch (ignored) {}
  appendRowFast_(sheet, [
    new Date(),
    String(err && err.message ? err.message : err),
    body,
    String(err && err.stack ? err.stack : "")
  ]);
}
