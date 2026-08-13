const ACCEPT_CH = [
  "Sec-CH-UA",
  "Sec-CH-UA-Mobile",
  "Sec-CH-UA-Platform",
  "Sec-CH-UA-Arch",
  "Sec-CH-UA-Bitness",
  "Sec-CH-UA-Full-Version-List",
  "Sec-CH-UA-Model",
  "Sec-CH-UA-Platform-Version",
  "Sec-CH-UA-WoW64",
  "Viewport-Width",
  "Width",
  "DPR",
  "Device-Memory",
  "Downlink",
  "ECT",
  "RTT",
  "Save-Data",
].join(", ");

const SAFE_REQUEST_HEADERS = [
  "user-agent",
  "accept",
  "accept-language",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-full-version",
  "sec-ch-ua-full-version-list",
  "sec-ch-ua-arch",
  "sec-ch-ua-bitness",
  "sec-ch-ua-model",
  "sec-ch-ua-wow64",
  "viewport-width",
  "width",
  "dpr",
  "device-memory",
  "downlink",
  "ect",
  "rtt",
  "save-data",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "dnt",
];

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

const REPORT_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_REPORT_BYTES = 64 * 1024;
const REPORT_ID_PATTERN = /^[a-f0-9]{32}$/;
const ASSESSMENT_CLASSES = new Set(["mobile", "desktop", "conflict", "neutral"]);

function withCommonHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("Accept-CH", ACCEPT_CH);
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Security-Policy", CSP);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function safeHeaders(headers) {
  return Object.fromEntries(
    SAFE_REQUEST_HEADERS.flatMap((name) => {
      const value = headers.get(name);
      return value === null ? [] : [[name, value]];
    }),
  );
}

function jsonResponse(payload, { status = 200, method = "GET" } = {}) {
  const body = method === "HEAD" ? null : JSON.stringify(payload, null, 2);
  return withCommonHeaders(
    new Response(body, {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    }),
  );
}

function htmlResponse(html, { status = 200, method = "GET" } = {}) {
  const response = withCommonHeaders(
    new Response(method === "HEAD" ? null : html, {
      status,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }),
  );
  response.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  return response;
}

function methodNotAllowed(method, allow) {
  const response = jsonResponse({ error: "Method not allowed" }, { status: 405, method });
  response.headers.set("Allow", allow);
  return response;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value) {
  return isRecord(value) ? value : {};
}

function defined(value) {
  return value !== undefined && value !== null && value !== "";
}

function displayValue(value) {
  if (!defined(value)) return "未提供";
  if (typeof value === "boolean") return value ? "是 / true" : "否 / false";
  if (Array.isArray(value)) {
    if (!value.length) return "空数组";
    if (value.every((item) => typeof item === "string")) return value.join(", ");
    return JSON.stringify(value, null, 2);
  }
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function formatDimension(width, height, unit = "px") {
  if (!defined(width) || !defined(height)) return "未提供";
  return `${width} × ${height} ${unit}`;
}

function brandList(brands) {
  if (!Array.isArray(brands) || !brands.length) return null;
  return brands
    .filter((item) => isRecord(item))
    .map((item) => `${displayValue(item.brand)} ${displayValue(item.version)}`)
    .join(" | ");
}

function validDiagnosticData(data) {
  if (
    !isRecord(data) ||
    typeof data.generatedAt !== "string" ||
    !Number.isFinite(Date.parse(data.generatedAt))
  ) {
    return false;
  }

  const requiredRecords = [
    data.page,
    data.userAgent,
    data.display,
    data.input,
    data.device,
    data.locale,
    data.clientHints,
    data.server,
    data.analysis,
  ];
  if (!requiredRecords.every(isRecord)) return false;
  if (!isRecord(data.display.screen) || !isRecord(data.display.viewport)) return false;
  if (!isRecord(data.server.headers)) return false;
  if (!Array.isArray(data.analysis.findings) || !data.analysis.findings.every((item) => typeof item === "string")) {
    return false;
  }
  if (!Array.isArray(data.analysis.uaTokens) || !data.analysis.uaTokens.every((item) => typeof item === "string")) {
    return false;
  }
  return (
    typeof data.analysis.assessment === "string" &&
    typeof data.analysis.source === "string" &&
    ASSESSMENT_CLASSES.has(data.analysis.assessmentClass)
  );
}

function formatReportDate(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "时间未知";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
    hour12: false,
    timeZone: "Asia/Shanghai",
  }).format(date);
}

function detailGroups(data) {
  const analysis = record(data.analysis);
  const server = record(data.server);
  const serverHeaders = record(server.headers);
  const clientHints = record(data.clientHints);
  const high = record(clientHints.highEntropy);
  const low = record(clientHints.lowEntropy);
  const display = record(data.display);
  const screen = record(display.screen);
  const viewport = record(display.viewport);
  const estimatedPhysicalScreen = record(display.estimatedPhysicalScreen);
  const userAgent = record(data.userAgent);
  const input = record(data.input);
  const device = record(data.device);
  const locale = record(data.locale);
  const page = record(data.page);

  return [
    {
      title: "User-Agent 与判定信号",
      open: true,
      rows: [
        { label: "navigator.userAgent", value: userAgent.navigatorUserAgent },
        { label: "服务器收到的 User-Agent", value: serverHeaders["user-agent"] },
        { label: "UA 移动关键词", value: analysis.uaTokens?.length ? analysis.uaTokens : "未命中" },
        { label: "navigator.platform", value: userAgent.platform },
        { label: "navigator.vendor", value: userAgent.vendor },
        { label: "navigator.appVersion", value: userAgent.appVersion },
      ],
    },
    {
      title: "Client Hints",
      open: true,
      rows: [
        { label: "JavaScript API 支持", value: clientHints.supported },
        { label: "brands", value: brandList(low.brands) },
        { label: "mobile", value: low.mobile },
        { label: "platform", value: low.platform },
        { label: "fullVersionList", value: brandList(high.fullVersionList) },
        { label: "architecture", value: high.architecture },
        { label: "bitness", value: high.bitness },
        { label: "model", value: high.model },
        { label: "platformVersion", value: high.platformVersion },
        { label: "formFactors", value: high.formFactors },
        { label: "wow64", value: high.wow64 },
        { label: "读取说明", value: clientHints.reason },
      ],
    },
    {
      title: "屏幕与视口",
      open: true,
      rows: [
        { label: "screen.width × height", value: formatDimension(screen.width, screen.height) },
        {
          label: "screen.availWidth × availHeight",
          value: formatDimension(screen.availWidth, screen.availHeight),
        },
        {
          label: "window.innerWidth × innerHeight",
          value: formatDimension(viewport.innerWidth, viewport.innerHeight),
        },
        {
          label: "document.clientWidth × clientHeight",
          value: formatDimension(viewport.clientWidth, viewport.clientHeight),
        },
        {
          label: "window.outerWidth × outerHeight",
          value: formatDimension(viewport.outerWidth, viewport.outerHeight),
        },
        { label: "devicePixelRatio", value: display.devicePixelRatio },
        {
          label: "估算物理像素",
          value: formatDimension(estimatedPhysicalScreen.width, estimatedPhysicalScreen.height),
        },
        { label: "Visual Viewport", value: display.visualViewport },
        { label: "屏幕方向", value: screen.orientation },
        { label: "colorDepth / pixelDepth", value: `${screen.colorDepth} / ${screen.pixelDepth}` },
      ],
    },
    {
      title: "触控与输入设备",
      rows: [
        { label: "maxTouchPoints", value: input.maxTouchPoints },
        { label: "Touch Event 可用", value: input.touchEventAvailable },
        { label: "主指针为 coarse", value: input.pointerCoarse },
        { label: "主指针为 fine", value: input.pointerFine },
        { label: "主指针支持 hover", value: input.hover },
        { label: "任一指针为 coarse", value: input.anyPointerCoarse },
        { label: "任一指针为 fine", value: input.anyPointerFine },
        { label: "任一指针支持 hover", value: input.anyHover },
      ],
    },
    {
      title: "设备、语言与网络",
      rows: [
        { label: "逻辑处理器数量", value: device.hardwareConcurrency },
        { label: "设备内存（GiB，近似）", value: device.deviceMemoryGiB },
        { label: "浏览器语言", value: locale.language },
        { label: "语言列表", value: locale.languages },
        { label: "时区", value: locale.timeZone },
        { label: "区域设置", value: locale.locale },
        { label: "在线状态", value: device.online },
        { label: "独立应用显示模式", value: device.standaloneDisplay },
        { label: "网络信息", value: data.network },
      ],
    },
    {
      title: "服务器实际收到的请求头",
      rows: [
        { label: "回显接口状态", value: server.available ? "可用" : server.reason },
        ...Object.entries(serverHeaders).map(([label, value]) => ({ label, value })),
      ],
    },
    {
      title: "页面环境",
      rows: [
        { label: "生成时间（ISO 8601）", value: data.generatedAt },
        { label: "页面地址（已移除参数）", value: page.urlWithoutQuery },
        { label: "协议", value: page.protocol },
        { label: "安全上下文", value: page.secureContext },
        { label: "Cookie 是否启用", value: device.cookieEnabled },
        { label: "Do Not Track", value: device.doNotTrack },
        { label: "PDF 查看器", value: device.pdfViewerEnabled },
      ],
    },
  ];
}

function renderSignal({ label, value, note }) {
  return `<div class="signal">
    <span class="signal__label">${escapeHtml(label)}</span>
    <strong class="signal__value">${escapeHtml(value)}</strong>
    <span class="signal__note">${escapeHtml(note)}</span>
  </div>`;
}

function renderDetailGroup(group) {
  const rows = group.rows.map(({ label, value }) => {
    const text = displayValue(value);
    const missingClass = text === "未提供" ? " value--missing" : "";
    return `<div class="kv-row">
      <dt>${escapeHtml(label)}</dt>
      <dd class="${missingClass.trim()}"><code>${escapeHtml(text)}</code></dd>
    </div>`;
  }).join("");

  return `<details class="detail-group"${group.open ? " open" : ""}>
    <summary><span>${escapeHtml(group.title)}<span class="detail-group__count">${group.rows.length} 项</span></span></summary>
    <dl class="kv-list">${rows}</dl>
  </details>`;
}

function reportModel(data) {
  const analysis = record(data.analysis);
  const server = record(data.server);
  const display = record(data.display);
  const viewport = record(display.viewport);
  const chValue = analysis.serverMobile ?? analysis.jsMobile;
  const chText = chValue === true ? "移动端" : chValue === false ? "非移动端" : "未提供";
  const chNote = analysis.serverMobile !== null && analysis.serverMobile !== undefined
    ? `服务器：${analysis.serverMobile ? "?1" : "?0"}`
    : analysis.jsMobile !== null && analysis.jsMobile !== undefined
      ? "来自浏览器 JavaScript API"
      : "当前浏览器未返回";
  const uaTokens = Array.isArray(analysis.uaTokens) ? analysis.uaTokens : [];
  const finding = analysis.findings.length
    ? `发现需要关注的信号：${analysis.findings.join("；")}。`
    : server.available && (analysis.serverMobile !== null || analysis.jsMobile !== null)
      ? "当前 UA 关键词与 Client Hints 未发现明显冲突。设备跳转仍应优先尊重用户主动选择。"
      : "当前信息不足以交叉验证 UA 与 Client Hints。";

  return {
    assessment: analysis.assessment,
    assessmentClass: analysis.assessmentClass,
    finding,
    findingClass: analysis.findings.length
      ? "warning"
      : server.available && (analysis.serverMobile !== null || analysis.jsMobile !== null)
        ? "ok"
        : "neutral",
    signals: [
      { label: "Client Hints", value: chText, note: chNote },
      {
        label: "UA 关键词",
        value: uaTokens.length ? "含移动特征" : "未见移动特征",
        note: uaTokens.length ? `命中：${uaTokens.join("、")}` : "仅做关键词检查",
      },
      {
        label: "视口 / DPR",
        value: `${displayValue(viewport.innerWidth)} × ${displayValue(viewport.innerHeight)}`,
        note: `DPR ${displayValue(display.devicePixelRatio)}`,
      },
      {
        label: "服务器回显",
        value: server.available ? "已捕获" : "未连接",
        note: server.available ? "已读取实际请求头" : displayValue(server.reason),
      },
    ],
    groups: detailGroups(data),
  };
}

function parseLegacyReport(report) {
  const metadata = new Map();
  const groups = [];
  let currentGroup = null;
  let lastRow = null;

  for (const rawLine of report.split("\n")) {
    const line = rawLine.trimEnd();
    const sectionMatch = line.match(/^\[(.+)]$/);
    if (sectionMatch) {
      currentGroup = { title: sectionMatch[1], rows: [], open: groups.length < 3 };
      groups.push(currentGroup);
      lastRow = null;
      continue;
    }
    if (!line.trim() || line === "浏览器诊断报告" || /^=+$/.test(line)) continue;
    if (/^\s/.test(rawLine) && lastRow) {
      lastRow.value += `\n${line}`;
      continue;
    }
    const separator = line.indexOf(":");
    if (separator > 0) {
      lastRow = { label: line.slice(0, separator).trim(), value: line.slice(separator + 1).trim() };
      if (currentGroup) currentGroup.rows.push(lastRow);
      else metadata.set(lastRow.label, lastRow.value);
    } else if (lastRow) {
      lastRow.value += `\n${line}`;
    }
  }

  const sectionTitles = new Map([
    ["User-Agent", "User-Agent 与判定信号"],
    ["Client Hints - JavaScript", "Client Hints（JavaScript）"],
    ["Client Hints - Server Request Headers", "Client Hints（服务器请求头）"],
    ["Display", "屏幕与视口"],
    ["Input", "触控与输入设备"],
    ["Device / Locale / Network", "设备、语言与网络"],
    ["Server Header Echo", "服务器实际收到的请求头"],
  ]);
  for (const group of groups) group.title = sectionTitles.get(group.title) || group.title;

  const findValue = (label) => {
    for (const group of groups) {
      const row = group.rows.find((item) => item.label === label);
      if (row) return row.value;
    }
    return null;
  };
  const assessment = metadata.get("快速判定") || "历史诊断报告";
  const lowerAssessment = assessment.toLowerCase();
  const assessmentClass = lowerAssessment.includes("冲突")
    ? "conflict"
    : lowerAssessment.includes("非移动")
      ? "desktop"
      : lowerAssessment.includes("移动")
        ? "mobile"
        : "neutral";
  const conflict = metadata.get("信号冲突");
  const secChMobile = findValue("sec-ch-ua-mobile") || findValue("mobile") || "未提供";
  const viewport = findValue("layout viewport") || "未提供";
  const dpr = findValue("devicePixelRatio") || findValue("dpr") || "未提供";

  return {
    assessment,
    assessmentClass,
    finding: conflict && conflict !== "未发现明显冲突"
      ? `发现需要关注的信号：${conflict}。`
      : "这是旧版报告，内容已按诊断类别重新整理。",
    findingClass: conflict && conflict !== "未发现明显冲突" ? "warning" : "neutral",
    signals: [
      { label: "Client Hints", value: secChMobile, note: "移动端信号" },
      { label: "UA 关键词", value: findValue("UA 移动关键词") || "未提供", note: "关键词检查" },
      { label: "视口 / DPR", value: viewport, note: `DPR ${dpr}` },
      { label: "服务器回显", value: findValue("status") || "未提供", note: "历史报告数据" },
    ],
    groups,
  };
}

function reportPage({ model, generatedAt, createdAt, expiresAt }) {
  const generatedLabel = formatReportDate(generatedAt || createdAt);
  const expiresLabel = formatReportDate(expiresAt);
  const signals = model.signals.map(renderSignal).join("");
  const groups = model.groups.map(renderDetailGroup).join("");

  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <meta name="color-scheme" content="light dark" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <title>浏览器诊断报告</title>
    <link rel="icon" href="/diagnostic-mark.svg" type="image/svg+xml" />
    <link rel="stylesheet" href="/styles.css" />
    <link rel="stylesheet" href="/report.css" />
  </head>
  <body>
    <header class="topbar">
      <div class="topbar__inner">
        <div class="brand">
          <img class="brand__mark" src="/diagnostic-mark.svg" alt="" width="42" height="42" />
          <div>
            <h1>浏览器诊断报告</h1>
            <p>生成于 ${escapeHtml(generatedLabel)}（北京时间）</p>
          </div>
        </div>
      </div>
    </header>
    <main class="report-view">
      <section class="privacy-band" aria-label="报告有效期">
        <div class="content-width privacy-band__inner">
          <span class="privacy-band__indicator" aria-hidden="true"></span>
          <p>这是本次访问的只读诊断快照</p>
          <span class="collection-status">有效至 ${escapeHtml(expiresLabel)}（北京时间）</span>
        </div>
      </section>
      <section class="summary-section content-width" aria-labelledby="reportSummaryTitle">
        <div class="section-heading">
          <div>
            <p class="eyebrow">报告结论</p>
            <h2 id="reportSummaryTitle">快速检查</h2>
          </div>
          <div class="assessment assessment--${escapeHtml(model.assessmentClass)}">${escapeHtml(model.assessment)}</div>
        </div>
        <div class="signal-grid">${signals}</div>
        <div class="finding finding--${escapeHtml(model.findingClass)}">${escapeHtml(model.finding)}</div>
      </section>
      <section class="details-band">
        <div class="content-width">
          <div class="section-heading section-heading--details">
            <div>
              <p class="eyebrow">原始数据</p>
              <h2>诊断明细</h2>
            </div>
            <p class="section-note">“未提供”表示浏览器或服务器没有返回该字段。</p>
          </div>
          <div class="detail-sections">${groups}</div>
        </div>
      </section>
    </main>
  </body>
</html>`;
}

function unavailableReportPage() {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <title>报告不可用</title>
    <link rel="stylesheet" href="/styles.css" />
    <link rel="stylesheet" href="/report.css" />
  </head>
  <body class="report-unavailable">
    <main>
      <h1>报告不可用</h1>
      <p>报告不存在、已过期或仍在同步，请稍后刷新。</p>
    </main>
  </body>
</html>`;
}

async function createReport(request, env, url) {
  if (!env.REPORTS) {
    return jsonResponse({ error: "Report storage unavailable" }, { status: 503 });
  }

  if (request.headers.get("Origin") !== url.origin) {
    return jsonResponse({ error: "Invalid origin" }, { status: 403 });
  }

  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) {
    return jsonResponse({ error: "Content-Type must be application/json" }, { status: 415 });
  }

  let rawPayload;
  try {
    rawPayload = await request.text();
  } catch {
    return jsonResponse({ error: "Invalid request body" }, { status: 400 });
  }
  if (new TextEncoder().encode(rawPayload).byteLength > MAX_REPORT_BYTES + 1024) {
    return jsonResponse({ error: "Report too large" }, { status: 413 });
  }

  let payload;
  try {
    payload = JSON.parse(rawPayload);
  } catch {
    return jsonResponse({ error: "Invalid JSON" }, { status: 400 });
  }

  const data = payload?.data;
  const serializedData = JSON.stringify(data);
  const reportBytes = new TextEncoder().encode(serializedData || "").byteLength;
  if (!validDiagnosticData(data) || reportBytes > MAX_REPORT_BYTES) {
    return jsonResponse({ error: "Invalid report" }, { status: 400 });
  }

  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const id = Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + REPORT_TTL_SECONDS * 1000);
  await env.REPORTS.put(
    `report:${id}`,
    JSON.stringify({ version: 2, data, createdAt: createdAt.toISOString(), expiresAt: expiresAt.toISOString() }),
    { expirationTtl: REPORT_TTL_SECONDS },
  );

  return jsonResponse(
    {
      id,
      path: `/r/${id}`,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    },
    { status: 201 },
  );
}

async function viewReport(id, env, method) {
  if (!env.REPORTS || !REPORT_ID_PATTERN.test(id)) {
    return htmlResponse(unavailableReportPage(), { status: 404, method });
  }

  const stored = await env.REPORTS.get(`report:${id}`);
  if (!stored) return htmlResponse(unavailableReportPage(), { status: 404, method });

  try {
    const entry = JSON.parse(stored);
    const createdAtMs = Date.parse(entry.createdAt);
    const expiresAtMs = Date.parse(entry.expiresAt);
    if (
      !Number.isFinite(createdAtMs) ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now()
    ) {
      return htmlResponse(unavailableReportPage(), { status: 404, method });
    }

    if (entry.version === 2 && validDiagnosticData(entry.data)) {
      return htmlResponse(
        reportPage({
          model: reportModel(entry.data),
          generatedAt: entry.data.generatedAt,
          createdAt: entry.createdAt,
          expiresAt: entry.expiresAt,
        }),
        { method },
      );
    }
    if (entry.version === 1 && typeof entry.report === "string") {
      return htmlResponse(
        reportPage({
          model: parseLegacyReport(entry.report),
          generatedAt: entry.createdAt,
          createdAt: entry.createdAt,
          expiresAt: entry.expiresAt,
        }),
        { method },
      );
    }
    return htmlResponse(unavailableReportPage(), { status: 404, method });
  } catch {
    return htmlResponse(unavailableReportPage(), { status: 404, method });
  }
}

export default {
  async fetch(request, env) {
    const method = request.method.toUpperCase();
    const url = new URL(request.url);

    if (url.pathname === "/api/reports") {
      if (method !== "POST") return methodNotAllowed(method, "POST");
      return createReport(request, env, url);
    }

    const reportMatch = url.pathname.match(/^\/r\/([^/]+)\/?$/);
    if (reportMatch) {
      if (method !== "GET" && method !== "HEAD") return methodNotAllowed(method, "GET, HEAD");
      return viewReport(reportMatch[1], env, method);
    }

    if (method !== "GET" && method !== "HEAD") {
      return methodNotAllowed(method, "GET, HEAD");
    }

    if (url.pathname === "/api/headers") {
      return jsonResponse(
        {
          receivedAt: new Date().toISOString(),
          headers: safeHeaders(request.headers),
        },
        { method },
      );
    }

    if (url.pathname === "/health") {
      return jsonResponse({ status: "ok" }, { method });
    }

    return withCommonHeaders(await env.ASSETS.fetch(request));
  },
};
