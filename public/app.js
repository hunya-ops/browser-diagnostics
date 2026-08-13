const MOBILE_UA_PATTERNS = [
  ["Mobile", /Mobile/i],
  ["Mobi", /Mobi/i],
  ["Android", /Android/i],
  ["iPhone", /iPhone/i],
  ["iPad", /iPad/i],
  ["iPod", /iPod/i],
  ["Windows Phone", /Windows Phone/i],
  ["IEMobile", /IEMobile/i],
  ["Opera Mini", /Opera Mini/i],
  ["BlackBerry", /BlackBerry|BB10/i],
  ["webOS", /webOS/i],
];

const SERVER_HINT_NAMES = [
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
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
];

const elements = {
  collectionStatus: document.getElementById("collectionStatus"),
  assessment: document.getElementById("deviceAssessment"),
  signalGrid: document.getElementById("signalGrid"),
  finding: document.getElementById("finding"),
  detailSections: document.getElementById("detailSections"),
  copyButton: document.getElementById("copyButton"),
  downloadButton: document.getElementById("downloadButton"),
  refreshButton: document.getElementById("refreshButton"),
  toast: document.getElementById("toast"),
};

let currentData = null;
let currentReport = "";
let toastTimer = null;

function defined(value) {
  return value !== undefined && value !== null && value !== "";
}

function readMedia(query) {
  try {
    return window.matchMedia(query).matches;
  } catch {
    return null;
  }
}

function cleanPageUrl() {
  if (location.protocol === "file:") return "file://（本地文件路径已隐藏）";
  return `${location.origin}${location.pathname}`;
}

function orientationData() {
  const orientation = screen.orientation;
  return {
    type: orientation?.type ?? null,
    angle: orientation?.angle ?? window.orientation ?? null,
  };
}

async function readClientHints() {
  const uaData = navigator.userAgentData;
  if (!uaData) {
    return {
      supported: false,
      reason: "navigator.userAgentData 不可用",
      lowEntropy: null,
      highEntropy: null,
    };
  }

  const result = {
    supported: true,
    reason: null,
    lowEntropy: {
      brands: uaData.brands ?? null,
      mobile: typeof uaData.mobile === "boolean" ? uaData.mobile : null,
      platform: uaData.platform ?? null,
    },
    highEntropy: null,
  };

  if (typeof uaData.getHighEntropyValues !== "function") {
    result.reason = "高熵 Client Hints API 不可用";
    return result;
  }

  try {
    result.highEntropy = await uaData.getHighEntropyValues([
      "architecture",
      "bitness",
      "formFactors",
      "fullVersionList",
      "model",
      "platformVersion",
      "uaFullVersion",
      "wow64",
    ]);
  } catch (error) {
    result.reason = `高熵 Client Hints 读取失败：${error?.message || "未知错误"}`;
  }

  return result;
}

async function readServerHeaders() {
  if (location.protocol === "file:") {
    return {
      available: false,
      reason: "当前为直接打开文件，未经过诊断服务器",
      receivedAt: null,
      headers: {},
    };
  }

  try {
    const response = await fetch(`./api/headers?t=${Date.now()}`, {
      cache: "no-store",
      credentials: "omit",
      headers: { "X-UA-Diagnostics": "1" },
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    return {
      available: true,
      reason: null,
      receivedAt: payload.receivedAt ?? null,
      headers: payload.headers ?? {},
    };
  } catch (error) {
    return {
      available: false,
      reason: `服务器回显接口不可用：${error?.message || "未知错误"}`,
      receivedAt: null,
      headers: {},
    };
  }
}

function collectLocalData() {
  const visualViewport = window.visualViewport;
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;

  return {
    generatedAt: new Date().toISOString(),
    page: {
      urlWithoutQuery: cleanPageUrl(),
      protocol: location.protocol,
      secureContext: window.isSecureContext,
      visibilityState: document.visibilityState,
    },
    userAgent: {
      navigatorUserAgent: navigator.userAgent ?? null,
      appVersion: navigator.appVersion ?? null,
      platform: navigator.platform ?? null,
      vendor: navigator.vendor ?? null,
      product: navigator.product ?? null,
    },
    display: {
      screen: {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        orientation: orientationData(),
      },
      viewport: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        clientWidth: document.documentElement.clientWidth,
        clientHeight: document.documentElement.clientHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
      },
      visualViewport: visualViewport
        ? {
            width: Math.round(visualViewport.width * 100) / 100,
            height: Math.round(visualViewport.height * 100) / 100,
            scale: visualViewport.scale,
            offsetLeft: visualViewport.offsetLeft,
            offsetTop: visualViewport.offsetTop,
          }
        : null,
      devicePixelRatio: window.devicePixelRatio ?? null,
      estimatedPhysicalScreen: {
        width: Math.round(screen.width * (window.devicePixelRatio || 1)),
        height: Math.round(screen.height * (window.devicePixelRatio || 1)),
      },
    },
    input: {
      maxTouchPoints: navigator.maxTouchPoints ?? null,
      touchEventAvailable: "ontouchstart" in window,
      pointerCoarse: readMedia("(pointer: coarse)"),
      pointerFine: readMedia("(pointer: fine)"),
      hover: readMedia("(hover: hover)"),
      anyPointerCoarse: readMedia("(any-pointer: coarse)"),
      anyPointerFine: readMedia("(any-pointer: fine)"),
      anyHover: readMedia("(any-hover: hover)"),
    },
    device: {
      hardwareConcurrency: navigator.hardwareConcurrency ?? null,
      deviceMemoryGiB: navigator.deviceMemory ?? null,
      cookieEnabled: navigator.cookieEnabled ?? null,
      online: navigator.onLine ?? null,
      doNotTrack: navigator.doNotTrack ?? null,
      pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
      standaloneDisplay: readMedia("(display-mode: standalone)"),
    },
    locale: {
      language: navigator.language ?? null,
      languages: navigator.languages ? Array.from(navigator.languages) : null,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? null,
      locale: Intl.DateTimeFormat().resolvedOptions().locale ?? null,
    },
    network: connection
      ? {
          effectiveType: connection.effectiveType ?? null,
          downlinkMbps: connection.downlink ?? null,
          rttMs: connection.rtt ?? null,
          saveData: connection.saveData ?? null,
          type: connection.type ?? null,
        }
      : null,
  };
}

function parseServerMobile(value) {
  if (value === "?1") return true;
  if (value === "?0") return false;
  return null;
}

function matchedUaTokens(ua) {
  if (!ua) return [];
  return MOBILE_UA_PATTERNS.filter(([, pattern]) => pattern.test(ua)).map(([label]) => label);
}

function analyze(data) {
  const browserUa = data.userAgent.navigatorUserAgent || "";
  const serverUa = data.server.headers["user-agent"] || "";
  const uaForDetection = serverUa || browserUa;
  const uaTokens = matchedUaTokens(uaForDetection);
  const serverMobile = parseServerMobile(data.server.headers["sec-ch-ua-mobile"]);
  const jsMobile = data.clientHints.lowEntropy?.mobile;
  const preferredMobile = serverMobile ?? jsMobile ?? null;
  const hasUaMobileSignal = uaTokens.length > 0;
  const uaMismatch = Boolean(serverUa && browserUa && serverUa !== browserUa);
  const chMismatch = serverMobile !== null && jsMobile !== null && serverMobile !== jsMobile;
  const conflict =
    (preferredMobile === false && hasUaMobileSignal) ||
    (preferredMobile === true && !hasUaMobileSignal) ||
    uaMismatch ||
    chMismatch;

  let assessment = "信息不足";
  let assessmentClass = "neutral";
  let source = "无可靠设备信号";

  if (conflict) {
    assessment = "信号存在冲突";
    assessmentClass = "conflict";
    source = "请以原始字段排查规则";
  } else if (preferredMobile === true) {
    assessment = "Client Hints：移动端";
    assessmentClass = "mobile";
    source = serverMobile !== null ? "服务器收到 ?1" : "浏览器 API 返回 true";
  } else if (preferredMobile === false) {
    assessment = "Client Hints：非移动端";
    assessmentClass = "desktop";
    source = serverMobile !== null ? "服务器收到 ?0" : "浏览器 API 返回 false";
  } else if (hasUaMobileSignal) {
    assessment = "UA：含移动特征";
    assessmentClass = "mobile";
    source = `命中 ${uaTokens.join("、")}`;
  } else {
    assessment = "UA：未见移动特征";
    assessmentClass = "desktop";
    source = "仅依据 UA 关键词";
  }

  const findings = [];
  if (preferredMobile === false && hasUaMobileSignal) {
    findings.push(`UA 命中移动关键词（${uaTokens.join("、")}），但 Client Hints 报告为非移动端`);
  }
  if (preferredMobile === true && !hasUaMobileSignal) {
    findings.push("Client Hints 报告为移动端，但 UA 未命中常见移动关键词");
  }
  if (uaMismatch) findings.push("服务器收到的 User-Agent 与 navigator.userAgent 不一致");
  if (chMismatch) findings.push("服务器与浏览器 API 返回的移动端 Client Hint 不一致");

  return {
    assessment,
    assessmentClass,
    source,
    conflict,
    findings,
    uaTokens,
    hasUaMobileSignal,
    serverMobile,
    jsMobile,
    uaMismatch,
    chMismatch,
  };
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
  return brands.map((item) => `${item.brand} ${item.version}`).join(" | ");
}

function createSignal(label, value, note) {
  const item = document.createElement("div");
  item.className = "signal";

  const labelNode = document.createElement("span");
  labelNode.className = "signal__label";
  labelNode.textContent = label;

  const valueNode = document.createElement("strong");
  valueNode.className = "signal__value";
  valueNode.textContent = value;

  const noteNode = document.createElement("span");
  noteNode.className = "signal__note";
  noteNode.textContent = note;

  item.append(labelNode, valueNode, noteNode);
  return item;
}

function createDetailGroup(title, rows, open = false) {
  const group = document.createElement("details");
  group.className = "detail-group";
  group.open = open;

  const summary = document.createElement("summary");
  const summaryText = document.createElement("span");
  summaryText.textContent = title;
  const count = document.createElement("span");
  count.className = "detail-group__count";
  count.textContent = `${rows.length} 项`;
  summaryText.append(count);
  summary.append(summaryText);

  const list = document.createElement("dl");
  list.className = "kv-list";

  for (const row of rows) {
    const wrapper = document.createElement("div");
    wrapper.className = "kv-row";
    const term = document.createElement("dt");
    term.textContent = row.label;
    const description = document.createElement("dd");
    const code = document.createElement("code");
    const value = displayValue(row.value);
    code.textContent = value;
    if (value === "未提供") description.classList.add("value--missing");
    description.append(code);
    wrapper.append(term, description);
    list.append(wrapper);
  }

  group.append(summary, list);
  return group;
}

function detailGroups(data, analysis) {
  const serverHeaders = data.server.headers;
  const high = data.clientHints.highEntropy || {};
  const low = data.clientHints.lowEntropy || {};

  return [
    {
      title: "User-Agent 与判定信号",
      open: true,
      rows: [
        { label: "navigator.userAgent", value: data.userAgent.navigatorUserAgent },
        { label: "服务器收到的 User-Agent", value: serverHeaders["user-agent"] },
        { label: "UA 移动关键词", value: analysis.uaTokens.length ? analysis.uaTokens : "未命中" },
        { label: "navigator.platform", value: data.userAgent.platform },
        { label: "navigator.vendor", value: data.userAgent.vendor },
        { label: "navigator.appVersion", value: data.userAgent.appVersion },
      ],
    },
    {
      title: "Client Hints",
      open: true,
      rows: [
        { label: "JavaScript API 支持", value: data.clientHints.supported },
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
        { label: "读取说明", value: data.clientHints.reason },
      ],
    },
    {
      title: "屏幕与视口",
      open: true,
      rows: [
        {
          label: "screen.width × height",
          value: formatDimension(data.display.screen.width, data.display.screen.height),
        },
        {
          label: "screen.availWidth × availHeight",
          value: formatDimension(data.display.screen.availWidth, data.display.screen.availHeight),
        },
        {
          label: "window.innerWidth × innerHeight",
          value: formatDimension(data.display.viewport.innerWidth, data.display.viewport.innerHeight),
        },
        {
          label: "document.clientWidth × clientHeight",
          value: formatDimension(data.display.viewport.clientWidth, data.display.viewport.clientHeight),
        },
        {
          label: "window.outerWidth × outerHeight",
          value: formatDimension(data.display.viewport.outerWidth, data.display.viewport.outerHeight),
        },
        { label: "devicePixelRatio", value: data.display.devicePixelRatio },
        {
          label: "估算物理像素",
          value: formatDimension(
            data.display.estimatedPhysicalScreen.width,
            data.display.estimatedPhysicalScreen.height,
          ),
        },
        { label: "Visual Viewport", value: data.display.visualViewport },
        { label: "屏幕方向", value: data.display.screen.orientation },
        { label: "colorDepth / pixelDepth", value: `${data.display.screen.colorDepth} / ${data.display.screen.pixelDepth}` },
      ],
    },
    {
      title: "触控与输入设备",
      rows: [
        { label: "maxTouchPoints", value: data.input.maxTouchPoints },
        { label: "Touch Event 可用", value: data.input.touchEventAvailable },
        { label: "主指针为 coarse", value: data.input.pointerCoarse },
        { label: "主指针为 fine", value: data.input.pointerFine },
        { label: "主指针支持 hover", value: data.input.hover },
        { label: "任一指针为 coarse", value: data.input.anyPointerCoarse },
        { label: "任一指针为 fine", value: data.input.anyPointerFine },
        { label: "任一指针支持 hover", value: data.input.anyHover },
      ],
    },
    {
      title: "设备、语言与网络",
      rows: [
        { label: "逻辑处理器数量", value: data.device.hardwareConcurrency },
        { label: "设备内存（GiB，近似）", value: data.device.deviceMemoryGiB },
        { label: "浏览器语言", value: data.locale.language },
        { label: "语言列表", value: data.locale.languages },
        { label: "时区", value: data.locale.timeZone },
        { label: "区域设置", value: data.locale.locale },
        { label: "在线状态", value: data.device.online },
        { label: "独立应用显示模式", value: data.device.standaloneDisplay },
        { label: "网络信息", value: data.network },
      ],
    },
    {
      title: "服务器实际收到的请求头",
      rows: [
        { label: "回显接口状态", value: data.server.available ? "可用" : data.server.reason },
        ...Object.entries(serverHeaders).map(([label, value]) => ({ label, value })),
      ],
    },
    {
      title: "页面环境",
      rows: [
        { label: "生成时间（ISO 8601）", value: data.generatedAt },
        { label: "页面地址（已移除参数）", value: data.page.urlWithoutQuery },
        { label: "协议", value: data.page.protocol },
        { label: "安全上下文", value: data.page.secureContext },
        { label: "Cookie 是否启用", value: data.device.cookieEnabled },
        { label: "Do Not Track", value: data.device.doNotTrack },
        { label: "PDF 查看器", value: data.device.pdfViewerEnabled },
      ],
    },
  ];
}

function reportLine(label, value) {
  return `${label}: ${displayValue(value)}`;
}

function buildReport(data, analysis) {
  const serverHeaders = data.server.headers;
  const low = data.clientHints.lowEntropy || {};
  const high = data.clientHints.highEntropy || {};
  const lines = [
    "浏览器诊断报告",
    "================",
    reportLine("生成时间", data.generatedAt),
    reportLine("页面地址（已移除参数）", data.page.urlWithoutQuery),
    reportLine("快速判定", analysis.assessment),
    reportLine("判定依据", analysis.source),
    reportLine("信号冲突", analysis.findings.length ? analysis.findings.join("；") : "未发现明显冲突"),
    "",
    "[User-Agent]",
    reportLine("navigator.userAgent", data.userAgent.navigatorUserAgent),
    reportLine("server.user-agent", serverHeaders["user-agent"]),
    reportLine("UA 移动关键词", analysis.uaTokens.length ? analysis.uaTokens.join(", ") : "未命中"),
    reportLine("navigator.platform", data.userAgent.platform),
    reportLine("navigator.vendor", data.userAgent.vendor),
    "",
    "[Client Hints - JavaScript]",
    reportLine("API 支持", data.clientHints.supported),
    reportLine("brands", brandList(low.brands)),
    reportLine("mobile", low.mobile),
    reportLine("platform", low.platform),
    reportLine("fullVersionList", brandList(high.fullVersionList)),
    reportLine("architecture", high.architecture),
    reportLine("bitness", high.bitness),
    reportLine("model", high.model),
    reportLine("platformVersion", high.platformVersion),
    reportLine("formFactors", high.formFactors),
    reportLine("wow64", high.wow64),
    reportLine("说明", data.clientHints.reason),
    "",
    "[Client Hints - Server Request Headers]",
    ...SERVER_HINT_NAMES.map((name) => reportLine(name, serverHeaders[name])),
    "",
    "[Display]",
    reportLine("screen", formatDimension(data.display.screen.width, data.display.screen.height)),
    reportLine(
      "available screen",
      formatDimension(data.display.screen.availWidth, data.display.screen.availHeight),
    ),
    reportLine(
      "layout viewport",
      formatDimension(data.display.viewport.innerWidth, data.display.viewport.innerHeight),
    ),
    reportLine("visual viewport", data.display.visualViewport),
    reportLine("devicePixelRatio", data.display.devicePixelRatio),
    reportLine(
      "estimated physical screen",
      formatDimension(data.display.estimatedPhysicalScreen.width, data.display.estimatedPhysicalScreen.height),
    ),
    reportLine("orientation", data.display.screen.orientation),
    reportLine("colorDepth", data.display.screen.colorDepth),
    "",
    "[Input]",
    ...Object.entries(data.input).map(([name, value]) => reportLine(name, value)),
    "",
    "[Device / Locale / Network]",
    reportLine("hardwareConcurrency", data.device.hardwareConcurrency),
    reportLine("deviceMemoryGiB", data.device.deviceMemoryGiB),
    reportLine("language", data.locale.language),
    reportLine("languages", data.locale.languages),
    reportLine("timeZone", data.locale.timeZone),
    reportLine("network", data.network),
    reportLine("secureContext", data.page.secureContext),
    "",
    "[Server Header Echo]",
    reportLine("status", data.server.available ? "可用" : data.server.reason),
    ...Object.entries(serverHeaders).map(([name, value]) => reportLine(name, value)),
  ];

  return lines.join("\n");
}

function render(data) {
  const analysis = analyze(data);
  data.analysis = analysis;
  currentReport = buildReport(data, analysis);

  elements.collectionStatus.textContent = data.server.available
    ? "浏览器数据 + 服务器请求头已采集"
    : "浏览器数据已采集，服务器请求头不可用";

  elements.assessment.textContent = analysis.assessment;
  elements.assessment.className = `assessment assessment--${analysis.assessmentClass}`;

  const chValue = analysis.serverMobile ?? analysis.jsMobile;
  const chText = chValue === true ? "移动端" : chValue === false ? "非移动端" : "未提供";
  const chNote = analysis.serverMobile !== null
    ? `服务器：${analysis.serverMobile ? "?1" : "?0"}`
    : analysis.jsMobile !== null
      ? "来自浏览器 JavaScript API"
      : "当前浏览器未返回";
  const uaText = analysis.uaTokens.length ? "含移动特征" : "未见移动特征";
  const uaNote = analysis.uaTokens.length ? `命中：${analysis.uaTokens.join("、")}` : "仅做关键词检查";
  const serverText = data.server.available ? "已捕获" : "未连接";
  const serverNote = data.server.available ? "已读取实际请求头" : data.server.reason;

  elements.signalGrid.replaceChildren(
    createSignal("Client Hints", chText, chNote),
    createSignal("UA 关键词", uaText, uaNote),
    createSignal(
      "视口 / DPR",
      `${data.display.viewport.innerWidth} × ${data.display.viewport.innerHeight}`,
      `DPR ${displayValue(data.display.devicePixelRatio)}`,
    ),
    createSignal("服务器回显", serverText, serverNote),
  );

  if (analysis.findings.length) {
    elements.finding.className = "finding finding--warning";
    elements.finding.textContent = `发现需要关注的信号：${analysis.findings.join("；")}。`;
  } else if (data.server.available && (analysis.serverMobile !== null || analysis.jsMobile !== null)) {
    elements.finding.className = "finding finding--ok";
    elements.finding.textContent = "当前 UA 关键词与 Client Hints 未发现明显冲突。设备跳转仍应优先尊重用户主动选择。";
  } else {
    elements.finding.className = "finding finding--neutral";
    elements.finding.textContent = "当前信息不足以交叉验证 UA 与 Client Hints；请通过本页附带的诊断服务器访问。";
  }

  const groups = detailGroups(data, analysis).map((group) =>
    createDetailGroup(group.title, group.rows, group.open),
  );
  elements.detailSections.replaceChildren(...groups);
}

async function collect() {
  elements.collectionStatus.textContent = "正在采集…";
  elements.refreshButton.disabled = true;

  const local = collectLocalData();
  const [clientHints, server] = await Promise.all([readClientHints(), readServerHeaders()]);
  currentData = { ...local, clientHints, server };
  render(currentData);
  elements.refreshButton.disabled = false;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("浏览器拒绝复制操作");
}

function showToast(message) {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  toastTimer = setTimeout(() => {
    elements.toast.hidden = true;
  }, 2600);
}

async function handleCopy() {
  try {
    await copyText(currentReport);
    showToast("完整诊断报告已复制，可直接发送给技术人员。 ");
  } catch (error) {
    showToast(`复制失败：${error?.message || "请手动选择预览内容"}`);
  }
}

function downloadJson() {
  if (!currentData) return;
  const blob = new Blob([JSON.stringify(currentData, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `browser-diagnostics-${stamp}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast("JSON 文件已生成。 ");
}

elements.copyButton.addEventListener("click", handleCopy);
elements.downloadButton.addEventListener("click", downloadJson);
elements.refreshButton.addEventListener("click", collect);
window.addEventListener("online", collect);
window.addEventListener("offline", collect);

collect();
