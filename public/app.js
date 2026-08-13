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

const copyButton = document.getElementById("copyButton");
const copyButtonLabel = document.getElementById("copyButtonLabel");
const statusText = document.getElementById("statusText");

let currentReport = "";
let feedbackTimer = null;

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
  return {
    type: screen.orientation?.type ?? null,
    angle: screen.orientation?.angle ?? window.orientation ?? null,
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
      reason: "当前为本地文件，未经过诊断服务器",
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
      reason: `服务器请求头读取失败：${error?.message || "未知错误"}`,
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
  const uaTokens = matchedUaTokens(serverUa || browserUa);
  const serverMobile = parseServerMobile(data.server.headers["sec-ch-ua-mobile"]);
  const jsMobile = data.clientHints.lowEntropy?.mobile ?? null;
  const preferredMobile = serverMobile ?? jsMobile;
  const findings = [];

  if (preferredMobile === false && uaTokens.length) {
    findings.push(`UA 命中移动关键词（${uaTokens.join("、")}），但 Client Hints 为非移动端`);
  }
  if (preferredMobile === true && !uaTokens.length) {
    findings.push("Client Hints 为移动端，但 UA 未命中常见移动关键词");
  }
  if (serverUa && browserUa && serverUa !== browserUa) {
    findings.push("服务器收到的 User-Agent 与 navigator.userAgent 不一致");
  }
  if (serverMobile !== null && jsMobile !== null && serverMobile !== jsMobile) {
    findings.push("服务器与浏览器 API 返回的移动端 Client Hint 不一致");
  }

  return {
    result:
      preferredMobile === true
        ? "移动端"
        : preferredMobile === false
          ? "非移动端"
          : uaTokens.length
            ? "UA 含移动特征"
            : "UA 未见移动特征",
    uaTokens,
    serverMobile,
    jsMobile,
    findings,
  };
}

function displayValue(value) {
  if (value === undefined || value === null || value === "") return "未提供";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    if (value.every((item) => typeof item === "string")) return value.join(", ");
  }
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatDimension(width, height) {
  if (width === undefined || height === undefined) return "未提供";
  return `${width} x ${height} px`;
}

function brandList(brands) {
  if (!Array.isArray(brands) || !brands.length) return null;
  return brands.map((item) => `${item.brand} ${item.version}`).join(" | ");
}

function reportLine(label, value) {
  return `${label}: ${displayValue(value)}`;
}

function buildReport(data) {
  const analysis = analyze(data);
  const serverHeaders = data.server.headers;
  const low = data.clientHints.lowEntropy || {};
  const high = data.clientHints.highEntropy || {};

  return [
    "浏览器诊断报告",
    "================",
    reportLine("生成时间", data.generatedAt),
    reportLine("页面地址（已移除参数）", data.page.urlWithoutQuery),
    reportLine("设备判定", analysis.result),
    reportLine("信号冲突", analysis.findings.length ? analysis.findings.join("；") : "未发现明显冲突"),
    "",
    "[User-Agent]",
    reportLine("navigator.userAgent", data.userAgent.navigatorUserAgent),
    reportLine("server.user-agent", serverHeaders["user-agent"]),
    reportLine("UA 移动关键词", analysis.uaTokens.length ? analysis.uaTokens.join(", ") : "未命中"),
    reportLine("navigator.platform", data.userAgent.platform),
    reportLine("navigator.vendor", data.userAgent.vendor),
    reportLine("navigator.appVersion", data.userAgent.appVersion),
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
  ].join("\n");
}

async function collect() {
  copyButton.disabled = true;
  copyButtonLabel.textContent = "复制完整报告";
  statusText.textContent = "正在准备设备信息";
  statusText.className = "status";

  try {
    const local = collectLocalData();
    const [clientHints, server] = await Promise.all([readClientHints(), readServerHeaders()]);
    currentReport = buildReport({ ...local, clientHints, server });
    copyButton.disabled = false;
    copyButtonLabel.textContent = "复制完整报告";
    statusText.textContent = "信息已准备好";
  } catch {
    currentReport = "";
    copyButtonLabel.textContent = "暂时无法复制";
    statusText.textContent = "准备失败，请刷新页面后重试";
    statusText.className = "status is-error";
  }
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
  if (!copied) throw new Error("copy failed");
}

async function handleCopy() {
  if (!currentReport) return;
  clearTimeout(feedbackTimer);

  try {
    await copyText(currentReport);
    copyButtonLabel.textContent = "复制成功";
    copyButton.classList.add("is-copied");
    statusText.textContent = "请返回并把内容发送给工作人员";
    statusText.className = "status is-success";

    feedbackTimer = setTimeout(() => {
      copyButtonLabel.textContent = "复制完整报告";
      copyButton.classList.remove("is-copied");
    }, 2400);
  } catch {
    statusText.textContent = "复制失败，请刷新页面后重试";
    statusText.className = "status is-error";
  }
}

copyButton.addEventListener("click", handleCopy);
collect();
