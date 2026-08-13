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
const REQUIRED_REPORT_SECTIONS = [
  "浏览器诊断报告",
  "[User-Agent]",
  "[Client Hints - JavaScript]",
  "[Display]",
  "[Input]",
  "[Device / Locale / Network]",
  "[Server Header Echo]",
];

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

function reportPage({ report, createdAt, expiresAt }) {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <meta name="color-scheme" content="light dark" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <title>浏览器诊断报告</title>
    <link rel="icon" href="/diagnostic-mark.svg" type="image/svg+xml" />
    <link rel="stylesheet" href="/report.css" />
  </head>
  <body>
    <header class="report-header">
      <div class="report-width report-header__inner">
        <img src="/diagnostic-mark.svg" alt="" width="42" height="42" />
        <div>
          <h1>浏览器诊断报告</h1>
          <p>生成于 ${escapeHtml(createdAt)} · 有效至 ${escapeHtml(expiresAt)}</p>
        </div>
      </div>
    </header>
    <main class="report-main">
      <div class="report-width">
        <p class="report-notice">任何获得此链接的人都可以查看这份报告</p>
        <pre class="report-content">${escapeHtml(report)}</pre>
      </div>
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

  const report = typeof payload?.report === "string" ? payload.report.trim() : "";
  const reportBytes = new TextEncoder().encode(report).byteLength;
  const validReport = REQUIRED_REPORT_SECTIONS.every((section) => report.includes(section));
  if (!report || !validReport || reportBytes > MAX_REPORT_BYTES) {
    return jsonResponse({ error: "Invalid report" }, { status: 400 });
  }

  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const id = Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + REPORT_TTL_SECONDS * 1000);
  await env.REPORTS.put(
    `report:${id}`,
    JSON.stringify({ version: 1, report, createdAt: createdAt.toISOString(), expiresAt: expiresAt.toISOString() }),
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
    const expiresAtMs = Date.parse(entry.expiresAt);
    if (
      entry.version !== 1 ||
      typeof entry.report !== "string" ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= Date.now()
    ) {
      return htmlResponse(unavailableReportPage(), { status: 404, method });
    }
    return htmlResponse(reportPage(entry), { method });
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
