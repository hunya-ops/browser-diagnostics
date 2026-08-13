import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import worker from "../src/index.js";

const assetRequests = [];
const reportStore = new Map();
const reportWrites = [];
const env = {
  ASSETS: {
    async fetch(request) {
      assetRequests.push(request.url);
      return new Response("<!doctype html><title>浏览器诊断信息</title>", {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          ETag: '"asset-hash"',
        },
      });
    },
  },
  REPORTS: {
    async get(key) {
      return reportStore.get(key) ?? null;
    },
    async put(key, value, options) {
      reportStore.set(key, value);
      reportWrites.push({ key, value, options });
    },
  },
};

const sampleData = {
  generatedAt: "2026-08-13T04:00:00.000Z",
  page: {
    urlWithoutQuery: "https://diagnostics.example/",
    protocol: "https:",
    secureContext: true,
  },
  userAgent: {
    navigatorUserAgent: "test <script>alert(1)</script>",
    appVersion: "test app version",
    platform: "TestOS",
    vendor: "Test Vendor",
  },
  display: {
    screen: {
      width: 1440,
      height: 900,
      availWidth: 1440,
      availHeight: 860,
      colorDepth: 24,
      pixelDepth: 24,
      orientation: { type: "landscape-primary", angle: 0 },
    },
    viewport: {
      innerWidth: 1280,
      innerHeight: 720,
      clientWidth: 1280,
      clientHeight: 720,
      outerWidth: 1280,
      outerHeight: 800,
    },
    visualViewport: { width: 1280, height: 720, scale: 1 },
    devicePixelRatio: 2,
    estimatedPhysicalScreen: { width: 2880, height: 1800 },
  },
  input: {
    maxTouchPoints: 0,
    touchEventAvailable: false,
    pointerCoarse: false,
    pointerFine: true,
    hover: true,
    anyPointerCoarse: false,
    anyPointerFine: true,
    anyHover: true,
  },
  device: {
    hardwareConcurrency: 8,
    deviceMemoryGiB: 8,
    cookieEnabled: true,
    online: true,
    doNotTrack: null,
    pdfViewerEnabled: true,
    standaloneDisplay: false,
  },
  locale: {
    language: "zh-CN",
    languages: ["zh-CN", "zh"],
    timeZone: "Asia/Shanghai",
    locale: "zh-CN",
  },
  network: { effectiveType: "4g", downlinkMbps: 10, rttMs: 50, saveData: false },
  clientHints: {
    supported: true,
    reason: null,
    lowEntropy: {
      brands: [{ brand: "Chromium", version: "151" }],
      mobile: false,
      platform: "TestOS",
    },
    highEntropy: {
      fullVersionList: [{ brand: "Chromium", version: "151.0.0.0" }],
      architecture: "arm",
      bitness: "64",
      model: "",
      platformVersion: "1.0",
      formFactors: ["Desktop"],
      wow64: false,
    },
  },
  server: {
    available: true,
    reason: null,
    receivedAt: "2026-08-13T04:00:00.000Z",
    headers: {
      "user-agent": "server test UA",
      "sec-ch-ua-mobile": "?0",
    },
  },
  analysis: {
    assessment: "Client Hints：非移动端",
    assessmentClass: "desktop",
    source: "服务器收到 ?0",
    conflict: true,
    findings: ["服务器收到的 User-Agent 与 navigator.userAgent 不一致"],
    uaTokens: [],
    hasUaMobileSignal: false,
    serverMobile: false,
    jsMobile: false,
    uaMismatch: true,
    chMismatch: false,
  },
};

const legacyReport = [
  "浏览器诊断报告",
  "================",
  "快速判定: Client Hints：非移动端",
  "信号冲突: 未发现明显冲突",
  "",
  "[User-Agent]",
  "navigator.userAgent: legacy test UA",
  "UA 移动关键词: 未命中",
  "",
  "[Client Hints - Server Request Headers]",
  "sec-ch-ua-mobile: ?0",
  "",
  "[Display]",
  "layout viewport: 1280 × 720 px",
  "devicePixelRatio: 2",
].join("\n");

test("serves assets with Client Hint negotiation and security headers", async () => {
  const response = await worker.fetch(new Request("https://diagnostics.example/"), env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  assert.match(response.headers.get("accept-ch"), /Sec-CH-UA-Mobile/);
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("etag"), '"asset-hash"');
  assert.match(await response.text(), /浏览器诊断信息/);
  assert.equal(assetRequests.at(-1), "https://diagnostics.example/");
});

test("echoes only allowlisted diagnostic request headers", async () => {
  const response = await worker.fetch(new Request("https://diagnostics.example/api/headers", {
    headers: {
      "User-Agent": "Desktop Browser Mobile Token",
      "Sec-CH-UA-Mobile": "?0",
      Cookie: "session=must-not-leak",
      Authorization: "Bearer must-not-leak",
      "X-Private-Value": "must-not-leak",
    },
  }), env);
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.headers["user-agent"], "Desktop Browser Mobile Token");
  assert.equal(payload.headers["sec-ch-ua-mobile"], "?0");
  assert.equal(payload.headers.cookie, undefined);
  assert.equal(payload.headers.authorization, undefined);
  assert.equal(payload.headers["x-private-value"], undefined);
});

test("rejects unsupported methods", async () => {
  const response = await worker.fetch(
    new Request("https://diagnostics.example/api/headers", { method: "POST" }),
    env,
  );
  assert.equal(response.status, 405);
});

test("returns health status without invoking assets", async () => {
  const requestCount = assetRequests.length;
  const response = await worker.fetch(new Request("https://diagnostics.example/health"), env);
  assert.deepEqual(await response.json(), { status: "ok" });
  assert.equal(assetRequests.length, requestCount);
});

test("creates a private report link with a seven-day TTL", async () => {
  const response = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://diagnostics.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: sampleData }),
    }),
    env,
  );
  const payload = await response.json();

  assert.equal(response.status, 201);
  assert.match(payload.id, /^[a-f0-9]{32}$/);
  assert.equal(payload.path, `/r/${payload.id}`);
  assert.equal(reportWrites.at(-1).key, `report:${payload.id}`);
  assert.equal(reportWrites.at(-1).options.expirationTtl, 7 * 24 * 60 * 60);
  assert.equal(JSON.parse(reportWrites.at(-1).value).version, 2);
  assert.deepEqual(JSON.parse(reportWrites.at(-1).value).data, sampleData);
});

test("renders saved reports as escaped, non-indexed HTML", async () => {
  const createResponse = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://diagnostics.example",
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({ data: sampleData }),
    }),
    env,
  );
  const { path } = await createResponse.json();
  const response = await worker.fetch(new Request(`https://diagnostics.example${path}`), env);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
  assert.match(html, /报告结论/);
  assert.match(html, /快速检查/);
  assert.match(html, /Client Hints：非移动端/);
  assert.match(html, /User-Agent 与判定信号/);
  assert.match(html, /服务器实际收到的请求头/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(html, /<pre class="report-content">/);
});

test("renders legacy text reports with the structured report layout", async () => {
  const id = "22222222222222222222222222222222";
  reportStore.set(
    `report:${id}`,
    JSON.stringify({
      version: 1,
      report: legacyReport,
      createdAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }),
  );

  const response = await worker.fetch(new Request(`https://diagnostics.example/r/${id}`), env);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(html, /这是旧版报告，内容已按诊断类别重新整理/);
  assert.match(html, /User-Agent 与判定信号/);
  assert.match(html, /屏幕与视口/);
  assert.doesNotMatch(html, /<pre class="report-content">/);
});

test("rejects invalid report creation requests", async () => {
  const wrongOrigin = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://other.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: sampleData }),
    }),
    env,
  );
  assert.equal(wrongOrigin.status, 403);

  const invalidReport = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://diagnostics.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: { generatedAt: "not a diagnostic report" } }),
    }),
    env,
  );
  assert.equal(invalidReport.status, 400);

  const missingReport = await worker.fetch(
    new Request("https://diagnostics.example/r/00000000000000000000000000000000"),
    env,
  );
  assert.equal(missingReport.status, 404);
  assert.match(await missingReport.text(), /报告不可用/);
});

test("does not render expired or malformed stored reports", async () => {
  const id = "11111111111111111111111111111111";
  reportStore.set(
    `report:${id}`,
    JSON.stringify({
      version: 1,
      report: legacyReport,
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "not-a-date",
    }),
  );

  const response = await worker.fetch(
    new Request(`https://diagnostics.example/r/${id}`),
    env,
  );

  assert.equal(response.status, 404);
  assert.match(await response.text(), /报告不可用/);
});

test("ships the expected static page", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const script = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const styles = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  const reportStyles = await readFile(new URL("../public/report.css", import.meta.url), "utf8");
  assert.match(html, /浏览器诊断信息/);
  assert.match(html, /快速检查/);
  assert.match(html, /诊断明细/);
  assert.match(html, /下载 JSON/);
  assert.match(html, /id="copyButton"[^>]*disabled/);
  assert.match(html, /正在生成报告/);
  assert.doesNotMatch(html, /id="reportLink"|id="shareButton"|复制报告链接/);
  assert.match(html, /临时保存 7 天/);
  assert.doesNotMatch(html, /回传内容预览|复制这段内容|reportPreview/);
  assert.match(html, /\.\/app\.js/);
  assert.match(script, /copyText\(currentReport\)/);
  assert.match(script, /copyButton\.disabled = true/);
  assert.match(script, /copyButton\.disabled = false/);
  assert.match(script, /复制完整报告/);
  assert.match(script, /正在生成报告/);
  assert.match(script, /fetch\("\.\/api\/reports"/);
  assert.match(script, /JSON\.stringify\(\{ data \}\)/);
  assert.match(script, /报告网址（7 天内有效）/);
  assert.doesNotMatch(script, /复制报告链接|shareButton|reportLink/);
  assert.doesNotMatch(script, /reportPreview|copyPreviewButton/);
  assert.match(styles, /\.copy-button:disabled/);
  assert.match(styles, /--copy-action: #1677ff/);
  assert.match(reportStyles, /\.report-view/);
  assert.doesNotMatch(reportStyles, /\.report-content/);
});
