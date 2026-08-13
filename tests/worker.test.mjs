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

const sampleReport = [
  "浏览器诊断报告",
  "[User-Agent]",
  "navigator.userAgent: test <script>alert(1)</script>",
  "[Client Hints - JavaScript]",
  "[Display]",
  "[Input]",
  "[Device / Locale / Network]",
  "[Server Header Echo]",
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
      body: JSON.stringify({ report: sampleReport }),
    }),
    env,
  );
  const payload = await response.json();

  assert.equal(response.status, 201);
  assert.match(payload.id, /^[a-f0-9]{32}$/);
  assert.equal(payload.path, `/r/${payload.id}`);
  assert.equal(reportWrites.at(-1).key, `report:${payload.id}`);
  assert.equal(reportWrites.at(-1).options.expirationTtl, 7 * 24 * 60 * 60);
  assert.equal(JSON.parse(reportWrites.at(-1).value).report, sampleReport);
});

test("renders saved reports as escaped, non-indexed HTML", async () => {
  const createResponse = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://diagnostics.example",
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({ report: sampleReport }),
    }),
    env,
  );
  const { path } = await createResponse.json();
  const response = await worker.fetch(new Request(`https://diagnostics.example${path}`), env);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /任何获得此链接的人都可以查看这份报告/);
});

test("rejects invalid report creation requests", async () => {
  const wrongOrigin = await worker.fetch(
    new Request("https://diagnostics.example/api/reports", {
      method: "POST",
      headers: {
        Origin: "https://other.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ report: sampleReport }),
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
      body: JSON.stringify({ report: "not a diagnostic report" }),
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
      report: sampleReport,
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
  assert.match(html, /id="reportLink"/);
  assert.match(html, /id="shareButton"[^>]*disabled/);
  assert.match(html, /临时保存 7 天/);
  assert.doesNotMatch(html, /回传内容预览|复制这段内容|reportPreview/);
  assert.match(html, /\.\/app\.js/);
  assert.match(script, /copyText\(currentReport\)/);
  assert.match(script, /copyButton\.disabled = true/);
  assert.match(script, /copyButton\.disabled = false/);
  assert.match(script, /复制完整报告/);
  assert.match(script, /正在生成报告/);
  assert.match(script, /fetch\("\.\/api\/reports"/);
  assert.match(script, /复制报告链接/);
  assert.match(script, /shareButton\.disabled = !canRetry/);
  assert.doesNotMatch(script, /reportPreview|copyPreviewButton/);
  assert.match(styles, /\.copy-button:disabled/);
  assert.match(styles, /--copy-action: #1677ff/);
  assert.match(reportStyles, /\.report-content/);
});
