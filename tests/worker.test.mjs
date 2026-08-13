import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import worker from "../src/index.js";

const assetRequests = [];
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
};

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

test("ships the expected static page", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  const script = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(html, /浏览器诊断信息/);
  assert.match(html, /快速检查/);
  assert.match(html, /诊断明细/);
  assert.match(html, /下载 JSON/);
  assert.match(html, /复制完整报告/);
  assert.doesNotMatch(html, /回传内容预览|复制这段内容|reportPreview/);
  assert.match(html, /\.\/app\.js/);
  assert.match(script, /copyText\(currentReport\)/);
  assert.doesNotMatch(script, /reportPreview|copyPreviewButton/);
});
