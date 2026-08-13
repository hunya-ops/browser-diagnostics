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

export default {
  async fetch(request, env) {
    const method = request.method.toUpperCase();
    const url = new URL(request.url);

    if (method !== "GET" && method !== "HEAD") {
      return jsonResponse(
        { error: "Method not allowed" },
        { status: 405, method },
      );
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
