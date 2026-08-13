# Browser Diagnostics

部署在 Cloudflare Workers 上的浏览器诊断信息页，用于收集并回传：

- 浏览器 `User-Agent` 以及常见移动端关键词命中情况
- JavaScript `navigator.userAgentData` 返回的 Client Hints
- 服务器实际收到的 `Sec-CH-UA-*` 等请求头
- 屏幕、视口、DPR、方向、触控、指针、语言、时区和网络能力
- UA 与 `Sec-CH-UA-Mobile` 是否存在明显冲突

页面不会回显 Cookie、Authorization、完整 URL 查询参数、来源页面或本地文件路径。

## 项目结构

```text
public/             静态诊断页面
src/index.js        Worker API 与统一响应头
tests/              Worker 行为测试
wrangler.jsonc      Cloudflare Workers 配置
```

## 本地开发

需要 Node.js 22 或更高版本：

```bash
npm install
npm run dev
```

Wrangler 会在终端显示本地访问地址。也可以直接打开 `public/index.html`，但这种方式无法读取服务器实际收到的请求头，部分 Client Hints 也可能因安全上下文限制而不可用。

## 部署到 Cloudflare Workers

手动部署：

```bash
npm install
npx wrangler login
npm run deploy
```

Worker 会处理 `/api/headers` 和 `/health`，其他请求交给 Workers Static Assets。所有响应都会附加 `Accept-CH`，让后续同源请求携带浏览器允许提供的 Client Hints。

`wrangler.jsonc` 已固定目标 Cloudflare Account。CLI 部署时仍应使用项目独立认证 Profile，避免依赖全局默认登录：

```bash
npx wrangler deploy --profile browser-diagnostics
```

## GitHub 自动部署

1. 在 Cloudflare Dashboard 打开 **Workers & Pages**，创建或选择 `browser-diagnostics` Worker。
2. 进入 **Settings > Build**，连接 `hunya-ops/browser-diagnostics`。
3. Production branch 选择 `main`。
4. Build command 留空。
5. Deploy command 使用 `npx wrangler deploy`。
6. Root directory 留空。

Cloudflare Workers Builds 会使用 `package.json` 中锁定的 Wrangler 版本。生产分支之外的分支默认执行 `npx wrangler versions upload`，生成预览版本。

## 测试

```bash
npm test
```

## 隐私边界

`/api/headers` 只回显代码中明确列出的诊断请求头。Cookie、Authorization、Referer、Cloudflare 访客 IP 和其他未列入白名单的请求头不会出现在报告中。
