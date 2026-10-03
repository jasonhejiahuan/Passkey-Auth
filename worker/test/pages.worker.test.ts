import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { afterAll, beforeAll, expect, it } from "vitest";

let worker: Miniflare;
beforeAll(async () => {
  const bundle = await build({
    stdin: {
      contents: `import { renderPage } from './src/pages.ts';
        export default { fetch() { return new Response(renderPage('oauth_authorize.html', {
          ok: true, screen_hint: 'signup', username: 'Worker <test>', client_id: 'test-client',
          redirect_uri: 'https://client.example/callback', state: 'state', auth_flow_token: 'synthetic-flow'
        }), { headers: {'Content-Type': 'text/html; charset=utf-8'} }); } };`,
      resolveDir: process.cwd(),
    },
    bundle: true,
    write: false,
    format: "esm",
    platform: "browser",
  });
  worker = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: bundle.outputFiles[0].text,
      compatibilityDate: "2026-10-01",
    }),
  );
});
afterAll(async () => {
  await worker?.dispose();
});

it("renders original inherited templates inside workerd without runtime compilation", async () => {
  const response = await worker.dispatchFetch("https://auth.example/");
  expect(response.status).toBe(200);
  const html = await response.text();
  expect(html).toContain("为 Worker &lt;test&gt; 创建 Passkey");
  expect(html).toContain('id="oauth-logo-button"');
  expect(html).toContain('src="/static/oauth_authorize.js"');
});
