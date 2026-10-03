import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  registerClientJavaScript,
  renderPage,
  type TemplateName,
} from "../src/pages";
import originals from "./fixtures/original-pages.json";

// Layout whitespace between tags is immaterial; authored text/pre contents remain.
const normalize = (html: string) => html.trim().replace(/>\s+</g, "><");

describe("original Python page parity", () => {
  for (const fixture of originals) {
    it(fixture.name, () => {
      expect(
        normalize(
          renderPage(fixture.template as TemplateName, fixture.context),
        ),
      ).toBe(normalize(fixture.html));
    });
  }
});

describe("page boundaries", () => {
  it("keeps self-service Passkeys in the native account entry and user controls separate from global settings", () => {
    const home = renderPage("index.html", {
      home_auth_enabled: true,
      account_passkeys_enabled: true,
      account_signed_in: true,
    });
    expect(home).toContain('id="account-passkeys-dialog"');
    expect(home).toContain('id="account-passkeys-add"');
    expect(home).toContain('src="/static/account_passkeys.js"');
    expect(home).not.toMatch(/id="account-passkeys-button"[^>]* hidden/);
    const anonymous = renderPage("index.html", {
      home_auth_enabled: true,
      account_passkeys_enabled: true,
      account_signed_in: false,
    });
    expect(anonymous).toMatch(/id="account-passkeys-button"[^>]* hidden/);
    const management = renderPage("management.html", {
      csrf_token: "test-csrf",
      account_passkeys_enabled: true,
    });
    expect(management).toContain('id="account-passkeys-button"');
    expect(management).toContain("我的 Passkeys");
  });

  it("escapes user text and authorization dataset values", () => {
    const hostile = '<img src=x onerror="alert(1)"> & \' quote';
    const html = renderPage("oauth_authorize.html", {
      ok: true,
      mode: "code",
      screen_hint: "signup",
      username: hostile,
      client_id: hostile,
      redirect_uri: hostile,
      state: hostile,
      auth_flow_token: "synthetic-flow",
    });
    expect(html).not.toContain("<img src=x");
    expect(html).toContain(
      "&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39; quote",
    );
    expect(html).toContain('data-state="&lt;img');
  });

  it("preserves debug fields but never displays credentials or bearer tokens", () => {
    const context = {
      ok: true,
      callback_params: {
        code: "secret-code",
        state: "display-state",
        result_token: "secret-result",
        challenge_result: "secret-challenge-result",
      },
      token_response: {
        access_token: "secret-access",
        refresh_token: "secret-refresh",
        token_type: "Bearer",
        nested: { client_secret: "secret-client" },
      },
      userinfo_response: { username: "Example user", sub: "public-sub" },
    };
    const html = renderPage("third_party_result.html", context);
    expect(html).not.toContain("secret-");
    expect(html).toContain("[redacted]");
    expect(html).toContain("public-sub");
    expect(html).toContain("display-state");
    expect(context.token_response.access_token).toBe("secret-access");
  });

  it("makes JSON HTML-safe while retaining its original readable representation", () => {
    const html = renderPage("third_party_result.html", {
      ok: false,
      callback_params: { value: '</pre><script>alert("x")</script> & 用户' },
      token_response: null,
      userinfo_response: null,
    });
    expect(html).not.toContain("<script>");
    expect(html).toContain("\\u003c/pre\\u003e\\u003cscript\\u003e");
    expect(html).toContain("\\u0026 \\u7528\\u6237");
  });

  it("has no filesystem template fallback or implicit telemetry injection", () => {
    expect(() => renderPage("../secret.html" as TemplateName)).toThrow(
      "Unknown page template.",
    );
    expect(
      renderPage("index.html", { home_auth_enabled: false }),
    ).not.toContain("<script");
    expect(
      renderPage("management.html", { csrf_token: "synthetic-csrf" }),
    ).not.toContain('src="/static/telemetry.js"');
  });

  it("copies every original static file without a content change", () => {
    const source = fileURLToPath(
      new URL("../../jstu_passkey/static/", import.meta.url),
    );
    const output = fileURLToPath(new URL("../public/static/", import.meta.url));
    const files = readdirSync(source, {
      recursive: true,
      withFileTypes: true,
    }).filter((entry) => entry.isFile());
    expect(files.length).toBeGreaterThan(10);
    for (const file of files) {
      const sourcePath = `${file.parentPath}/${file.name}`;
      const relative = sourcePath.slice(source.length);
      expect(readFileSync(`${output}${relative}`)).toEqual(
        readFileSync(sourcePath),
      );
    }
  });

  it("keeps the lazy registration JavaScript byte-for-byte", () => {
    const pythonSource = readFileSync(
      new URL("../../jstu_passkey/register_client.py", import.meta.url),
      "utf8",
    );
    const original = pythonSource.match(
      /^REGISTER_CLIENT_JS = r'''([\s\S]*?)'''\s*$/,
    )?.[1];
    expect(registerClientJavaScript).toBe(original);
  });
});
