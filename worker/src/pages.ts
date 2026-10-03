import * as nunjucks from "nunjucks/browser/nunjucks-slim.js";
import { templates, type TemplateName } from "./generated/templates.js";

export { registerClientJavaScript } from "./generated/register-client";
export type { TemplateName } from "./generated/templates.js";

// Templates are trusted, build-time compiled functions. The Worker has no template
// compiler, filesystem loader, or route accepting template source from a visitor.
// Upstream typings mistakenly call this constructor's dictionary an array.
const loader = new nunjucks.PrecompiledLoader(
  templates as unknown as ConstructorParameters<
    typeof nunjucks.PrecompiledLoader
  >[0],
);
const environment = new nunjucks.Environment(loader, {
  autoescape: true,
  throwOnUndefined: false,
});

const pagePaths: Record<string, string> = {
  oauth_demo: "/demo/oauth",
  third_party_demo: "/demo/third-party",
  link_login_demo: "/demo/link-login",
  link_login_start: "/demo/link-login/start",
};

environment.addGlobal("None", null);
environment.addGlobal(
  "url_for",
  (endpoint: string, options: { filename?: string } = {}) => {
    if (endpoint === "static") {
      const filename = options.filename;
      if (
        !filename ||
        filename.split("/").some((part) => part === "..") ||
        /[\\?#]/.test(filename)
      ) {
        throw new Error("Invalid static template reference.");
      }
      return `/static/${filename}`;
    }
    const result = pagePaths[endpoint];
    if (!result) throw new Error(`Unknown template endpoint: ${endpoint}`);
    return result;
  },
);

// Flask/Jinja's tojson sorts keys, escapes non-ASCII characters and HTML-sensitive
// characters. Preserve its display while preventing a </script> or tag breakout.
environment.addFilter(
  "tojson",
  (value: unknown, options: { indent?: number } = {}) => {
    const stable = (item: unknown): unknown => {
      if (Array.isArray(item)) return item.map(stable);
      if (item && typeof item === "object") {
        return Object.fromEntries(
          Object.entries(item)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
            .map(([key, child]) => [key, stable(child)]),
        );
      }
      return item;
    };
    const indent =
      typeof options.indent === "number" ? options.indent : undefined;
    let output = JSON.stringify(stable(value), null, indent);
    if (output === undefined) output = "null";
    output = output.replace(
      /[<>&'\u007f-\uffff]/g,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
    return new nunjucks.runtime.SafeString(output);
  },
);

const resultTemplates = new Set<TemplateName>([
  "oauth_result.html",
  "third_party_result.html",
  "link_login_result.html",
]);
const secretField =
  /^(?:code|authorizationcode|accessToken|refreshToken|idToken|clientSecret|codeVerifier|authFlowToken|actionToken|nextActionToken|challengeResult|resultToken|result|token|credential|rawId|session|cookie|authorization|apiKey|privateKey)$/i;

function redactResult(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactResult);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        secretField.test(key.replace(/[_-]/g, ""))
          ? "[redacted]"
          : redactResult(child),
      ]),
    );
  }
  return value;
}

/** Render an original template. Authorization and response headers belong to routes. */
export function renderPage(
  name: string,
  variables: Record<string, unknown> = {},
): string {
  if (!Object.hasOwn(templates, name))
    throw new Error("Unknown page template.");
  const context = resultTemplates.has(name as TemplateName)
    ? (redactResult(variables) as Record<string, unknown>)
    : { ...variables };
  // The original compact result page prints Python's bool, not JSON's bool.
  if (
    name === "oauth_result.html" &&
    context.token_response &&
    typeof context.token_response === "object"
  ) {
    const token = context.token_response as Record<string, unknown>;
    if (typeof token.authenticated === "boolean") {
      context.token_response = {
        ...token,
        authenticated: token.authenticated ? "True" : "False",
      };
    }
  }
  return environment.render(name, context);
}
