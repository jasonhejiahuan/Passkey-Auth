import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import nunjucks from "nunjucks";

const workerRoot = fileURLToPath(new URL("..", import.meta.url));
const sourceRoot = path.resolve(workerRoot, "../jstu_passkey");
const generatedRoot = path.join(workerRoot, "src/generated");
const publicStatic = path.join(workerRoot, "public/static");
await mkdir(generatedRoot, { recursive: true });
// Only replace this build's owned output. Source assets remain the original UI.
await rm(publicStatic, { recursive: true, force: true });
await mkdir(publicStatic, { recursive: true });
await cp(path.join(sourceRoot, "static"), publicStatic, { recursive: true });

const templateRoot = path.join(sourceRoot, "templates");
const names = (await readdir(templateRoot))
  .filter((name) => name.endsWith(".html"))
  .sort();
const templates = names.map((name) =>
  nunjucks.precompile(path.join(templateRoot, name), {
    name,
    wrapper: (compiled) =>
      compiled
        .map(
          (item) =>
            `${JSON.stringify(item.name)}: (function() {\n${item.template}\n})()`,
        )
        .join(",\n"),
  }),
);
await writeFile(
  path.join(generatedRoot, "templates.js"),
  "// Generated from jstu_passkey/templates by scripts/build-assets.mjs. Do not edit.\n" +
    `export const templates = {\n${templates.join(",\n")}\n};\n`,
);
await writeFile(
  path.join(generatedRoot, "templates.d.ts"),
  `export type TemplateName = ${names.map((name) => JSON.stringify(name)).join(" | ")};\n` +
    "export declare const templates: Record<TemplateName, object>;\n",
);

// Keep the existing lazily loaded registration module as its single source.
// Extraction is deliberately strict; changes to the Python wrapper fail the build.
const registrationSource = await readFile(
  path.join(sourceRoot, "register_client.py"),
  "utf8",
);
const registrationMatch = registrationSource.match(
  /^REGISTER_CLIENT_JS = r'''\r?\n([\s\S]*?)'''\s*$/,
);
if (!registrationMatch)
  throw new Error(
    "Unrecognized register_client.py wrapper. Review the registration asset extraction.",
  );
await writeFile(
  path.join(generatedRoot, "register-client.ts"),
  "// Generated from jstu_passkey/register_client.py. Do not edit.\n" +
    `export const registerClientJavaScript = ${JSON.stringify("\n" + registrationMatch[1])};\n`,
);
console.log(
  `Built ${names.length} original templates and copied original static assets.`,
);
