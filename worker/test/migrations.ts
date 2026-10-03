import { readdir, readFile } from "node:fs/promises";

/** Tests initialize the same ordered schema as a newly provisioned D1 database. */
export async function readMigrations(): Promise<string> {
  const root = new URL("../migrations/", import.meta.url);
  const files = (await readdir(root))
    .filter((file) => /^\d+.*\.sql$/.test(file))
    .sort();
  return (
    await Promise.all(
      files.map((file) => readFile(new URL(file, root), "utf8")),
    )
  ).join("\n");
}
