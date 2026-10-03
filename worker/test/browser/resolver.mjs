import dns from "node:dns";
import { isIPv4 } from "node:net";
import { syncBuiltinESMExports } from "node:module";

const normalized = (value) => String(value).toLowerCase().replace(/\.$/, "");

export function validatedAnswers(hostname, result) {
  const name = normalized(hostname);
  if (!/^[a-z0-9.-]+$/.test(name) || name.includes(".."))
    throw new Error("Invalid resolver hostname");
  if (
    result?.Status !== 0 ||
    result.TC === true ||
    result.Question?.length !== 1 ||
    result.Question[0].type !== 1 ||
    normalized(result.Question[0].name) !== name
  )
    throw new Error("DNS response does not match the requested hostname");
  const answers = (result.Answer || []).filter((answer) => answer.type === 1);
  if (
    !answers.length ||
    answers.length > 16 ||
    answers.some(
      (answer) => normalized(answer.name) !== name || !isIPv4(answer.data),
    )
  )
    throw new Error("DNS response does not contain exact-host IPv4 answers");
  return [...new Set(answers.map((answer) => answer.data))];
}

/** Override only one exact host in this Node process, never system DNS or TLS. */
export function installLookup(hostname, addresses) {
  const name = normalized(hostname);
  if (!addresses.length || addresses.some((address) => !isIPv4(address)))
    throw new Error("An IPv4 result is required");
  const lookup = dns.lookup;
  const promiseLookup = dns.promises.lookup;
  const result = (options) => {
    const family = typeof options === "number" ? options : options?.family;
    if (family === 6 || family === "IPv6") {
      const error = new Error("No IPv6 answer in the scoped IPv4 resolver");
      error.code = "ENOTFOUND";
      throw error;
    }
    const records = addresses.map((address) => ({ address, family: 4 }));
    return options?.all ? records : records[0];
  };
  dns.lookup = function (target, options, callback) {
    if (normalized(target) !== name) return lookup.apply(this, arguments);
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    if (typeof callback !== "function")
      throw new TypeError("DNS lookup callback is required");
    queueMicrotask(() => {
      try {
        const resolved = result(options);
        if (options?.all) callback(null, resolved);
        else callback(null, resolved.address, resolved.family);
      } catch (error) {
        callback(error);
      }
    });
  };
  dns.promises.lookup = async function (target, options) {
    if (normalized(target) !== name)
      return promiseLookup.apply(this, arguments);
    return result(options);
  };
  syncBuiltinESMExports();
  let active = true;
  return () => {
    if (!active) return;
    dns.lookup = lookup;
    dns.promises.lookup = promiseLookup;
    syncBuiltinESMExports();
    active = false;
  };
}

export async function scopedResolver(origin, mode = "system") {
  if (mode === "system")
    return { name: "system", chromeArgs: [], restore() {} };
  if (mode !== "cloudflare-doh")
    throw new Error("Unknown remote resolver mode");
  const hostname = new URL(origin).hostname;
  const query = new URL("https://cloudflare-dns.com/dns-query");
  query.searchParams.set("name", hostname);
  query.searchParams.set("type", "A");
  const response = await fetch(query, {
    headers: { Accept: "application/dns-json" },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error("DNS over HTTPS request failed");
  const addresses = validatedAnswers(hostname, await response.json());
  return {
    name: "cloudflare-doh",
    chromeArgs: [`--host-resolver-rules=MAP ${hostname} ${addresses[0]}`],
    restore: installLookup(hostname, addresses),
  };
}
