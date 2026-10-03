import dns from "node:dns";
import { afterEach, expect, it } from "vitest";
import { installLookup, validatedAnswers } from "./resolver.mjs";

let restore: (() => void) | undefined;
afterEach(() => {
  restore?.();
  restore = undefined;
});
const answer = {
  Status: 0,
  Question: [{ name: "auth.example.", type: 1 }],
  Answer: [{ name: "auth.example.", type: 1, data: "192.0.2.1" }],
};

it("accepts only the queried hostname's IPv4 A answers", () => {
  expect(validatedAnswers("auth.example", answer)).toEqual(["192.0.2.1"]);
  expect(() => validatedAnswers("other.example", answer)).toThrow();
  expect(() =>
    validatedAnswers("auth.example", { ...answer, Status: 3 }),
  ).toThrow();
  expect(() =>
    validatedAnswers("auth.example", {
      ...answer,
      Answer: [{ name: "other.example", type: 1, data: "192.0.2.2" }],
    }),
  ).toThrow();
  expect(() =>
    validatedAnswers("auth.example", {
      ...answer,
      Answer: [{ name: "auth.example", type: 1, data: "::1" }],
    }),
  ).toThrow();
  expect(() =>
    validatedAnswers("auth.example", { ...answer, Answer: [] }),
  ).toThrow();
});

it("scopes callback and promise lookups to one hostname and restores them", async () => {
  const original = dns.lookup;
  const originalPromises = dns.promises.lookup;
  restore = installLookup("auth.example", ["192.0.2.1", "192.0.2.2"]);
  expect(await dns.promises.lookup("auth.example", { all: true })).toEqual([
    { address: "192.0.2.1", family: 4 },
    { address: "192.0.2.2", family: 4 },
  ]);
  expect(
    await new Promise((resolve, reject) =>
      dns.lookup("AUTH.EXAMPLE.", (error, address, family) =>
        error ? reject(error) : resolve({ address, family }),
      ),
    ),
  ).toEqual({ address: "192.0.2.1", family: 4 });
  expect(await dns.promises.lookup("127.0.0.1")).toEqual(
    await originalPromises("127.0.0.1"),
  );
  await expect(
    dns.promises.lookup("auth.example", { family: 6 }),
  ).rejects.toMatchObject({ code: "ENOTFOUND" });
  restore();
  expect(dns.lookup).toBe(original);
  expect(dns.promises.lookup).toBe(originalPromises);
});
