import { test } from "node:test";
import assert from "node:assert/strict";
import { allowed, parsePolicy, PolicyError } from "../src/policy.js";

test("allows per package and for everyone", () => {
  const p = parsePolicy(
    JSON.stringify({ $comment: "x", allow: { esbuild: ["install-script", "binary"], "*": ["fs-write"] } }),
  );
  assert.equal(allowed(p, "esbuild", "binary"), true);
  assert.equal(allowed(p, "esbuild", "network"), false);
  assert.equal(allowed(p, "anything", "fs-write"), true);
  assert.equal(allowed(p, "anything", "env"), false);
});

test("a typo is an error, never a silent allow or deny", () => {
  for (const [text, re] of [
    ["{", /not JSON/],
    ["[]", /not a JSON object/],
    [JSON.stringify({ alow: {} }), /unknown key 'alow'/],
    [JSON.stringify({ allow: [] }), /must be an object/],
    [JSON.stringify({ allow: { a: "network" } }), /must be a list/],
    [JSON.stringify({ allow: { a: ["netwrok"] } }), /unknown capability "netwrok"/],
  ] as const) {
    assert.throws(
      () => parsePolicy(text),
      (e: unknown) => e instanceof PolicyError && re.test((e as Error).message),
      text,
    );
  }
});
