import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { blocked, diff } from "../src/diff.js";
import { parseLockfile, type LockedPackage } from "../src/lockfile.js";
import { EMPTY_POLICY, parsePolicy } from "../src/policy.js";
import { FixtureSource, type Source } from "../src/source.js";

const fixtures = new FixtureSource("fixtures/packages");
const example = (name: string) =>
  [0, 1].map((i) =>
    parseLockfile(readFileSync(`examples/${name}/${i ? "after" : "before"}.json`, "utf8")),
  ) as [ReturnType<typeof parseLockfile>, ReturnType<typeof parseLockfile>];
const gains = (r: Awaited<ReturnType<typeof diff>>, name: string) =>
  r.findings.find((f) => f.name === name)!.gains.map((g) => (g.allowed ? "+" : "") + g.capability);

test("event-stream: a new transitive dependency with hidden require and env", async () => {
  const [b, a] = example("event-stream");
  const r = await diff(b, a, fixtures, EMPTY_POLICY);
  assert.deepEqual(gains(r, "flatmap-lite"), ["env", "dynamic-require"]);
  const f = r.findings.find((x) => x.name === "flatmap-lite")!;
  assert.deepEqual(f.previous, []);
  assert.deepEqual(f.requiredBy, ["stream-pipe"]);
  assert.deepEqual(r.findings.find((x) => x.name === "stream-pipe")!.newDependencies, ["flatmap-lite"]);
  assert.deepEqual(gains(r, "stream-pipe"), []);
  assert.deepEqual(
    blocked(r).map((x) => x.name),
    ["flatmap-lite"],
  );
  assert.deepEqual(r.removed, ["stream-pipe@3.3.5"]);
});

test("ua-parser-js: a patch release that grows a preinstall downloader", async () => {
  const [b, a] = example("ua-sniff");
  const r = await diff(b, a, fixtures, EMPTY_POLICY);
  assert.deepEqual(gains(r, "ua-sniff"), ["install-script", "network", "exec", "fs-write", "env"]);
});

test("a policy turns expected gains into allowed ones, and only those", async () => {
  const [b, a] = example("monday");
  const policy = parsePolicy(readFileSync("examples/monday/permit.json", "utf8"));
  const r = await diff(b, a, fixtures, policy);
  assert.deepEqual(gains(r, "fast-bundler"), ["+install-script", "+binary"]);
  assert.deepEqual(gains(r, "@acme/logger"), ["network", "env"]);
  assert.deepEqual(gains(r, "left-padder"), []);
  assert.deepEqual(
    blocked(r).map((x) => x.name),
    ["@acme/logger"],
  );
  // Without the policy, both are blocked.
  const strict = await diff(b, a, fixtures, EMPTY_POLICY);
  assert.deepEqual(
    blocked(strict).map((x) => x.name),
    ["@acme/logger", "fast-bundler"],
  );
});

test("the same lockfile on both sides is not a change", async () => {
  const [, a] = example("monday");
  const r = await diff(a, a, fixtures, EMPTY_POLICY);
  assert.deepEqual(r.findings, []);
  assert.equal(r.analysed, 0);
});

test("a capability any previous version had is not new", async () => {
  // Two versions of left-padder installed before (one nested); the new one is
  // compared with both. Here: a fake source where only the old nested copy
  // used the network.
  const lock = (pkgs: Record<string, unknown>) =>
    parseLockfile(JSON.stringify({ lockfileVersion: 3, packages: pkgs }));
  const before = lock({
    "node_modules/x": { version: "1.0.0" },
    "node_modules/y/node_modules/x": { version: "0.9.0" },
  });
  const after = lock({ "node_modules/x": { version: "1.1.0" } });
  const src: Source = {
    async unpack(p: LockedPackage) {
      return `test-fixture-${p.version}`;
    },
  };
  // Use real fixture dirs through a mapping.
  const map: Record<string, string> = {
    "0.9.0": "fixtures/packages/@acme+logger@2.1.0",
    "1.0.0": "fixtures/packages/left-padder@1.2.0",
    "1.1.0": "fixtures/packages/@acme+logger@2.1.0",
  };
  const mapped: Source = { unpack: async (p) => map[p.version] ?? (await src.unpack(p)) };
  const r = await diff(before, after, mapped, EMPTY_POLICY);
  assert.deepEqual(r.findings[0]!.previous, ["0.9.0", "1.0.0"]);
  assert.deepEqual(r.findings[0]!.gains, []);
});

test("a package that cannot be fetched is blocked as unanalyzable", async () => {
  const [b, a] = example("ua-sniff");
  const broken: Source = {
    unpack: async (p) => {
      if (p.version === "0.7.29") throw new Error("registry unreachable");
      return fixtures.unpack(p);
    },
  };
  const r = await diff(b, a, broken, EMPTY_POLICY);
  assert.deepEqual(gains(r, "ua-sniff"), ["unanalyzable"]);
  assert.match(r.findings[0]!.gains[0]!.evidence.detail, /registry unreachable/);
});
