import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { main } from "../src/cli.js";
import { tempDir } from "./helpers.js";

async function run(...args: string[]) {
  let out = "";
  let err = "";
  const code = await main(
    args,
    (s) => void (out += s),
    (s) => void (err += s),
  );
  return { code, out, err };
}

const FIX = ["--fixtures", "fixtures/packages"];

test("blocks the ua-sniff upgrade, exit 1", async () => {
  const r = await run("diff", "examples/ua-sniff/before.json", "examples/ua-sniff/after.json", ...FIX);
  assert.equal(r.code, 1);
  assert.match(r.out, /ua-sniff 0\.7\.28 -> 0\.7\.29/);
  assert.match(r.out, /NEW\s+install-script\s+package\.json\s+preinstall: node preinstall\.js/);
  assert.match(r.out, /Blocked: ua-sniff@0\.7\.29/);
});

test("passes when the policy allows every gain, exit 0", async () => {
  const d = tempDir();
  writeFileSync(
    join(d, "permit.json"),
    JSON.stringify({ allow: { "ua-sniff": ["install-script", "network", "exec", "fs-write", "env"] } }),
  );
  const r = await run(
    "diff",
    "examples/ua-sniff/before.json",
    "examples/ua-sniff/after.json",
    ...FIX,
    "--policy",
    join(d, "permit.json"),
  );
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /allowed install-script/);
});

test("--json", async () => {
  const r = await run(
    "diff",
    "examples/event-stream/before.json",
    "examples/event-stream/after.json",
    ...FIX,
    "--json",
  );
  const j = JSON.parse(r.out);
  assert.deepEqual(j.blocked, ["flatmap-lite@0.1.1"]);
  assert.equal(j.findings.length, 2);
});

test("--base compares a git ref's lockfile with the working tree's", async () => {
  const d = tempDir();
  const git = (...a: string[]) =>
    execFileSync("git", ["-C", d, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { stdio: "pipe" });
  git("init", "-q");
  copyFileSync("examples/monday/before.json", join(d, "package-lock.json"));
  git("add", ".");
  git("commit", "-qm", "before");
  copyFileSync("examples/monday/after.json", join(d, "package-lock.json"));
  copyFileSync("examples/monday/permit.json", join(d, "permit.json"));
  const cwd = process.cwd();
  const fixtures = resolve("fixtures/packages");
  process.chdir(d);
  try {
    const r = await run("diff", "--base", "HEAD", "--fixtures", fixtures);
    assert.equal(r.code, 1, r.out + r.err);
    assert.match(r.out, /Blocked: @acme\/logger@2\.1\.0/);
    assert.match(r.out, /allowed binary/, "picked up ./permit.json");
    const bad = await run("diff", "--base", "no-such-ref", "--fixtures", fixtures);
    assert.equal(bad.code, 2);
    assert.match(bad.err, /cannot read package-lock.json at no-such-ref/);
  } finally {
    process.chdir(cwd);
  }
});

test("scan shows a package's capabilities", async () => {
  const r = await run("scan", "fixtures/packages/ua-sniff@0.7.29");
  assert.equal(r.code, 0);
  assert.match(r.out, /^install-script\s+package\.json/m);
  assert.match(r.out, /^exec\s+preinstall\.js:7/m);
});

test("usage and input errors exit 2", async () => {
  for (const args of [
    [],
    ["frobnicate"],
    ["diff"],
    ["diff", "examples/ua-sniff/before.json"],
    ["diff", "a.json", "b.json"],
    ["diff", "examples/ua-sniff/before.json", "examples/ua-sniff/after.json", "--bogus"],
    ["diff", "examples/ua-sniff/before.json", "examples/ua-sniff/after.json", "--policy"],
    ["diff", "examples/ua-sniff/before.json", "package.json", ...FIX],
    ["diff", "--base", "HEAD", "x.json"],
    ["scan"],
    ["scan", "no/such/dir"],
  ]) {
    const r = await run(...args);
    assert.equal(r.code, 2, `${args.join(" ")}: ${r.out}${r.err}`);
  }
});

test("capabilities and version", async () => {
  const c = await run("capabilities");
  assert.equal(c.out.trim().split("\n").length, 10);
  assert.match((await run("version")).out, /^permit \d+\.\d+\.\d+/);
});
