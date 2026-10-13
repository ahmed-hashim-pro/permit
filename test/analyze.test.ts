import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  analyzePackage,
  analyzeSource,
  capabilitiesOf,
  CAPABILITIES,
  type Capability,
} from "../src/analyze.js";
import { rng, tempDir } from "./helpers.js";

const caps = (src: string) => capabilitiesOf(analyzeSource(src, "x.js"));

test("detects each capability from real code", () => {
  const cases: [string, Capability[]][] = [
    [`const https = require('https'); https.get('u')`, ["network"]],
    [`import net from 'node:net'`, ["network"]],
    [`import { request } from "undici"`, ["network"]],
    [`export * from 'dgram'`, ["network"]],
    [`const m = await import('tls')`, ["network"]],
    [`fetch('https://x')`, ["network"]],
    [`globalThis.fetch(u)`, ["network"]],
    [`new WebSocket('wss://x')`, ["network"]],
    [`require('child_process').exec('ls')`, ["exec"]],
    [`import { spawn } from 'node:child_process'`, ["exec"]],
    [`const fs = require('fs'); fs.writeFileSync('a', 'b')`, ["fs-write"]],
    [`const { promises } = require('fs'); `, []],
    [`import fs from 'fs'; fs.promises.writeFile('a', 'b')`, ["fs-write"]],
    [`import { rmSync } from 'node:fs'`, ["fs-write"]],
    [`const { chmodSync } = require('fs')`, ["fs-write"]],
    [`require('fs').unlinkSync('x')`, ["fs-write"]],
    [`console.log(process.env.HOME)`, ["env"]],
    [`const t = process['env']`, ["env"]],
    [`eval('1+1')`, ["dynamic-code"]],
    [`new Function('return 1')()`, ["dynamic-code"]],
    [`require('vm').runInNewContext('1')`, ["dynamic-code"]],
    [`m._compile(src, 'x')`, ["dynamic-code"]],
    [`require(name)`, ["dynamic-require"]],
    [`require('a' + b)`, ["dynamic-require"]],
    [`import(\`./\${x}\`)`, ["dynamic-require"]],
    [`#!/usr/bin/env node\nreturn require('http')`, ["network"]],
  ];
  for (const [src, want] of cases) assert.deepEqual(caps(src), want, src);
});

test("words in comments and strings are not code", () => {
  for (const src of [
    `// require('child_process') would be bad`,
    `const s = "require('https')"; const t = 'process.env'`,
    `/* eval('x') */ const fetcher = 1`,
    "const doc = `import net from 'net'`",
    `const fs = require('fs'); fs.readFileSync('a'); fs.existsSync('b')`,
    `obj.writeFileSync('a')`, // not fs
    `const o = { env: 1 }; o.env`,
    `require('./local.js'); require('lodash')`,
  ]) {
    assert.deepEqual(caps(src), [], src);
  }
});

test("sees through aliases, as obfuscated payloads use them", () => {
  assert.deepEqual(caps(`var r = require; r('ht' + 'tps')`), ["dynamic-require"]);
  assert.deepEqual(caps(`var r; r = require; r('https')`), ["network"]);
  assert.deepEqual(caps(`var t = process; t[k]`), ["env"]);
  assert.deepEqual(caps(`var t = process; t.env.X`), ["env"]);
});

test("evidence points at the line", () => {
  const p = analyzeSource("\n\nconst x = 1\nfetch(u)\n", "lib/a.js");
  assert.deepEqual(p.network, { file: "lib/a.js", line: 4, detail: "calls fetch()" });
});

test("code that does not parse is reported, not skipped", () => {
  const p = analyzeSource("function (", "bad.js");
  assert.deepEqual(capabilitiesOf(p), ["unanalyzable"]);
});

test("package-level capabilities: scripts, native builds, binaries", () => {
  const d = tempDir();
  writeFileSync(
    join(d, "package.json"),
    JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "node i.js", test: "x" } }),
  );
  writeFileSync(join(d, "binding.gyp"), "{}");
  mkdirSync(join(d, "bin"));
  writeFileSync(join(d, "bin", "tool"), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2]));
  writeFileSync(join(d, "bin", "win.exe"), Buffer.from("MZ\x90\x00"));
  writeFileSync(join(d, "addon.node"), "x");
  writeFileSync(join(d, "readme.txt"), "MZ is not at the start of this file");
  mkdirSync(join(d, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(d, "node_modules", "dep", "x.js"), "require('https')"); // bundled: listed separately
  symlinkSync("/etc", join(d, "escape")); // never followed
  const { profile, dependencies } = analyzePackage(d);
  assert.deepEqual(capabilitiesOf(profile), ["install-script", "native-build", "binary"]);
  assert.match(profile["install-script"]!.detail, /postinstall/);
  assert.deepEqual(dependencies, []);
});

test("a package without a readable package.json is an error", () => {
  assert.throws(() => analyzePackage(tempDir()), /package.json/);
});

// Property: build files from random snippets whose capabilities are known,
// in random order, between random harmless code; the detected set must be
// exactly the union.
const ATOMS: [string, Capability | undefined][] = [
  [`const h = require('https')`, "network"],
  [`import d from 'node:dns'`, "network"],
  [`await fetch(u)`, "network"],
  [`require('child_process')`, "exec"],
  [`require('fs').appendFileSync(p, s)`, "fs-write"],
  [`const k = process.env.TOKEN`, "env"],
  [`eval(s)`, "dynamic-code"],
  [`require(modName)`, "dynamic-require"],
  [`const x = [1, 2, 3].map((n) => n * 2)`, undefined],
  [`class A { #p = 1; get p() { return this.#p } }`, undefined],
  [`const s = "require('net') eval process.env"`, undefined],
  [`// fetch('x') child_process`, undefined],
  [`label: for (const a of []) { break label }`, undefined],
  [`const fs = require('fs'); fs.readFile(p, () => {})`, undefined],
];

test("property: detected = union of the snippets' capabilities", () => {
  const r = rng(42);
  for (let trial = 0; trial < 500; trial++) {
    const n = 1 + Math.floor(r() * 8);
    const picked = Array.from({ length: n }, () => ATOMS[Math.floor(r() * ATOMS.length)]!);
    // Each snippet in its own block (so declarations never clash), except
    // imports, which must be at the top level of a module.
    const fixed = picked
      .map(([s], i) => (s.startsWith("import ") ? s.replace(" d ", ` d${i} `) : `{\n${s}\n}`))
      .join("\n");
    const want = CAPABILITIES.filter((c) => picked.some(([, cap]) => cap === c));
    assert.deepEqual(caps(`async function main() {}\n${fixed}`), want, fixed);
  }
});
