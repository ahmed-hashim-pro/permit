#!/usr/bin/env node
// permit: what does this dependency upgrade newly get to do?

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { analyzePackage, capabilitiesOf, CAPABILITIES, DESCRIPTIONS } from "./analyze.js";
import { blocked, diff, type Report } from "./diff.js";
import { LockfileError, parseLockfile, type Lockfile } from "./lockfile.js";
import { EMPTY_POLICY, parsePolicy, PolicyError, type Policy } from "./policy.js";
import { FixtureSource, RegistrySource, type Source } from "./source.js";

const VERSION = "0.1.0";

const USAGE = `permit: what does this dependency upgrade newly get to do?

usage:
  permit diff <before-lock> <after-lock> [options]   compare two package-lock.json files
  permit diff --base <git-ref> [options]             compare <git-ref>:package-lock.json with the working tree's
  permit scan <dir>                                  the capabilities of one unpacked package
  permit capabilities                                list what is detected
  permit version

options:
  --policy FILE     allowed capabilities per package (default: ./permit.json if present)
  --lockfile FILE   with --base: the lockfile path (default: package-lock.json)
  --fixtures DIR    read packages from DIR/<name>@<version>/ instead of the registry
  --registry URL    registry for tarballs the lockfile has no URL for (default: https://registry.npmjs.org)
  --cache DIR       tarball cache (default: ~/.cache/permit)
  --json            machine-readable report

exit codes: 0 nothing new or all of it allowed, 1 a package newly gains a capability
            the policy does not allow, 2 bad input or usage`;

class UsageError extends Error {}

interface Opts {
  positional: string[];
  flags: Map<string, string | true>;
}

const VALUED = new Set(["--policy", "--lockfile", "--fixtures", "--registry", "--cache", "--base"]);
const SWITCHES = new Set(["--json"]);

function parseArgs(args: string[]): Opts {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("--")) {
      if (SWITCHES.has(a)) flags.set(a, true);
      else if (VALUED.has(a)) {
        const v = args[++i];
        if (v === undefined) throw new UsageError(`${a} needs a value`);
        flags.set(a, v);
      } else throw new UsageError(`unknown option ${a}`);
    } else positional.push(a);
  }
  return { positional, flags };
}

function str(o: Opts, name: string): string | undefined {
  const v = o.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function readText(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    throw new UsageError(
      `${path}: ${(e as NodeJS.ErrnoException).code === "ENOENT" ? "no such file" : (e as Error).message}`,
    );
  }
}

function loadPolicy(o: Opts): Policy {
  const explicit = str(o, "--policy");
  const path = explicit ?? (existsSync("permit.json") ? "permit.json" : undefined);
  if (!path) return EMPTY_POLICY;
  return parsePolicy(readText(path), path);
}

function source(o: Opts): Source {
  const fixtures = str(o, "--fixtures");
  if (fixtures) return new FixtureSource(fixtures);
  return new RegistrySource({ registry: str(o, "--registry"), cacheDir: str(o, "--cache") });
}

function lockfiles(o: Opts): [Lockfile, Lockfile] {
  const base = str(o, "--base");
  if (base) {
    if (o.positional.length > 0) throw new UsageError("--base takes no lockfile arguments");
    const path = str(o, "--lockfile") ?? "package-lock.json";
    let old: string;
    try {
      old = execFileSync("git", ["show", `${base}:${path}`], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer: 256 << 20,
      });
    } catch (e) {
      throw new UsageError(
        `cannot read ${path} at ${base}: ${String((e as { stderr?: string }).stderr ?? e).trim()}`,
      );
    }
    return [parseLockfile(old, `${base}:${path}`), parseLockfile(readText(path), path)];
  }
  if (o.positional.length !== 2)
    throw new UsageError("diff takes <before-lock> <after-lock>, or --base <git-ref>");
  const [b, a] = o.positional as [string, string];
  return [parseLockfile(readText(b), b), parseLockfile(readText(a), a)];
}

function render(r: Report): string {
  const lines: string[] = [];
  const interesting = r.findings.filter((f) => f.gains.length > 0 || f.newDependencies.length > 0);
  const bad = blocked(r);
  const quiet = r.findings.length - interesting.length;
  lines.push(
    `${r.findings.length} package version${r.findings.length === 1 ? "" : "s"} added or changed; ` +
      `${interesting.length} with something new, ${bad.length} blocked by policy`,
  );
  for (const f of interesting) {
    lines.push("");
    const from = f.previous.length ? `${f.previous.join(", ")} -> ${f.version}` : `${f.version} (new`;
    const via = f.previous.length
      ? ""
      : f.requiredBy.length
        ? `, required by ${f.requiredBy.join(", ")})`
        : ")";
    lines.push(`${f.name} ${from}${via}`);
    if (f.newDependencies.length) lines.push(`  new dependencies: ${f.newDependencies.join(", ")}`);
    const width = Math.max(0, ...f.gains.map((g) => g.capability.length));
    for (const g of f.gains) {
      const where = g.evidence.file
        ? `${g.evidence.file}${g.evidence.line ? `:${g.evidence.line}` : ""}  `
        : "";
      const verdict = g.allowed ? "allowed " : "NEW     ";
      lines.push(`  ${verdict}${g.capability.padEnd(width)}  ${where}${g.evidence.detail}`);
    }
  }
  if (quiet > 0)
    lines.push("", `${quiet} other${quiet === 1 ? "" : "s"} changed version without gaining anything.`);
  if (bad.length) {
    lines.push("", `Blocked: ${bad.map((f) => `${f.name}@${f.version}`).join(", ")}.`);
    lines.push(`Review them, then allow what is expected in permit.json, e.g.`);
    const f = bad[0]!;
    const caps = f.gains.filter((g) => !g.allowed).map((g) => JSON.stringify(g.capability));
    lines.push(`  { "allow": { ${JSON.stringify(f.name)}: [${caps.join(", ")}] } }`);
  }
  return lines.join("\n") + "\n";
}

async function cmdDiff(o: Opts, out: (s: string) => void): Promise<number> {
  const [before, after] = lockfiles(o);
  const policy = loadPolicy(o);
  const report = await diff(before, after, source(o), policy);
  if (o.flags.has("--json"))
    out(
      JSON.stringify({ ...report, blocked: blocked(report).map((f) => `${f.name}@${f.version}`) }, null, 2) +
        "\n",
    );
  else out(render(report));
  return blocked(report).length > 0 ? 1 : 0;
}

function cmdScan(o: Opts, out: (s: string) => void): number {
  if (o.positional.length !== 1) throw new UsageError("scan takes one directory");
  const dir = o.positional[0]!;
  if (!existsSync(dir)) throw new UsageError(`${dir}: no such directory`);
  const { profile } = analyzePackage(dir);
  if (o.flags.has("--json")) {
    out(JSON.stringify(profile, null, 2) + "\n");
    return 0;
  }
  const caps = capabilitiesOf(profile);
  if (caps.length === 0) out("no capabilities found\n");
  for (const c of caps) {
    const e = profile[c]!;
    out(`${c.padEnd(16)} ${e.file}${e.line ? `:${e.line}` : ""}  ${e.detail}\n`);
  }
  return 0;
}

export async function main(
  argv: string[],
  out = (s: string) => void process.stdout.write(s),
  err = (s: string) => void process.stderr.write(s),
): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case "diff":
        return await cmdDiff(parseArgs(rest), out);
      case "scan":
        return cmdScan(parseArgs(rest), out);
      case "capabilities":
        for (const c of CAPABILITIES) out(`${c.padEnd(16)} ${DESCRIPTIONS[c]}\n`);
        return 0;
      case "version":
      case "--version":
        out(`permit ${VERSION}\n`);
        return 0;
      case "help":
      case "--help":
      case "-h":
        out(USAGE + "\n");
        return 0;
      case undefined:
        err(USAGE + "\n");
        return 2;
      default:
        throw new UsageError(`unknown command '${cmd}'\n\n${USAGE}`);
    }
  } catch (e) {
    if (e instanceof UsageError || e instanceof LockfileError || e instanceof PolicyError) {
      err(`permit: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
}

// Run when executed directly (also through npm's bin symlink), not when imported by the tests.
function isMain(): boolean {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}
if (isMain()) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`permit: ${(e as Error).stack ?? e}\n`);
      process.exit(2);
    },
  );
}
