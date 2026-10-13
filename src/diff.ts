// The diff: for every package version the new lockfile installs that the old
// one did not, which capabilities it has that no previous version of the
// same package had.
//
// A package that is new to the tree has no previous version, so everything it
// can do is new. That is deliberate: a fresh transitive dependency is exactly
// how most supply-chain attacks arrive.

import { analyzePackage, capabilitiesOf, type Capability, type Evidence, type Profile } from "./analyze.js";
import { key, type LockedPackage, type Lockfile } from "./lockfile.js";
import { allowed, type Policy } from "./policy.js";
import type { Source } from "./source.js";

export interface Gain {
  capability: Capability;
  evidence: Evidence;
  allowed: boolean;
}

export interface Finding {
  name: string;
  version: string;
  /** Versions of this package in the old lockfile; empty if it is new. */
  previous: string[];
  /** Packages in the new lockfile that depend on it. */
  requiredBy: string[];
  gains: Gain[];
  newDependencies: string[];
}

export interface Report {
  findings: Finding[];
  removed: string[];
  /** Number of package versions analysed (both sides). */
  analysed: number;
}

export function blocked(r: Report): Finding[] {
  return r.findings.filter((f) => f.gains.some((g) => !g.allowed));
}

function unique(pkgs: LockedPackage[]): LockedPackage[] {
  const seen = new Map<string, LockedPackage>();
  for (const p of pkgs) if (!seen.has(key(p))) seen.set(key(p), p);
  return [...seen.values()];
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pb = b.split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? -1;
    const y = pb[i] ?? -1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x - y;
    return String(x).localeCompare(String(y));
  }
  return 0;
}

export async function diff(
  before: Lockfile,
  after: Lockfile,
  source: Source,
  policy: Policy,
  concurrency = 8,
): Promise<Report> {
  const beforeKeys = new Set(before.packages.map(key));
  const afterKeys = new Set(after.packages.map(key));
  const byName = new Map<string, LockedPackage[]>();
  for (const p of unique(before.packages)) byName.set(p.name, [...(byName.get(p.name) ?? []), p]);

  const profiles = new Map<string, Promise<Profile>>();
  let analysed = 0;
  const profileOf = (p: LockedPackage): Promise<Profile> => {
    const k = key(p);
    let pending = profiles.get(k);
    if (!pending) {
      pending = (async () => {
        analysed++;
        try {
          return analyzePackage(await source.unpack(p)).profile;
        } catch (e) {
          // Could not get or read it: that is a capability we cannot rule out.
          return { unanalyzable: { file: "", line: 0, detail: (e as Error).message } } as Profile;
        }
      })();
      profiles.set(k, pending);
    }
    return pending;
  };

  const findings: Finding[] = [];
  const changed = unique(after.packages).filter((p) => !beforeKeys.has(key(p)));
  changed.sort((a, b) => a.name.localeCompare(b.name) || compareVersions(a.version, b.version));

  // Fetch and analyse everything needed, several at a time; the loop below
  // then reads from the cache in a fixed order, so output never depends on
  // which download finished first.
  const needed = unique([...changed, ...changed.flatMap((p) => byName.get(p.name) ?? [])]);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, needed.length) }, async () => {
      while (next < needed.length) await profileOf(needed[next++]!);
    }),
  );
  for (const p of changed) {
    const prev = (byName.get(p.name) ?? []).slice().sort((a, b) => compareVersions(a.version, b.version));
    const baseline = new Set<Capability>();
    const baselineDeps = new Set<string>();
    for (const q of prev) {
      for (const c of capabilitiesOf(await profileOf(q))) baseline.add(c);
      for (const d of q.dependencies) baselineDeps.add(d);
    }
    const profile = await profileOf(p);
    const gains: Gain[] = capabilitiesOf(profile)
      .filter((c) => !baseline.has(c))
      .map((c) => ({ capability: c, evidence: profile[c]!, allowed: allowed(policy, p.name, c) }));
    const newDependencies = prev.length === 0 ? [] : p.dependencies.filter((d) => !baselineDeps.has(d));
    const requiredBy = [
      ...new Set(after.packages.filter((q) => q.dependencies.includes(p.name)).map((q) => q.name)),
    ].sort();
    findings.push({
      name: p.name,
      version: p.version,
      previous: prev.map((q) => q.version),
      requiredBy,
      gains,
      newDependencies,
    });
  }
  const removed = [
    ...new Set(
      unique(before.packages)
        .filter((p) => !afterKeys.has(key(p)))
        .map(key),
    ),
  ].sort();
  return { findings, removed, analysed };
}
