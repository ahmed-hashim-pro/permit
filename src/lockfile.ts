// package-lock.json (lockfileVersion 2 or 3), parsed strictly.
//
// Only the "packages" section is read: it lists every installed package by
// its path in node_modules, which is what actually lands on disk. Version 1
// lockfiles have no such section, so they are refused rather than guessed at.

export interface LockedPackage {
  /** Path in the tree, e.g. "node_modules/a/node_modules/@s/b". */
  path: string;
  name: string;
  version: string;
  /** Tarball URL, when the lockfile records one. */
  resolved?: string;
  /** Subresource integrity, e.g. "sha512-...". */
  integrity?: string;
  /** Names of its declared runtime dependencies. */
  dependencies: string[];
  /** Installed but only for development / optional on this platform. */
  dev: boolean;
  optional: boolean;
}

export interface Lockfile {
  lockfileVersion: number;
  packages: LockedPackage[];
}

export class LockfileError extends Error {}

function fail(source: string, message: string): never {
  throw new LockfileError(`${source}: ${message}`);
}

/** The package name a node_modules path installs, or undefined for the root. */
export function nameFromPath(path: string): string | undefined {
  const marker = "node_modules/";
  const at = path.lastIndexOf(marker);
  if (at < 0) return undefined;
  return path.slice(at + marker.length);
}

const NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseLockfile(text: string, source = "lockfile"): Lockfile {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    fail(source, `not JSON (${(e as Error).message})`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) fail(source, "not a JSON object");
  const d = doc as Record<string, unknown>;
  const v = d["lockfileVersion"];
  if (v === 1) fail(source, "lockfileVersion 1 has no 'packages' section; regenerate it with npm 7 or newer");
  if (v !== 2 && v !== 3) fail(source, `unsupported lockfileVersion ${JSON.stringify(v)} (expected 2 or 3)`);
  const pkgs = d["packages"];
  if (typeof pkgs !== "object" || pkgs === null || Array.isArray(pkgs))
    fail(source, "missing 'packages' object");

  const packages: LockedPackage[] = [];
  for (const [path, raw] of Object.entries(pkgs as Record<string, unknown>)) {
    if (path === "") continue; // the project itself
    if (typeof raw !== "object" || raw === null) fail(source, `packages["${path}"] is not an object`);
    const e = raw as Record<string, unknown>;
    if (e["link"] === true) continue; // a workspace symlink; its target is listed separately
    const fromPath = nameFromPath(path);
    if (fromPath === undefined) {
      // A workspace package ("packages/foo"): local code, not a downloaded dependency.
      continue;
    }
    const name = typeof e["name"] === "string" ? (e["name"] as string) : fromPath;
    if (!NAME.test(name)) fail(source, `packages["${path}"]: '${name}' is not a valid package name`);
    const version = e["version"];
    if (typeof version !== "string" || !VERSION.test(version)) {
      fail(source, `packages["${path}"]: version ${JSON.stringify(version)} is not a semver version`);
    }
    for (const k of ["resolved", "integrity"] as const) {
      if (e[k] !== undefined && typeof e[k] !== "string")
        fail(source, `packages["${path}"]: '${k}' is not a string`);
    }
    const deps = e["dependencies"];
    if (deps !== undefined && (typeof deps !== "object" || deps === null || Array.isArray(deps))) {
      fail(source, `packages["${path}"]: 'dependencies' is not an object`);
    }
    packages.push({
      path,
      name,
      version,
      resolved: e["resolved"] as string | undefined,
      integrity: e["integrity"] as string | undefined,
      dependencies: Object.keys((deps as Record<string, unknown>) ?? {}).sort(),
      dev: e["dev"] === true,
      optional: e["optional"] === true,
    });
  }
  packages.sort((a, b) => a.path.localeCompare(b.path));
  return { lockfileVersion: v, packages };
}

export function key(p: { name: string; version: string }): string {
  return `${p.name}@${p.version}`;
}
