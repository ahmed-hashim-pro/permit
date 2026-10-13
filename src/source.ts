// Where package contents come from: the registry (with an on-disk cache and
// integrity checking), or a directory of unpacked fixtures.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, normalize, isAbsolute } from "node:path";
import { gunzipSync } from "node:zlib";
import type { LockedPackage } from "./lockfile.js";

export interface Source {
  /** A directory holding the package's files (package.json at its root). */
  unpack(pkg: LockedPackage): Promise<string>;
}

export class SourceError extends Error {}

function slug(p: { name: string; version: string }): string {
  return `${p.name.replace("/", "+")}@${p.version}`;
}

/** Unpacked packages in `dir/<name>@<version>/`, with "/" in scoped names as "+". */
export class FixtureSource implements Source {
  constructor(private readonly dir: string) {}
  async unpack(pkg: LockedPackage): Promise<string> {
    const d = join(this.dir, slug(pkg));
    if (!existsSync(join(d, "package.json")))
      throw new SourceError(`no fixture for ${pkg.name}@${pkg.version} in ${this.dir}`);
    return d;
  }
}

/** Checks a buffer against an SRI string such as "sha512-<base64>". */
export function checkIntegrity(data: Buffer, integrity: string): boolean {
  // SRI allows several space-separated hashes; any one matching is enough.
  for (const part of integrity.trim().split(/\s+/)) {
    const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/=]+)$/.exec(part);
    if (!m) continue;
    const got = createHash(m[1]!).update(data).digest("base64");
    if (got === m[2]) return true;
  }
  return false;
}

/**
 * Extracts a gzipped npm tarball into `dest`. Only regular files are
 * written. Links are skipped, and an entry whose path would land outside
 * `dest` is an error: a tarball that tries that is not analysed, it is refused.
 */
export function extractTarball(tgz: Buffer, dest: string): number {
  const tar = gunzipSync(tgz);
  let off = 0;
  let count = 0;
  let longName: string | undefined;
  const str = (b: Buffer) => {
    const nul = b.indexOf(0);
    return b.subarray(0, nul < 0 ? b.length : nul).toString("utf8");
  };
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    const sizeField = str(h.subarray(124, 136)).trim();
    const size = sizeField === "" ? 0 : parseInt(sizeField, 8);
    if (!Number.isFinite(size) || size < 0) throw new SourceError(`corrupt tar header at byte ${off}`);
    const type = String.fromCharCode(h[156] ?? 0);
    const body = tar.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;

    if (type === "x") {
      // pax extended header: "len path=value\n" records.
      const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(body.toString("utf8"));
      if (m) longName = m[1];
      continue;
    }
    if (type === "L") {
      longName = str(body);
      continue;
    }
    if (type === "g") continue;
    const prefix = str(h.subarray(345, 500));
    let name = longName ?? (prefix ? `${prefix}/${str(h.subarray(0, 100))}` : str(h.subarray(0, 100)));
    longName = undefined;
    if (type !== "0" && type !== "\0" && type !== "7") continue; // directories, links, devices

    // npm tarballs put everything under one top directory, usually "package/".
    const slash = name.indexOf("/");
    name = slash >= 0 ? name.slice(slash + 1) : name;
    if (name === "") continue;
    const target = normalize(join(dest, name));
    if (isAbsolute(name) || name.split("/").includes("..") || !target.startsWith(normalize(dest) + "/")) {
      throw new SourceError(`tarball entry '${name}' escapes the package directory`);
    }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, body);
    count++;
  }
  return count;
}

export interface RegistryOptions {
  registry?: string;
  cacheDir?: string;
  fetchImpl?: typeof fetch;
}

/**
 * Downloads tarballs (the lockfile's `resolved` URL, or the registry's
 * conventional one), checks them against the lockfile's integrity hash, and
 * keeps both the tarball and its unpacked files in a cache keyed by name,
 * version and hash. A mismatch is an error, never a warning: the bytes being
 * analysed must be the bytes npm would install.
 */
export class RegistrySource implements Source {
  readonly registry: string;
  readonly cacheDir: string;
  private readonly fetchImpl: typeof fetch;
  constructor(opts: RegistryOptions = {}) {
    this.registry = (opts.registry ?? "https://registry.npmjs.org").replace(/\/+$/, "");
    this.cacheDir =
      opts.cacheDir ?? join(process.env["XDG_CACHE_HOME"] ?? join(homedir(), ".cache"), "permit");
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /** GET with three attempts on network errors and 5xx; a 4xx is final. */
  private async download(url: string, what: string): Promise<Buffer> {
    let last = "";
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 250 * 4 ** (attempt - 1)));
      let res: Response;
      try {
        res = await this.fetchImpl(url);
      } catch (e) {
        last = `${(e as Error).message}${(e as { cause?: Error }).cause ? ` (${(e as { cause: Error }).cause.message})` : ""}`;
        continue;
      }
      if (res.ok) return Buffer.from(await res.arrayBuffer());
      last = `GET ${url} returned ${res.status}`;
      if (res.status < 500) break;
    }
    throw new SourceError(`${what}: ${last}`);
  }

  url(pkg: LockedPackage): string {
    if (pkg.resolved) return pkg.resolved;
    const base = pkg.name.split("/").pop()!;
    return `${this.registry}/${pkg.name}/-/${base}-${pkg.version}.tgz`;
  }

  async unpack(pkg: LockedPackage): Promise<string> {
    const url = this.url(pkg);
    if (!/^https?:\/\//.test(url)) {
      throw new SourceError(
        `${pkg.name}@${pkg.version} resolves to '${url}', which is not a registry tarball`,
      );
    }
    const tag = pkg.integrity
      ? createHash("sha256").update(pkg.integrity).digest("hex").slice(0, 16)
      : "unverified";
    const root = join(this.cacheDir, `${slug(pkg)}-${tag}`);
    const done = join(root, ".permit-complete");
    const dir = join(root, "package");
    if (existsSync(done)) return dir;

    const data = await this.download(url, `${pkg.name}@${pkg.version}`);
    if (pkg.integrity && !checkIntegrity(data, pkg.integrity)) {
      throw new SourceError(
        `${pkg.name}@${pkg.version}: the tarball from ${url} does not match the lockfile's integrity hash`,
      );
    }
    // Unpack beside the final place, then move it in, so a crash never leaves
    // a half-written package that looks complete.
    const tmp = `${root}.tmp-${process.pid}`;
    rmSync(tmp, { recursive: true, force: true });
    try {
      mkdirSync(join(tmp, "package"), { recursive: true });
      try {
        extractTarball(data, join(tmp, "package"));
      } catch (e) {
        if (e instanceof SourceError) throw new SourceError(`${pkg.name}@${pkg.version}: ${e.message}`);
        throw e;
      }
      writeFileSync(join(tmp, "package.tgz"), data);
      writeFileSync(join(tmp, ".permit-complete"), url + "\n");
      rmSync(root, { recursive: true, force: true });
      mkdirSync(dirname(root), { recursive: true });
      renameSync(tmp, root);
    } catch (e) {
      // A refused or failed unpack leaves nothing behind in the cache.
      rmSync(tmp, { recursive: true, force: true });
      throw e;
    }
    return dir;
  }
}
