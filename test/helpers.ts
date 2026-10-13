import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

export function tempDir(prefix = "permit-test-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export interface TarEntry {
  name: string;
  body?: string | Buffer;
  /** ustar type flag: "0" file (default), "5" dir, "2" symlink, "1" hard link. */
  type?: string;
  linkname?: string;
}

function header(name: string, size: number, type: string, linkname = ""): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write("0000644\0", 100);
  h.write("0000000\0", 108);
  h.write("0000000\0", 116);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write("00000000000\0", 136);
  h.write("        ", 148);
  h.write(type, 156);
  h.write(linkname, 157, 100);
  h.write("ustar\0", 257);
  h.write("00", 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}

function pad(b: Buffer): Buffer {
  const rem = b.length % 512;
  return rem === 0 ? b : Buffer.concat([b, Buffer.alloc(512 - rem)]);
}

/** A gzipped ustar archive, as npm pack writes them (with pax headers for long names). */
export function tarball(entries: TarEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    const body = typeof e.body === "string" ? Buffer.from(e.body) : (e.body ?? Buffer.alloc(0));
    let name = e.name;
    if (Buffer.byteLength(name) > 99) {
      const rec = ` path=${name}\n`;
      let len = rec.length + 2;
      while (`${len}${rec}`.length !== len) len = `${len}${rec}`.length;
      const pax = Buffer.from(`${len}${rec}`);
      parts.push(header("PaxHeader", pax.length, "x"), pad(pax));
      name = name.slice(0, 99);
    }
    parts.push(header(name, e.type && e.type !== "0" ? 0 : body.length, e.type ?? "0", e.linkname));
    if (!e.type || e.type === "0") parts.push(pad(body));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

/** A tiny deterministic RNG for the property tests. */
export function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
