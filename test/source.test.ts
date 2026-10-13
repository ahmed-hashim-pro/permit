import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { checkIntegrity, extractTarball, FixtureSource, RegistrySource, SourceError } from "../src/source.js";
import type { LockedPackage } from "../src/lockfile.js";
import { tarball, tempDir } from "./helpers.js";

const sri = (b: Buffer) => "sha512-" + createHash("sha512").update(b).digest("base64");
const pkg = (over: Partial<LockedPackage> = {}): LockedPackage => ({
  path: "node_modules/p",
  name: "p",
  version: "1.0.0",
  dependencies: [],
  dev: false,
  optional: false,
  ...over,
});

test("extracts regular files, strips the top directory", () => {
  const d = tempDir();
  const long = "package/" + "deep/".repeat(25) + "file.js";
  const n = extractTarball(
    tarball([
      { name: "package/package.json", body: '{"name":"p"}' },
      { name: "package/lib", type: "5" },
      { name: "package/lib/a.js", body: "x" },
      { name: long, body: "long" },
      { name: "package/link", type: "2", linkname: "/etc/passwd" },
      { name: "package/hard", type: "1", linkname: "package/lib/a.js" },
    ]),
    d,
  );
  assert.equal(n, 3);
  assert.equal(readFileSync(join(d, "lib/a.js"), "utf8"), "x");
  assert.equal(readFileSync(join(d, long.slice("package/".length)), "utf8"), "long");
  assert.equal(existsSync(join(d, "link")), false);
  assert.equal(existsSync(join(d, "hard")), false);
});

test("an entry escaping the package directory is refused", () => {
  for (const name of ["package/../../evil.js", "package/a/../../../x"]) {
    assert.throws(() => extractTarball(tarball([{ name, body: "x" }]), tempDir()), SourceError, name);
  }
});

test("reads a tarball written by npm pack", () => {
  const d = tempDir();
  extractTarball(readFileSync("test/data/left-padder-1.3.0.tgz"), d);
  assert.equal(JSON.parse(readFileSync(join(d, "package.json"), "utf8")).version, "1.3.0");
  assert.ok(existsSync(join(d, "index.js")));
});

test("integrity: SRI sha512/sha1, several hashes, mismatches", () => {
  const b = Buffer.from("hello");
  assert.ok(checkIntegrity(b, sri(b)));
  assert.ok(checkIntegrity(b, "sha1-" + createHash("sha1").update(b).digest("base64")));
  assert.ok(checkIntegrity(b, `sha512-AAAA ${sri(b)}`));
  assert.ok(!checkIntegrity(b, sri(Buffer.from("other"))));
  assert.ok(!checkIntegrity(b, "md5-whatever"));
});

test("fixtures are looked up by name and version", async () => {
  const s = new FixtureSource("fixtures/packages");
  assert.match(await s.unpack(pkg({ name: "@acme/logger", version: "2.1.0" })), /@acme\+logger@2\.1\.0$/);
  await assert.rejects(s.unpack(pkg({ name: "nope" })), SourceError);
});

test("registry: downloads, verifies, caches; refuses a mismatch", async () => {
  const body = tarball([
    { name: "package/package.json", body: '{"name":"p","version":"1.0.0"}' },
    { name: "package/index.js", body: "fetch(u)" },
  ]);
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    if (req.url === "/p/-/p-1.0.0.tgz") res.end(body);
    else (res.statusCode = 404), res.end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const cacheDir = tempDir();
    const s = new RegistrySource({ registry: base, cacheDir });
    const dir = await s.unpack(pkg({ integrity: sri(body) }));
    assert.equal(readFileSync(join(dir, "index.js"), "utf8"), "fetch(u)");
    await s.unpack(pkg({ integrity: sri(body) }));
    assert.equal(requests, 1, "second unpack is served from the cache");

    await assert.rejects(
      new RegistrySource({ registry: base, cacheDir: tempDir() }).unpack(
        pkg({ integrity: sri(Buffer.from("x")) }),
      ),
      /does not match/,
    );
    await assert.rejects(
      new RegistrySource({ registry: base, cacheDir: tempDir() }).unpack(pkg({ name: "q" })),
      /returned 404/,
    );
    await assert.rejects(
      s.unpack(pkg({ resolved: "git+ssh://git@github.com/x/y.git" })),
      /not a registry tarball/,
    );
    // A lockfile's own URL wins over the registry convention.
    const viaResolved = new RegistrySource({ registry: "http://unused.invalid", cacheDir: tempDir() });
    assert.ok(await viaResolved.unpack(pkg({ resolved: `${base}/p/-/p-1.0.0.tgz` })));
  } finally {
    server.close();
  }
});

test("registry: retries a 5xx, but not a 4xx", async () => {
  const body = tarball([{ name: "package/package.json", body: '{"name":"p","version":"1.0.0"}' }]);
  let calls = 0;
  const flaky: typeof fetch = async () => {
    calls++;
    if (calls === 1) throw new TypeError("fetch failed");
    if (calls === 2) return new Response("busy", { status: 503 });
    return new Response(body);
  };
  const s = new RegistrySource({ cacheDir: tempDir(), fetchImpl: flaky });
  assert.ok(await s.unpack(pkg()));
  assert.equal(calls, 3);

  let gone = 0;
  const notFound: typeof fetch = async () => (gone++, new Response("", { status: 404 }));
  await assert.rejects(new RegistrySource({ cacheDir: tempDir(), fetchImpl: notFound }).unpack(pkg()), /404/);
  assert.equal(gone, 1);
});
