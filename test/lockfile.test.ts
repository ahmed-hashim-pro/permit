import { test } from "node:test";
import assert from "node:assert/strict";
import { nameFromPath, parseLockfile, LockfileError } from "../src/lockfile.js";

const lock = (packages: Record<string, unknown>, v = 3) => JSON.stringify({ lockfileVersion: v, packages });

test("reads v2 and v3 packages, nested and scoped", () => {
  for (const v of [2, 3]) {
    const l = parseLockfile(
      lock(
        {
          "": { name: "app", version: "1.0.0" },
          "node_modules/a": { version: "1.0.0", dependencies: { b: "^2", "@s/c": "1" } },
          "node_modules/a/node_modules/b": {
            version: "2.1.0",
            resolved: "https://r/b-2.1.0.tgz",
            integrity: "sha512-x",
          },
          "node_modules/@s/c": { version: "1.0.0-beta.1", dev: true, optional: true },
        },
        v,
      ),
    );
    assert.deepEqual(
      l.packages.map((p) => `${p.name}@${p.version}`),
      ["@s/c@1.0.0-beta.1", "a@1.0.0", "b@2.1.0"],
    );
    const a = l.packages.find((p) => p.name === "a")!;
    assert.deepEqual(a.dependencies, ["@s/c", "b"]);
    assert.equal(l.packages.find((p) => p.name === "@s/c")!.dev, true);
  }
});

test("an aliased package keeps its real name", () => {
  const l = parseLockfile(lock({ "node_modules/alias": { name: "real-pkg", version: "1.0.0" } }));
  assert.equal(l.packages[0]!.name, "real-pkg");
});

test("workspace links and workspace sources are not dependencies", () => {
  const l = parseLockfile(
    lock({
      "node_modules/ws-a": { resolved: "packages/a", link: true },
      "packages/a": { name: "ws-a", version: "0.0.1" },
      "node_modules/x": { version: "1.0.0" },
    }),
  );
  assert.deepEqual(
    l.packages.map((p) => p.name),
    ["x"],
  );
});

test("refuses what it cannot be sure of", () => {
  const cases: [string, RegExp][] = [
    ["not json", /not JSON/],
    ["[]", /not a JSON object/],
    [JSON.stringify({ lockfileVersion: 1, dependencies: {} }), /lockfileVersion 1/],
    [JSON.stringify({ lockfileVersion: 4, packages: {} }), /unsupported lockfileVersion 4/],
    [JSON.stringify({ lockfileVersion: 3 }), /missing 'packages'/],
    [lock({ "node_modules/a": "1.0.0" }), /is not an object/],
    [lock({ "node_modules/a": { version: "^1.0.0" } }), /not a semver version/],
    [lock({ "node_modules/a": {} }), /not a semver version/],
    [lock({ "node_modules/A B": { version: "1.0.0" } }), /not a valid package name/],
    [lock({ "node_modules/a": { version: "1.0.0", integrity: 5 } }), /'integrity' is not a string/],
    [lock({ "node_modules/a": { version: "1.0.0", dependencies: [] } }), /'dependencies' is not an object/],
  ];
  for (const [text, re] of cases) {
    assert.throws(
      () => parseLockfile(text, "x.json"),
      (e: unknown) => e instanceof LockfileError && re.test((e as Error).message),
      text,
    );
  }
});

test("nameFromPath", () => {
  assert.equal(nameFromPath("node_modules/a"), "a");
  assert.equal(nameFromPath("node_modules/a/node_modules/@s/b"), "@s/b");
  assert.equal(nameFromPath("packages/a"), undefined);
});
