# permit

[![CI](https://github.com/ahmed-hashim-pro/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed-hashim-pro/permit/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A CLI and GitHub Action that reads a dependency upgrade the way a security
reviewer would. It answers one question: **what can the new code do that the
old code couldn't?** If an upgrade newly opens network connections, runs a
script at install time, starts processes, reads environment variables or
loads code by a computed name, the pull request stops until someone allows
it.

Most supply-chain attacks on npm arrive as an ordinary-looking version bump.

- **event-stream 3.3.6** added one small dependency. Its minified file read
  `process.env` through an alias and `require`d a module by a decoded string.
- **ua-parser-js 0.7.29** gained a `preinstall` script that downloaded and
  started a binary.

Neither change shows up in a lockfile diff. Both are obvious once someone
asks what the package can now _do_. Nobody reads 400 transitive dependencies
on every bump, so `permit` asks for them.

```
$ permit diff before.json after.json
1 package version added or changed; 1 with something new, 1 blocked by policy

ua-sniff 0.7.28 -> 0.7.29
  NEW     install-script  package.json  preinstall: node preinstall.js
  NEW     network         preinstall.js:5  requires 'https'
  NEW     exec            preinstall.js:7  requires 'child_process'
  NEW     fs-write        preinstall.js:13  calls fs createWriteStream()
  NEW     env             preinstall.js:10  reads process.env

Blocked: ua-sniff@0.7.29.
Review them, then allow what is expected in permit.json, e.g.
  { "allow": { "ua-sniff": ["install-script", "network", "exec", "fs-write", "env"] } }
$ echo $?
1
```

![Terminal recording: permit blocks the ua-sniff patch release that gains a preinstall downloader; flags flatmap-lite, a new transitive dependency that reads a computed property of process through an alias and requires a computed module name; then, with a permit.json that allows fast-bundler's install script and binary, passes fast-bundler and blocks only @acme/logger, which newly calls fetch and reads process.env](docs/demo.gif)

_The examples use small synthetic packages in `fixtures/packages/`. They're
shaped like the real incidents and are inert: the hosts are `.invalid`, the
"payload" is empty, and nothing runs. `make demo` re-records this._

## Quickstart

You need Node 20 or newer.

```bash
git clone https://github.com/ahmed-hashim-pro/permit && cd permit
npm ci && npm run build

# The three examples, offline:
cd examples/ua-sniff
node ../../dist/src/cli.js diff before.json after.json --fixtures ../../fixtures/packages
cd ../event-stream
node ../../dist/src/cli.js diff before.json after.json --fixtures ../../fixtures/packages
cd ../monday
node ../../dist/src/cli.js diff before.json after.json --fixtures ../../fixtures/packages
cd ../..

# Your own project, against the real registry: compare main's lockfile with yours.
node dist/src/cli.js diff --base origin/main      # run inside your repository
```

`npm test` runs the suite in a few seconds, without network access.

### In CI

```yaml
# .github/workflows/permit.yml
on: pull_request
jobs:
  permit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ahmed-hashim-pro/permit@main
```

The action compares the base branch's `package-lock.json` with the pull
request's. It writes the report to the job summary and fails the check when
anything new isn't allowed. Inputs: `base`, `lockfile`, `policy`.

## The policy

`permit.json`, in the repository root:

```json
{
  "$comment": "fast-bundler ships a native binary and checks it on install, like esbuild.",
  "allow": {
    "fast-bundler": ["install-script", "binary"],
    "*": []
  }
}
```

The policy is per package, and `"*"` applies to every package. An allowed
gain is still printed, marked `allowed`, so the review trail stays visible.
A misspelt capability or an unknown key is an error, not a silent allow.
`permit` never edits the policy itself. It prints the line you would add, and
a person decides.

## What it detects

`permit capabilities`:

| Capability        | Meaning                           | How                                                                                                                                                      |
| ----------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `install-script`  | runs code at install              | `preinstall`/`install`/`postinstall`, or a `binding.gyp` (npm runs `node-gyp rebuild`)                                                                   |
| `native-build`    | compiles native code at install   | `binding.gyp` or `"gypfile": true`                                                                                                                       |
| `network`         | can talk to the network           | imports `http`, `https`, `http2`, `net`, `tls`, `dgram`, `dns` or `undici`; calls `fetch`, `WebSocket`, `XMLHttpRequest` or `EventSource`                |
| `exec`            | can start programs                | imports `child_process`                                                                                                                                  |
| `fs-write`        | writes, deletes or changes files  | a write-family call on a name bound to `fs`/`fs/promises` (`writeFile*`, `appendFile*`, `createWriteStream`, `rm*`, `unlink*`, `chmod*`, `rename*`, ...) |
| `env`             | reads environment variables       | `process.env`, or any computed property of `process`                                                                                                     |
| `dynamic-code`    | evaluates strings as code         | `eval`, `Function`, `new Function`, `vm`, `._compile()`                                                                                                  |
| `dynamic-require` | loads a module by a computed name | `require(x)` or `import(x)` with a non-literal argument                                                                                                  |
| `binary`          | ships compiled code               | `.node` addons; files starting with ELF, Mach-O or PE magic                                                                                              |
| `unanalyzable`    | could not be checked              | JavaScript that doesn't parse, a file over 4 MB, or a package that couldn't be fetched                                                                   |

Every `.js`, `.cjs` and `.mjs` file is **parsed with acorn and walked**, not
grepped. A comment or a string that mentions `child_process` isn't a use of
it. `require` and `process` are tracked through aliases (`var r = require`,
`t = process`), because that's how obfuscated payloads hide them:

```
flatmap-lite 0.1.1 (new, required by stream-pipe)
  NEW     env              index.min.js:7  reads a computed property of process (as 't')
  NEW     dynamic-require  index.min.js:7  require() (as 'r') of a computed name
```

The event-stream-shaped fixture hides its network code inside an encrypted
string, so `network` can't be seen. What _can_ be seen, an aliased `require`
of a decoded name and a computed read of `process`, is enough to block it.
That's the general approach. When the analysis can't resolve something, it
reports that as a capability instead of dropping it.

## How the diff works

1. **Parse both lockfiles strictly.** Only `lockfileVersion` 2 or 3, which
   are the versions with a `packages` section listing what lands in
   `node_modules`. Workspace links are skipped. A malformed entry, a
   non-semver version or a v1 lockfile is an error with the entry's path.
2. **Find every package version installed after but not before.** A name
   that existed before at other versions is _changed_. A new name is _new_,
   and everything it can do counts as new, because a fresh transitive
   dependency is how most attacks arrive.
3. **Fetch each version, before and after.** The source is the URL the
   lockfile resolved to, or the registry's conventional one. The tarball is
   checked against the lockfile's `integrity` hash, so the bytes analysed
   are the bytes npm would install, and a mismatch is an error. Downloads run
   eight at a time with retries. Tarballs and unpacked files are cached in
   `$XDG_CACHE_HOME/permit` (or `~/.cache/permit` when it is unset) by name,
   version and hash.
4. **Unpack safely.** Only regular files are written. Symlinks and hard
   links are skipped, and an entry whose path would escape the package
   directory makes the tarball be refused, not analysed.
5. **Profile and subtract.** The gains are the new version's capabilities
   minus everything _any_ previously installed version of that package had.
   Each gain carries the file and line where it was first seen. Packages
   bundled inside a tarball's own `node_modules` are skipped, because the
   lockfile lists them separately.
6. **Apply the policy.** Exit 1 if any gain isn't allowed.

A package that can't be fetched or read doesn't pass. It's reported as
`unanalyzable` and blocks like any other gain.

### A real upgrade

Against the live registry, upgrading `esbuild` 0.17.19 → 0.18.20 and
`node-fetch` 2.6.7 → 3.3.2 changes 29 package versions:

```
node-domexception 1.0.0 (new, required by fetch-blob)
  NEW     unanalyzable  .history/index_20210527213843.js:9  Unexpected token (9:2)

node-fetch 2.6.7 -> 3.3.2
  new dependencies: data-uri-to-buffer, fetch-blob, formdata-polyfill

27 others changed version without gaining anything.
```

That's the expected answer. esbuild's install script and platform binaries
were already there in 0.17, so they aren't new. node-fetch 3 already used
`http` in 2.x. The one block is real: `node-domexception` publishes an editor
history file that doesn't parse. It's harmless here, but `permit` can't
_know_ that, so it says so and leaves the call to a person. The cold run took
54 s, mostly downloading esbuild's binaries for every platform. The warm run
took 1 s.

## How it is tested

`npm test` runs 36 tests with `node:test`, all offline:

- **The analyser (8).**
  - 26 snippets, one per detection route: CommonJS, ESM, `node:` prefixes,
    dynamic `import()`, globals, destructuring, aliases.
  - Comments, strings and look-alikes that must _not_ trigger, and line
    numbers in evidence.
  - Package-level detection: scripts, `binding.gyp`, ELF/PE/`.node` binaries.
    Bundled `node_modules` and symlinks are ignored.
  - A **property test**: 500 files assembled at random from snippets with
    known capabilities, mixed with harmless code and decoys. The detected set
    must equal the union exactly.
- **Lockfiles (5) and the policy (2).** Valid v2/v3 trees with nested,
  scoped and aliased packages and workspace links, plus every class of
  malformed input.
- **Sources (8).**
  - A tar writer in the tests produces archives with pax long names,
    directories, symlinks and hard links. Path-traversal entries are refused,
    and a refused tarball leaves nothing in the cache.
  - A real `npm pack` tarball is read.
  - SRI integrity: several hashes, and mismatches.
  - A local HTTP registry checks downloading, caching (the second fetch makes
    no request), integrity failure, 404, retry on a network error and on
    503, and no retry on 404.
- **The diff (6).**
  - The three examples end to end.
  - A policy allowing exactly what it lists.
  - A lockfile against itself.
  - A capability held by _any_ earlier version not counting as new.
  - An unfetchable package blocked as `unanalyzable`.
- **The CLI (7).**
  - Exit codes 0, 1 and 2, and `--json`.
  - `--base` against a temporary git repository, picking up `./permit.json`.
  - `scan`, `capabilities`, and eleven kinds of usage error.

CI runs:

- prettier, `tsc --strict` and the tests on Node 20 and 22
- a check that `examples/` matches `scripts/examples.py`
- the action itself on this repository's own lockfile

## What this does not do

- **It is static analysis, and it can be evaded.** Code that builds
  `require` from `globalThis["req" + "uire"]`, or decrypts a payload and runs
  it through a path not listed above, can hide a capability. Common evasions
  (aliases, computed requires, computed `process` access, `eval`,
  `_compile`) are flagged as capabilities in their own right. A determined
  attacker can still get past it. `permit` raises the cost of a quiet upgrade.
  It doesn't replace sandboxing installs (`--ignore-scripts`) or reviewing
  what it flags.
- **Capabilities are per package, not per call path.** A package that uses
  `https` in an optional CLI you never call still "has network". The answer
  is to allow it, once, in `permit.json`.
- **npm's lockfile only.** No yarn, pnpm, or bun lockfiles yet. Packages from
  git or local paths can't be fetched as tarballs and are reported as
  `unanalyzable`.
- **No vulnerability database.** `permit` says what a version can newly do,
  not whether it has a known CVE. Use `npm audit` for that.
- **The examples are synthetic.** The real flatmap-stream and the hijacked
  ua-parser-js releases were unpublished, rightly. The fixtures copy the
  shape of what those releases did, not their code.

## License

MIT
