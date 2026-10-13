// What a package version can do, read from its files: a capability profile.
//
// JavaScript is parsed with acorn and walked, not grepped, so a comment or a
// string that mentions "child_process" is not mistaken for a use of it. The
// analysis is static and per file. What it cannot resolve it does not drop:
// a require() of a computed string is reported as `dynamic-require`, and a
// file that does not parse is reported as `unanalyzable`. Both are
// capabilities in their own right: "this package can do something we could
// not see".

import { closeSync, lstatSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import * as acorn from "acorn";
import * as walk from "acorn-walk";

export const CAPABILITIES = [
  "install-script",
  "native-build",
  "network",
  "exec",
  "fs-write",
  "env",
  "dynamic-code",
  "dynamic-require",
  "binary",
  "unanalyzable",
] as const;
export type Capability = (typeof CAPABILITIES)[number];

export const DESCRIPTIONS: Record<Capability, string> = {
  "install-script": "runs code when installed (preinstall, install or postinstall)",
  "native-build": "compiles native code on install (binding.gyp / node-gyp)",
  network: "imports a networking module or calls fetch/WebSocket",
  exec: "can start other programs (child_process)",
  "fs-write": "writes, deletes or changes permissions of files",
  env: "reads environment variables (tokens and secrets live there)",
  "dynamic-code": "evaluates strings as code (eval, new Function, vm)",
  "dynamic-require": "loads a module whose name is computed at run time",
  binary: "ships a compiled executable or native library",
  unanalyzable:
    "could not be checked: JavaScript that does not parse, a file over 4 MB, or a package that could not be fetched",
};

export interface Evidence {
  file: string;
  line: number;
  detail: string;
}

/** Each capability present, with the first place it was seen. */
export type Profile = Partial<Record<Capability, Evidence>>;

const NETWORK_MODULES = new Set(["http", "https", "http2", "net", "tls", "dgram", "dns", "undici"]);
const EXEC_MODULES = new Set(["child_process"]);
const FS_MODULES = new Set(["fs", "fs/promises"]);
const FS_WRITES = new Set([
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "createWriteStream",
  "unlink",
  "unlinkSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "mkdir",
  "mkdirSync",
  "rename",
  "renameSync",
  "chmod",
  "chmodSync",
  "chown",
  "chownSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "symlink",
  "symlinkSync",
  "link",
  "linkSync",
  "truncate",
  "truncateSync",
]);
const NETWORK_GLOBALS = new Set(["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]);
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"] as const;
const JS = /\.(?:js|cjs|mjs)$/;
const MAX_JS_BYTES = 4 * 1024 * 1024;

function builtin(spec: string): string {
  return spec.startsWith("node:") ? spec.slice(5) : spec;
}

function note(p: Profile, cap: Capability, ev: Evidence): void {
  if (!p[cap]) p[cap] = ev;
}

/** Magic numbers of executables and native libraries. */
function isBinary(head: Buffer): string | undefined {
  if (head.length >= 4 && head.readUInt32BE(0) === 0x7f454c46) return "ELF";
  if (head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a) return "PE (Windows)";
  if (head.length >= 4) {
    const m = head.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m)) return "Mach-O";
  }
  return undefined;
}

function head(file: string): Buffer {
  const buf = Buffer.alloc(4);
  const fd = openSync(file, "r");
  try {
    const n = readSync(fd, buf, 0, 4, 0);
    return buf.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

function files(dir: string): string[] {
  const out: string[] = [];
  const visit = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      const full = join(d, name);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) continue; // never follow links out of the package
      if (st.isDirectory()) visit(full);
      else if (st.isFile()) out.push(full);
    }
  };
  visit(dir);
  return out;
}

/** Analyse one JavaScript source; `file` is used only for evidence. */
export function analyzeSource(source: string, file: string, profile: Profile = {}): Profile {
  let ast: acorn.Node;
  const opts = {
    ecmaVersion: "latest" as const,
    allowHashBang: true,
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowAwaitOutsideFunction: true,
    locations: true,
  };
  try {
    ast = acorn.parse(source, { ...opts, sourceType: "module" });
  } catch {
    try {
      ast = acorn.parse(source, { ...opts, sourceType: "script" });
    } catch (e) {
      note(profile, "unanalyzable", {
        file,
        line: (e as { loc?: { line: number } }).loc?.line ?? 0,
        detail: (e as Error).message,
      });
      return profile;
    }
  }

  const line = (n: acorn.Node) => n.loc?.start.line ?? 0;
  // Local names bound to fs modules, for `fs.writeFileSync` style calls.
  const fsNames = new Set<string>();
  const fsWriteCalls: acorn.Node[] = [];

  const useModule = (spec: string, at: acorn.Node, how: string) => {
    const m = builtin(spec);
    const ev = { file, line: line(at), detail: `${how} '${spec}'` };
    if (NETWORK_MODULES.has(m)) note(profile, "network", ev);
    if (EXEC_MODULES.has(m)) note(profile, "exec", ev);
    if (m === "vm") note(profile, "dynamic-code", ev);
  };
  const literal = (n: acorn.Node | undefined | null): string | undefined => {
    if (!n) return undefined;
    const a = n as acorn.Node & {
      type: string;
      value?: unknown;
      expressions?: unknown[];
      quasis?: { value: { cooked: string } }[];
    };
    if (a.type === "Literal" && typeof a.value === "string") return a.value;
    if (a.type === "TemplateLiteral" && a.expressions?.length === 0) return a.quasis?.[0]?.value.cooked;
    return undefined;
  };
  // Names that hold `require` or `process` under another name (`var r = require`,
  // `t = process`): how obfuscated code hides both. Collected first, so a use
  // above the assignment is still recognised.
  const requireNames = new Set(["require"]);
  const processNames = new Set(["process"]);
  walk.full(ast, (node) => {
    const n = node as any;
    const alias = (target: any, value: any) => {
      if (target?.type !== "Identifier" || value?.type !== "Identifier") return;
      if (value.name === "require") requireNames.add(target.name);
      if (value.name === "process") processNames.add(target.name);
    };
    if (n.type === "VariableDeclarator") alias(n.id, n.init);
    if (n.type === "AssignmentExpression") alias(n.left, n.right);
  });
  const isRequire = (callee: any) => callee?.type === "Identifier" && requireNames.has(callee.name);

  walk.full(ast, (node) => {
    const n = node as any;
    switch (n.type) {
      case "ImportDeclaration":
      case "ExportAllDeclaration":
      case "ExportNamedDeclaration": {
        const spec = literal(n.source);
        if (spec !== undefined) {
          useModule(spec, n, "imports");
          if (FS_MODULES.has(builtin(spec))) {
            for (const s of n.specifiers ?? []) {
              const imported = s.imported?.name ?? s.local?.name;
              if (s.type === "ImportSpecifier" && FS_WRITES.has(imported)) {
                note(profile, "fs-write", {
                  file,
                  line: line(n),
                  detail: `imports ${imported} from '${spec}'`,
                });
              } else if (s.local) fsNames.add(s.local.name);
            }
          }
        }
        break;
      }
      case "ImportExpression": {
        const spec = literal(n.source);
        if (spec === undefined)
          note(profile, "dynamic-require", { file, line: line(n), detail: "import() of a computed name" });
        else useModule(spec, n, "imports");
        break;
      }
      case "CallExpression": {
        if (isRequire(n.callee)) {
          const spec = literal(n.arguments[0]);
          if (spec === undefined) {
            const as = n.callee.name === "require" ? "require()" : `require() (as '${n.callee.name}')`;
            note(profile, "dynamic-require", { file, line: line(n), detail: `${as} of a computed name` });
          } else {
            useModule(spec, n, "requires");
          }
        } else if (n.callee.type === "Identifier") {
          if (n.callee.name === "eval")
            note(profile, "dynamic-code", { file, line: line(n), detail: "calls eval()" });
          if (n.callee.name === "Function")
            note(profile, "dynamic-code", { file, line: line(n), detail: "calls Function()" });
          if (NETWORK_GLOBALS.has(n.callee.name))
            note(profile, "network", { file, line: line(n), detail: `calls ${n.callee.name}()` });
        } else if (n.callee.type === "MemberExpression") {
          const prop = n.callee.computed ? literal(n.callee.property) : n.callee.property?.name;
          if (prop && FS_WRITES.has(prop)) fsWriteCalls.push(n);
          // module._compile(src): how the event-stream payload ran its decrypted code.
          if (prop === "_compile")
            note(profile, "dynamic-code", { file, line: line(n), detail: "calls _compile()" });
          // globalThis.fetch(...)
          if (
            prop &&
            NETWORK_GLOBALS.has(prop) &&
            n.callee.object.type === "Identifier" &&
            ["globalThis", "window", "self", "global"].includes(n.callee.object.name)
          ) {
            note(profile, "network", { file, line: line(n), detail: `calls ${prop}()` });
          }
        }
        break;
      }
      case "NewExpression": {
        if (n.callee.type === "Identifier" && n.callee.name === "Function") {
          note(profile, "dynamic-code", { file, line: line(n), detail: "new Function()" });
        }
        if (n.callee.type === "Identifier" && NETWORK_GLOBALS.has(n.callee.name)) {
          note(profile, "network", { file, line: line(n), detail: `new ${n.callee.name}()` });
        }
        break;
      }
      case "VariableDeclarator": {
        // const fs = require('fs'), const { writeFileSync } = require('fs')
        const init = n.init;
        if (init?.type === "CallExpression" && isRequire(init.callee)) {
          const spec = literal(init.arguments[0]);
          if (spec !== undefined && FS_MODULES.has(builtin(spec))) {
            if (n.id.type === "Identifier") fsNames.add(n.id.name);
            if (n.id.type === "ObjectPattern") {
              for (const prop of n.id.properties) {
                const k = prop.key?.name ?? literal(prop.key);
                if (k && FS_WRITES.has(k))
                  note(profile, "fs-write", { file, line: line(n), detail: `takes ${k} from '${spec}'` });
              }
            }
          }
        }
        break;
      }
      case "MemberExpression": {
        // process.env, process["env"], and process[<computed>], which could be env.
        if (n.object.type === "Identifier" && processNames.has(n.object.name)) {
          const prop = n.computed ? literal(n.property) : n.property?.name;
          const via = n.object.name === "process" ? "process" : `process (as '${n.object.name}')`;
          if (prop === "env") note(profile, "env", { file, line: line(n), detail: `reads ${via}.env` });
          else if (prop === undefined)
            note(profile, "env", { file, line: line(n), detail: `reads a computed property of ${via}` });
        }
        break;
      }
    }
  });

  for (const call of fsWriteCalls) {
    const c = call as any;
    const obj = c.callee.object;
    // fs.writeFileSync(...), fs.promises.writeFile(...), require('fs').writeFileSync(...)
    const base = obj.type === "MemberExpression" ? obj.object : obj;
    const viaRequire =
      base.type === "CallExpression" &&
      isRequire(base.callee) &&
      FS_MODULES.has(builtin(literal(base.arguments[0]) ?? ""));
    if ((base.type === "Identifier" && fsNames.has(base.name)) || viaRequire) {
      const prop = c.callee.computed ? literal(c.callee.property) : c.callee.property.name;
      note(profile, "fs-write", { file, line: line(call), detail: `calls fs ${prop}()` });
      break;
    }
  }
  return profile;
}

/** Analyse an unpacked package directory (the one holding package.json). */
export function analyzePackage(dir: string): { profile: Profile; dependencies: string[] } {
  const profile: Profile = {};
  const pkgPath = join(dir, "package.json");
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch (e) {
    throw new Error(`${pkgPath}: cannot read package.json (${(e as Error).message})`);
  }
  const scripts = (manifest["scripts"] ?? {}) as Record<string, unknown>;
  for (const s of INSTALL_SCRIPTS) {
    if (typeof scripts[s] === "string") {
      note(profile, "install-script", { file: "package.json", line: 0, detail: `${s}: ${scripts[s]}` });
    }
  }
  const all = files(dir);
  const rel = (f: string) => relative(dir, f).split(sep).join("/");
  if (manifest["gypfile"] === true || all.some((f) => rel(f) === "binding.gyp")) {
    note(profile, "native-build", {
      file: "binding.gyp",
      line: 0,
      detail: "node-gyp builds native code on install",
    });
    // npm runs `node-gyp rebuild` as the install script when binding.gyp exists and none is given.
    note(profile, "install-script", {
      file: "binding.gyp",
      line: 0,
      detail: "implicit install: node-gyp rebuild",
    });
  }
  for (const f of all) {
    const r = rel(f);
    if (r.startsWith("node_modules/")) continue; // bundled deps are listed in the lockfile on their own
    const size = statSync(f).size;
    if (JS.test(r)) {
      if (size > MAX_JS_BYTES) {
        note(profile, "unanalyzable", {
          file: r,
          line: 0,
          detail: `${size} bytes, over the ${MAX_JS_BYTES}-byte limit`,
        });
        continue;
      }
      analyzeSource(readFileSync(f, "utf8"), r, profile);
      continue;
    }
    if (r.endsWith(".node")) {
      note(profile, "binary", { file: r, line: 0, detail: "native addon (.node)" });
      continue;
    }
    const kind = isBinary(head(f));
    if (kind) note(profile, "binary", { file: r, line: 0, detail: `${kind} executable` });
  }
  const deps = Object.keys((manifest["dependencies"] ?? {}) as object).sort();
  return { profile, dependencies: deps };
}

export function capabilitiesOf(p: Profile): Capability[] {
  return CAPABILITIES.filter((c) => p[c] !== undefined);
}
