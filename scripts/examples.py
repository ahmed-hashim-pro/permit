#!/usr/bin/env python3
"""Writes the example lockfiles in examples/. Run from the repo root:  python3 scripts/examples.py

They are package-lock.json v3 files for a small app, before and after an
upgrade, pointing at the synthetic packages in fixtures/packages/. The
package names are made up and not on npm, so the examples run with
--fixtures fixtures/packages and never touch the network.
"""
import json, os

def lock(app, pkgs):
    deps = {name: "^" + ver for name, ver, _ in pkgs if _ is not None}
    out = {"name": app, "version": "1.0.0", "lockfileVersion": 3, "requires": True,
           "packages": {"": {"name": app, "version": "1.0.0", "dependencies": deps}}}
    for name, ver, pdeps in pkgs:
        base = name.split("/")[-1]
        entry = {"version": ver, "resolved": f"https://registry.npmjs.org/{name}/-/{base}-{ver}.tgz", "license": "MIT"}
        if pdeps:
            entry["dependencies"] = pdeps
        out["packages"][f"node_modules/{name}"] = entry
    return json.dumps(out, indent=2) + "\n"

def write(scenario, before, after, policy=None):
    d = os.path.join("examples", scenario)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "before.json"), "w").write(lock(scenario, before))
    open(os.path.join(d, "after.json"), "w").write(lock(scenario, after))
    if policy is not None:
        open(os.path.join(d, "permit.json"), "w").write(json.dumps(policy, indent=2) + "\n")

# A direct dependency (None marks a transitive one, not in the app's own deps).
write("event-stream",
      [("stream-pipe", "3.3.5", {"through-lite": "^2.3.1"}), ("through-lite", "2.3.8", None)],
      [("stream-pipe", "3.3.6", {"through-lite": "^2.3.1", "flatmap-lite": "^0.1.0"}),
       ("through-lite", "2.3.8", None), ("flatmap-lite", "0.1.1", None)])
write("ua-sniff", [("ua-sniff", "0.7.28", {})], [("ua-sniff", "0.7.29", {})])
write("monday",
      [("left-padder", "1.2.0", {}), ("fast-bundler", "0.20.2", {}), ("@acme/logger", "2.0.0", {})],
      [("left-padder", "1.3.0", {}), ("fast-bundler", "0.21.0", {}), ("@acme/logger", "2.1.0", {})],
      {"$comment": "fast-bundler ships a native binary and checks it on install, like esbuild.",
       "allow": {"fast-bundler": ["install-script", "binary"]}})
