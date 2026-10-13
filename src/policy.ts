// permit.json: which packages may have which capabilities.
//
//   {
//     "allow": {
//       "esbuild": ["install-script", "binary"],
//       "*": ["fs-write"]
//     }
//   }
//
// "*" applies to every package. Anything not allowed is reported and blocks.
// Unknown keys and unknown capability names are errors: a typo in a policy
// must not silently allow nothing, or everything.

import { CAPABILITIES, type Capability } from "./analyze.js";

export interface Policy {
  allow: Map<string, Set<Capability>>;
}

export class PolicyError extends Error {}

export const EMPTY_POLICY: Policy = { allow: new Map() };

export function parsePolicy(text: string, source = "permit.json"): Policy {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new PolicyError(`${source}: not JSON (${(e as Error).message})`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc))
    throw new PolicyError(`${source}: not a JSON object`);
  for (const k of Object.keys(doc)) {
    if (k !== "allow" && k !== "$comment")
      throw new PolicyError(`${source}: unknown key '${k}' (expected "allow")`);
  }
  const allowRaw = (doc as Record<string, unknown>)["allow"] ?? {};
  if (typeof allowRaw !== "object" || allowRaw === null || Array.isArray(allowRaw)) {
    throw new PolicyError(`${source}: "allow" must be an object of package name -> capability list`);
  }
  const allow = new Map<string, Set<Capability>>();
  for (const [name, caps] of Object.entries(allowRaw)) {
    if (!Array.isArray(caps))
      throw new PolicyError(`${source}: allow["${name}"] must be a list of capabilities`);
    const set = new Set<Capability>();
    for (const c of caps) {
      if (!(CAPABILITIES as readonly unknown[]).includes(c)) {
        throw new PolicyError(
          `${source}: allow["${name}"]: unknown capability ${JSON.stringify(c)} (known: ${CAPABILITIES.join(", ")})`,
        );
      }
      set.add(c as Capability);
    }
    allow.set(name, set);
  }
  return { allow };
}

export function allowed(policy: Policy, name: string, cap: Capability): boolean {
  return policy.allow.get(name)?.has(cap) === true || policy.allow.get("*")?.has(cap) === true;
}
