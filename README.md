# dag-contracts

The canonical component/parameter validation contract for Dagnam.AI — **one
definition, three runtimes that cannot disagree.**

| artifact | registry | consumed by |
|---|---|---|
| `dagnam-contracts` | PyPI | the platform backend, and the `dagnam` SDK |
| `@dagnam/contracts` | npm | the Studio web app |

## Why this repo exists

A neural-network architecture is validated in three places: the backend when a
project is saved, the SDK before a job is submitted, and the Studio as you drag
nodes onto the canvas. All three must reach **identical** verdicts — a parameter
the Studio accepts and the backend rejects is a bug the user experiences as the
product lying to them.

That was previously kept true by generating `component-schema.json` from a
registry in the backend and **copying it into three other trees**, with a script
that diffed the copies to prove they still matched.

Copies are the defect; the guard was a workaround. Three problems followed:

- The guard compared **working trees**, so it could pass while the artifact
  actually published to PyPI had drifted — it verified `../dag-lib/`, not what
  users installed.
- It could not run outside a full multi-repo checkout, so CI (which clones one
  repo) failed on it.
- There was no way to express *"the Studio is one contract version behind."* A
  schema change silently required four repositories to move in lockstep, and
  nothing recorded which contract a given SDK release was built against.

Here the contract is a **dependency**, not a file. Consumers pin a version.
There are no copies left to drift.

## Design

```
        components.py  (Pydantic registry — AUTHORING, never shipped)
               │  generate
               ▼
      component-schema.json          ← the interlingua
         │                │
         ▼                ▼
  dagnam-contracts   @dagnam/contracts
  JSON + Python      JSON + TypeScript
  interpreter        interpreter
```

**The Pydantic registry is an authoring format that compiles to JSON and never
ships.** That single decision is what makes the rest work:

- The published Python package has **no pydantic dependency**, so the `dagnam`
  SDK stays light — a hard constraint, since the SDK deliberately ships with
  only `requests` and `numpy`.
- The JSON is the interlingua. Each runtime interprets it in its own idiom, so
  adding a fourth runtime costs **one interpreter**, not another copy of the
  rules.
- Validation *logic* is single-sourced per language rather than duplicated per
  repository.

Both packages carry the **byte-identical** schema and share a version number:
`dagnam-contracts==1.4.0` and `@dagnam/contracts@1.4.0` describe the same
contract. Breaking changes take a major bump, and each consumer upgrades
deliberately.

## Layout

```
registry/     the Pydantic ComponentSpec registry and the generator (dev-only)
python/       the dagnam-contracts distribution: schema + interpreter
npm/          the @dagnam/contracts distribution: schema + interpreter
```

`registry/` is the **only** place the contract is authored. Editing a component
means editing `registry/components.py` (or a message in
`registry/diagnostics.py`) and recompiling:

```sh
python -m registry.generate          # rewrite both shipped schemas
python -m registry.generate --check  # what CI runs
```

CI runs `--check` on every PR, so a hand-edited `component-schema.json`, a
forgotten recompile, or a Python/TypeScript copy that drifted from its twin all
fail before a release can immortalize them. Conformance across the two
interpreters is checked in the same workflow (`parity-across-languages`).

## Releasing

One tag publishes both packages from one source, so they can never be published
at different versions:

```
git tag contracts/v1.0.0 && git push origin contracts/v1.0.0
```

Publication uses OIDC trusted publishing on both registries — no long-lived
tokens to leak or expire.

## Status

Live. All three consumers — the platform backend, the `dagnam` SDK, and the
Studio — read the contract from these packages; none of them carries a copy of
the schema any more, and none of them authors the registry.

## License

Apache-2.0.
