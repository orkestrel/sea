# Guides

A dual-axis index into this repository's guides — by concept, and by
directory.

## By concept

| Concept | Spec               | Source                        | Tests                                     |
| ------- | ------------------ | ----------------------------- | ----------------------------------------- |
| Sea     | [`sea.md`](sea.md) | [`src/server`](../src/server) | [`tests/src/server`](../tests/src/server) |

## By directory

| Directory    | Guide              |
| ------------ | ------------------ |
| `src/server` | [`sea.md`](sea.md) |

## Dependency reference

[`contract.md`](contract.md) is a byte-identical mirror of the guide for
`@orkestrel/contract` — one of this package's runtime dependencies. It documents
**that package's** surface (guards, combinators, parsers, and the shape DSL), not
anything sourced in this repo; it is kept here so a reader of this package can see
the primitives it is built from without leaving this guide set.

[`emitter.md`](emitter.md) is a byte-identical mirror of the guide for
`@orkestrel/emitter` — one of this package's runtime dependencies, used by `SEA` and
`AssetManager` for typed events. It documents **that package's** surface
(`Emitter`, `createEmitter`, the event-map pattern), not anything sourced in this
repo; it is kept here so a reader of this package can see the primitives it is
built from without leaving this guide set.

[`process.md`](process.md) is a byte-identical mirror of the guide for
`@orkestrel/process` — one of this package's runtime dependencies, used for every
spawned command (`executeSync`) and every detached browser launch (`detach`). It
documents **that package's** surface, not anything sourced in this repo; it is kept
here so a reader of this package can see the primitives it is built from without
leaving this guide set.

[`guide.md`](guide.md) is a byte-identical mirror of the guide for
`@orkestrel/guide` — the devDependency powering this repo's guides-parity test
suite (`tests/guides.test.ts`). It documents **that package's**
surface (`Guide` / `Source`, the manifest and comparison helpers), not anything
sourced in this repo; it is kept here so a reader of the parity suite can see
the primitives it is built from without leaving this guide set.

The folder also carries byte-identical mirrors of the guides for the remaining
development dependencies — [`test.md`](test.md) for `@orkestrel/test`,
[`probe.md`](probe.md) for `@orkestrel/probe`, and
[`scaffold.md`](scaffold.md) for `@orkestrel/scaffold`.

## See also

- [`AGENTS.md`](../AGENTS.md) — the rules this repository is written to.
