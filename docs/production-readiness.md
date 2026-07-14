# @orkestrel/sea — Production Readiness

Status and roadmap for taking this package from "green and hardened" to
"enterprise-grade / production-ready." Written after the conversion +
P0/P1 hardening passes. This file is documentation only; it is not
published to npm (`package.json` `files` ships `dist` + `README.md`).

## What this package is

A programmatic builder for Node.js Single Executable Applications (SEA):
it brotli-compresses asset directories, generates the SEA prep blob, and
injects that blob into PE (Windows), ELF (Linux), and Mach-O (macOS)
binaries with its own pure-TypeScript injector (no `postject`, no WASM,
4 MB chunked streaming so there is no file-size ceiling). It patches the
Windows PE subsystem to `gui` to hide the console, patches the SEA
sentinel fuse, strips/re-signs signatures, and ships an `AssetManager`
for loading embedded assets at runtime via `node:sea`.

## Confirmed capabilities (verified in source)

- **Hide the terminal** — Windows GUI-subsystem patch (`windows.subsystem: 'gui'`). Present.
- **Bundle larger files** — 4 MB chunked streaming injection, no in-memory size ceiling. Present.
- **Open / close the browser** — **NOT present in this codebase.** This capability existed only
  in stale test scaffolding inherited from an older monorepo; there is no browser-control feature
  in `SEA`/`Injector`/`Asset`/`AssetManager`. If it is wanted, it is net-new work (and arguably
  belongs in the consuming application, not a build tool). See "Open questions."

## Done in the hardening pass (P0/P1)

| Area | What shipped |
| --- | --- |
| Sign-after-inject ordering | `#assemble` builds into a temp file; signing is the final content mutation on every platform; Windows subsystem patch moved before injection; verify is read-only |
| Atomic, non-destructive output | same-dir temp + fsync + atomic rename (`finalizeExecutable`); any failure removes the temp and leaves a pre-existing output byte-intact |
| No swallowed errors | empty strip/sign catches removed; failures surface as coded `SEAError`; `SEAResult.signed/stripped/subsystem` reflect only real outcomes |
| Input validation | real-path (`realpathSync`) root containment for asset + compression paths (`ensureContained`) defeats symlink escape; drive-relative keys rejected; output `name` guarded |
| Error taxonomy | `SEAError` + `SEAErrorCode` + `isSEAError`; `ShellError extends SEAError`; every throw carries a code + context |
| Cancellation + timeout | `SEAOptions.signal`, `SEAShellOptions.timeout`/`signal`, enforced in `runShell` and checked across the pipeline |
| Entry format | `entry: { path, format? }`; `mainFormat: 'module'` emitted for `esm`, with the `useSnapshot` incompatibility guarded |
| Signature verification | `codesign --verify --strict` after signing on macOS, reflected in `signed` |
| Ops | CI matrix (ubuntu/windows/macos + macos-14 arm64, Node 24/26) + a job that builds a real SEA and executes it; `SECURITY.md`; `CHANGELOG.md` |

## Roadmap (not yet done)

### P1 — publishing/supply-chain hardening
- **npm provenance / OIDC trusted publishing.** Add `publish.yml` with `permissions: id-token: write`
  and `npm publish --provenance`. Currently documented as a follow-up in `SECURITY.md`, not implemented.
- **API report gate.** `@microsoft/api-extractor` is already a devDependency; wire an `api.md`
  report + a check so public-surface changes are reviewed. (Pre-1.0 the surface is still moving.)

### P2 — differentiators
- **Reproducible builds.** Parameterize/drop the `new Date().toISOString()` in the compression
  manifest so output is byte-stable given fixed inputs; document that the host `node` binary and the
  V8 code cache remain reproducibility-breaking inputs.
- **PE checksum recompute.** The PE `OptionalHeader.CheckSum` is not recomputed after section
  append; some loaders/AV distrust a stale checksum. Zero or recompute it.
- **Progress / logging hooks** beyond the coarse `compress`/`blob`/`assemble` events.
- **Compatibility + troubleshooting docs.** Per-OS/arch/Node support table; AV/EDR false-positive
  guidance (Node SEA clones are increasingly flagged); migration notes from `postject`/`pkg`/`bun
  compile`; an "embedded local-UI" example using `AssetManager`'s `client.html` conventions.

### Residuals from the security review (accepted for now)
- **Point-of-use TOCTOU.** Containment is enforced at `#validate` time via real paths; a symlink
  swapped between validate and use is not re-checked. Acceptable for a local build tool operating on
  the invoker's own inputs; close it by re-checking `ensureContained` at the point of use if this is
  ever run against untrusted trees.
- **Parent-directory fsync.** `finalizeExecutable` fsyncs the file but not the containing directory,
  so a crash immediately post-rename could lose the directory entry. Deliberately not added this pass
  (it would require a tolerant/empty catch, conflicting with the no-swallow rule). Low severity.
- **Windows Authenticode signing.** There is no Windows signing step (`signed` is `false` on Windows);
  the produced `.exe` is intentionally unsigned. Documented in `SECURITY.md` as the consumer's
  responsibility. Add a `sign` command override in `SEAOptions` if a first-class Windows signing story
  is wanted.

## Platform reality (must inform users)

- **ESM entry requires a Node ≥ 25.7 build host.** The `mainFormat` SEA-config field does not exist
  in Node 24 (the package's floor); `esm` builds must run `--experimental-sea-config` on Node ≥ 25.7.
  `mainFormat: 'module'` is incompatible with `useSnapshot`, and `import()` of filesystem modules is
  unsupported under ESM SEA. CommonJS remains the safe default.
- **No cross-compilation.** The build uses the host `process.execPath`/`process.platform`; you must
  build on and for each OS/arch. The code-cache blob is V8/Node-version-coupled, so blobs are not
  portable across Node versions.
- **The injector's correctness is unproven until CI runs it.** The ELF `PT_NOTE` and Mach-O
  `NODE_SEA` layouts can only be confirmed by building a SEA and executing it on each real OS/Node
  line — that is exactly what the new CI `sea` job does. It has not run here (this environment is
  Node 22, single-OS); treat the first green CI matrix run as the real acceptance gate.
- **Positioning vs Node's own tooling.** Node 25.5 added `--build-sea` (in-tree blob+inject). This
  package's differentiators are the `postject`-free streaming injector (no size ceiling), the
  programmatic surface, brotli asset compression, and the terminal-hiding/fuse patches — worth
  stating explicitly in the README against the built-in flow.

## Sibling @orkestrel packages — verdict

- **@orkestrel/emitter, @orkestrel/contract** — already dependencies; keep. Emitter provides the typed
  `SEAEventMap`/`AssetManagerEventMap` progress events; contract's guards back the validation helpers.
- **worker** — no. A single build is one blob-gen + sequential binary IO; real parallelism is across
  OSes (the CI matrix), not within a build. Would be dependency bloat.
- **server / router / websocket** — docs/examples only, never dependencies. Serving a UI from embedded
  assets is the end-user application's concern; making an HTTP stack a dependency of a build tool
  inverts the relationship. Reference them in an "embedded local-UI" example that consumes
  `AssetManager`.
- **timeout / abort** — optional. Native `AbortSignal` + `execFileSync`'s `timeout` already cover the
  cancellation/timeout needs; adopt a sibling only if it is zero-dependency and strictly more ergonomic.

## Open questions for the maintainer

1. **Browser open/close** — do you want this added (net-new feature), or was it a mis-remembered
   capability? It is not in the current code.
2. **Windows signing** — first-class support (a `sign` override), or keep it consumer-owned?
3. **ESM floor** — raise `engines.node` to `>= 25.7` for a first-class ESM story, or keep `>= 24`
   with ESM as best-effort?
