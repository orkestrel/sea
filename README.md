# @orkestrel/sea

A pure-TypeScript Node.js [Single Executable Application (SEA)](https://nodejs.org/api/single-executable-applications.html)
builder for the `@orkestrel` line — compress assets, assemble the SEA blob,
and inject it into a standalone binary, entirely in TypeScript with no
external tools.

## Install

```sh
npm install @orkestrel/sea
```

## Quick start

```ts
import { formatSize, createSEA } from '@orkestrel/sea'

const sea = createSEA({
	name: 'myapp',
	entry: { path: 'dist/server/serve.cjs' },
	output: 'dist/sea',
	assets: { 'model.gguf': 'models/model.gguf' },
	compression: {
		paths: ['dist/app/browser'],
		mode: 'text',
	},
	windows: { terminal: false },
	on: {
		compress: (compression) => {
			if (compression === undefined) return
			process.stdout.write(`compressed ${String(compression.assets.length)} assets\n`)
		},
		blob: (blob) => {
			process.stdout.write(`blob ${blob}\n`)
		},
		assemble: (executable) => {
			process.stdout.write(`assembled ${executable}\n`)
		},
	},
})

const result = await sea.execute()
process.stdout.write(
	`${result.executable} ${formatSize(result.size)} ${String(result.duration)}ms\n`,
)
```

## Features

- **Pure-TypeScript cross-platform injection** — PE (Windows), ELF (Linux),
  and Mach-O (macOS) binary formats, with no external tools (no `postject`,
  no WASM) and no size ceiling: the blob is streamed from disk in 4 MB
  chunks.
- **Brotli asset compression** — directories are compressed before blob
  assembly, with `generic` / `text` / `font` modes.
- **Hide the Windows terminal** — `windows: { terminal: false }` patches the
  PE subsystem field so a GUI application launches without a console window.
- **Runtime asset access** — `AssetManager` loads assets embedded in the SEA
  blob via `node:sea`, or falls back to disk in development.
- **Open the browser** — `openBrowser(url)` is a runtime helper (not a build
  step) for a bundled local-UI app to launch the system default browser at
  its own served address. Best-effort, detached, argv-only dispatch.
- **Typed events** — `SEA` and `AssetManager` each own an `Emitter` from
  [`@orkestrel/emitter`](https://github.com/orkestrel/emitter), exposed as
  `readonly emitter`.

## Code signing

- **macOS** — the injector re-signs the output automatically with an ad-hoc
  identity (`codesign --sign -`) and verifies the signature
  (`codesign --verify --strict`) as the final build step. An ad-hoc signature
  satisfies local Gatekeeper checks but is not a trusted, distributable
  signature — re-sign with a real Apple Developer ID for distribution.
- **Windows** — signing is **optional**, via `windows.sign`. Provide exactly
  one of `file` (a `.pfx` path + `password`) or `thumbprint` (a cert-store
  SHA1 hash), plus an optional RFC 3161 `timestamp` URL and `digest`
  (defaults to `sha256`):

  ```ts
  // Certificate store, by thumbprint
  windows: {
  	sign: {
  		thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD',
  		timestamp: 'http://timestamp.digicert.com',
  	},
  }

  // PFX file on disk
  windows: {
  	sign: {
  		file: 'certs/signing.pfx',
  		password: process.env.SIGNING_PASSWORD,
  		timestamp: 'http://timestamp.digicert.com',
  	},
  }
  ```

  Without `windows.sign` the produced `.exe` is intentionally left unsigned —
  it still runs, but Windows SmartScreen will warn on first launch. Signing
  requires `signtool` (from the Windows SDK) to be on `PATH`.

## Compatibility

- **Node.js >= 24** is required; the package is a single Node-native
  server-only surface (no CommonJS/browser split).
- **ESM entry requires a Node ≥ 25.7 build host.** `entry: { format: 'esm' }`
  emits `mainFormat: 'module'`, a SEA-config field that only exists starting
  Node 25.7; it is incompatible with `useSnapshot`. CommonJS (the default) is
  the safe choice on Node 24.
- **No cross-compilation.** The build uses the host `process.execPath` /
  `process.platform` — you must build on and for each target OS/arch. Blobs
  are Node-version-coupled, so they are not portable across Node versions.
- **The CI matrix is the real acceptance gate.** A build-only pass proves
  nothing about injector correctness on a given OS/arch — the project's CI
  runs a matrix (ubuntu / windows / macos, including arm64, on Node 24 and 26)
  that builds a real SEA **and executes it** on every combination.
- **Byte reproducibility.** Output is reproducible for an identical Node
  binary + identical inputs; the embedded V8 code cache is host-coupled, so
  set `blob: { cache: false }` to drop it if you need byte-identical output
  across hosts.

## Migrating from postject / pkg / `--build-sea`

If you're coming from a manual `postject` injection script, `pkg`, or Node's
built-in `--build-sea`, this package's edge is: a `postject`-free streaming
injector with no file size ceiling, a fully programmatic surface (`createSEA`,
typed events, `Result`-style errors), brotli asset compression, and the
terminal-hiding (`windows.terminal`) and SEA-sentinel-fuse patches that none
of those flows provide out of the box.

## Troubleshooting

- **Antivirus / EDR flags the output binary.** SEA works by cloning the Node
  binary broadly and injecting a blob — this pattern resembles what some
  AV/EDR heuristics flag for modified executables. Code-sign the output (see
  Code signing above) and, if needed, submit it to your vendor's allowlist.
- **Windows SmartScreen warns on first launch.** The `.exe` is unsigned —
  sign it via `windows.sign` (see Code signing above) to avoid the warning.
- **macOS Gatekeeper blocks the app.** Gatekeeper requires a valid signature;
  the automatic ad-hoc signature (`codesign --sign -`) satisfies local
  Gatekeeper checks so it runs on the machine that built it, but for
  distribution to other Macs, re-sign with a real Apple Developer ID.
- **`signtool` / `codesign` not found.** These come from the platform SDK
  (Windows SDK for `signtool`, Xcode Command Line Tools for `codesign`) —
  install the SDK and ensure the tool is on `PATH`.

## Example: embedded local UI

A SEA whose entry starts a local server, serves a bundled `client.html` via
`AssetManager`, and opens the system browser once ready:

```ts
import { createSEA } from '@orkestrel/sea'

const sea = createSEA({
	name: 'myapp',
	entry: { path: 'dist/server/serve.cjs' },
	output: 'dist/sea',
	assets: { 'client.html': 'dist/app/client.html' },
	on: {
		progress: (p) => {
			process.stdout.write(`${p.path} ${String(p.current)}/${String(p.total)}\n`)
		},
	},
})

await sea.execute()
```

```ts
// dist/server/serve.cjs (the SEA entry point)
import { createServer } from 'node:http'
import { AssetManager, openBrowser } from '@orkestrel/sea'

const assets = new AssetManager()
const server = createServer((_req, res) => {
	const asset = assets.asset('client.html')
	if (asset) res.end(Buffer.from(asset.content))
})

server.listen(0, () => {
	const address = server.address()
	const port = typeof address === 'object' && address !== null ? address.port : 0
	void openBrowser(`http://localhost:${String(port)}`)
})
```

## Status

Pre-release. The public API documented in
[`guides/src/sea.md`](https://github.com/orkestrel/sea/blob/main/guides/src/sea.md)
is implemented and covered by tests, but the package has not yet reached a
stable `1.0` release.

## Package

Published as a single Node-only surface per the `exports` field in
`package.json` — one `.` entry backed by a CommonJS build of `src/server`
(required by Node's CJS-only SEA entry-point shape).

## Guides

- [`guides/README.md`](guides/README.md) — the guides index.
- [`guides/src/sea.md`](guides/src/sea.md) — the `SEA` / `Injector` /
  `Asset` / `AssetManager` surface.

## License

MIT © [Orkestrel](https://github.com/orkestrel) — see [LICENSE](./LICENSE).
