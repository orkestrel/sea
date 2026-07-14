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
	entry: 'dist/server/serve.cjs',
	output: 'dist/sea',
	assets: { 'model.gguf': 'models/model.gguf' },
	compression: {
		paths: ['dist/app/browser'],
		mode: 'text',
	},
	windows: { subsystem: 'gui' },
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
  and Mach-O (macOS) binary formats, with no external tools and no size
  ceiling: the blob is streamed from disk in 4 MB chunks.
- **Brotli asset compression** — directories are compressed before blob
  assembly, with `generic` / `text` / `font` modes.
- **Hide the Windows terminal** — `windows: { subsystem: 'gui' }` patches the
  PE subsystem field so a GUI application launches without a console window.
- **Runtime asset access** — `AssetManager` loads assets embedded in the SEA
  blob via `node:sea`, or falls back to disk in development.
- **Typed events** — `SEA` and `AssetManager` each own an `Emitter` from
  [`@orkestrel/emitter`](https://github.com/orkestrel/emitter), exposed as
  `readonly emitter`.

## Requirements

- Node.js >= 24
- Server-only — no CommonJS/browser split, single Node-native surface

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
