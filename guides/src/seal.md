# Seal — Single Executable Application Builder

> Node.js SEA builder — compress, blob, assemble, sign, and embed assets into a standalone binary.

**Package:** `@scsr/server`
**Location:** `src/server/seal/` (with `seals/`, `injectors/`, `assets/` subfolders)
**Types:** `src/server/types.ts`
**Factories:** `src/server/factories.ts`

---

## Overview

The seal feature builds standalone executables from Node.js applications using the [Single Executable Application (SEA)](https://nodejs.org/api/single-executable-applications.html) API. It lives on the `@scsr/server` surface and handles asset compression, blob generation, binary assembly, code signing, PE subsystem patching, and embedded asset management.

All types, helpers, constants, and factories follow the centralized file convention — they live in `src/server/types.ts`, `src/server/helpers.ts`, `src/server/constants.ts`, and `src/server/factories.ts` respectively. Only the implementation classes live under `src/server/seal/`.

---

## Architecture

```
src/server/seal/
├── seals/
│   └── Seal.ts             # Build orchestrator — compress, blob, assemble
├── injectors/
│   └── Injector.ts         # Cross-platform binary resource injector
└── assets/
    ├── Asset.ts            # Single named asset (key, content, compression flag)
    └── AssetManager.ts     # Collection manager for SEA-embedded and disk-loaded assets
```

---

## Seal

Build orchestrator. Executes a three-step pipeline:

1. **Compress** — Brotli-compress directories listed in `options.compression.paths`
2. **Blob** — Write `sea-config.json`, run `node --experimental-sea-config`, verify blob
3. **Assemble** — Copy node binary, strip signature, inject blob via `Injector`, re-sign (macOS), patch PE (Windows)

```ts
import { formatSize } from '@scsr/core'
import { createSeal } from '@scsr/server'

const seal = createSeal({
	name: 'myapp',
	entry: 'dist/server/serve.cjs',
	output: 'dist/seal',
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

const result = await seal.execute()
process.stdout.write(
	`${result.executable} ${formatSize(result.size)} ${String(result.duration)}ms\n`,
)
```

### Seal Events

Seal owns an `Emitter<SealEventMap>` and exposes it via `seal.emitter`.

| Event      | Arguments                              | When                           |
| ---------- | -------------------------------------- | ------------------------------ |
| `compress` | `compression: SealCompressionManifest` | Compression step completes     |
| `blob`     | `blob: string`                         | Blob generation step completes |
| `assemble` | `executable: string`                   | Assembly step completes        |
| `complete` | `result: SealResult`                   | Full build pipeline completes  |
| `error`    | `error: unknown`                       | Build pipeline fails           |

### Seal Lifecycle

```
idle → active → done
idle → active → error
```

- `execute()` — run the full pipeline, transitions `idle → active → done` (or `error`)
- `destroy()` — tear down emitter and release resources

---

## Injector

Cross-platform binary resource injector. Detects the executable format from file header magic bytes and injects a resource using pure TypeScript file I/O. Handles blobs of any size — no WASM memory ceiling.

| Format     | Strategy                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------- |
| **PE**     | Parses existing resource directory, rebuilds with new RT_RCDATA entry, appends as `.rsrc2` section |
| **ELF**    | Appends a PT_NOTE segment with the blob as note data                                               |
| **Mach-O** | Appends an LC_SEGMENT_64 load command with a section containing the blob                           |

The blob data is streamed from disk in 4 MB chunks — never held in memory.

```ts
import { createInjector } from '@scsr/server'

const injector = createInjector({
	executable: 'dist/seal/myapp.exe',
	resource: 'NODE_SEA_BLOB',
	blob: 'dist/seal/sea-prep.blob',
	fuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
	macho: { segment: 'NODE_SEA' },
})

console.log(injector.format) // 'pe' | 'elf' | 'macho'
injector.inject()
```

---

## Asset

A single named asset wrapping its key, content buffer, and compression flag. Infers compression from the `.br` extension when not explicitly provided.

```ts
import { createAsset } from '@scsr/server'

const asset = createAsset({
	key: 'client.html.br',
	content: compressedBuffer,
})

asset.key // 'client.html.br'
asset.compressed // true (inferred from .br extension)
asset.content // ArrayBuffer
```

---

## AssetManager

Manages named assets embedded in the SEA blob or loaded from disk. In SEA mode, assets are auto-loaded via `node:sea` APIs on construction. Outside SEA, assets are loaded via `load()` or registered manually.

AssetManager owns an `Emitter<AssetManagerEventMap>` and exposes it via `manager.emitter`.

```ts
import { createAssetManager } from '@scsr/server'

const manager = createAssetManager({ root: process.cwd() })

// Manual registration
manager.register({ key: 'data.json', content: buffer })

// Disk loading (looks for client assets in client/ or dist/client/)
manager.load()

// Lookup
const asset = manager.asset('client.html.br')
const all = manager.assets()
const keys = manager.keys()

// Events
manager.emitter.on('register', (asset) => console.log('registered', asset.key))
manager.emitter.on('load', (keys) => console.log('loaded', keys))
manager.emitter.on('error', (error) => console.error(error))

manager.destroy()
```

### AssetManager Events

| Event      | Arguments                 | When                    |
| ---------- | ------------------------- | ----------------------- |
| `register` | `asset: AssetInterface`   | An asset is registered  |
| `load`     | `keys: readonly string[]` | Assets loaded from disk |
| `clear`    | (none)                    | All assets cleared      |
| `error`    | `error: unknown`          | Asset loading fails     |

### SEA Mode

When running inside a Single Executable Application, `AssetManager` automatically loads all embedded assets via `node:sea.getAssetKeys()` and `node:sea.getRawAsset()` during construction. The `load()` method becomes a no-op in this mode.

### Disk Mode

Outside SEA, `load()` searches for client assets in two locations:

1. `{root}/client/client.html` — raw development asset
2. `{root}/dist/client/client.html.br` — Brotli-compressed production asset

The first match wins. If neither exists, an `error` event is emitted.

---

## Types Reference

| Type                      | Kind      | Purpose                                                |
| ------------------------- | --------- | ------------------------------------------------------ |
| `SealInterface`           | Interface | Build orchestrator contract                            |
| `SealOptions`             | Options   | Build configuration                                    |
| `SealResult`              | Result    | Build outcome                                          |
| `SealEventMap`            | Event map | `compress`, `blob`, `assemble`, `complete`, `error`    |
| `SealStep`                | Union     | `'compress' \| 'blob' \| 'assemble'`                   |
| `SealStatus`              | Union     | `'idle' \| 'active' \| 'done' \| 'error'`              |
| `SealCompressionResult`   | Result    | Single file compression outcome                        |
| `SealCompressionManifest` | Data      | All compressed assets summary                          |
| `SealCompressionOptions`  | Options   | Brotli quality and mode                                |
| `SealCompressionInput`    | Input     | Compression paths plus Brotli options                  |
| `SealCompressionSize`     | Data      | Original vs compressed bytes                           |
| `SealCompressionMode`     | Union     | `'generic' \| 'text' \| 'font'`                        |
| `SealPlatform`            | Data      | Platform-specific build config                         |
| `SealMachoOptions`        | Options   | Mach-O segment configuration                           |
| `SealWindowsOptions`      | Options   | Windows subsystem configuration                        |
| `SealShellOptions`        | Options   | Shell command execution config                         |
| `WindowsSubsystem`        | Union     | `'console' \| 'gui'`                                   |
| `ExecutableFormat`        | Union     | `'pe' \| 'elf' \| 'macho'`                             |
| `InjectorInterface`       | Interface | Binary resource injector contract                      |
| `InjectorOptions`         | Options   | Injection configuration                                |
| `AssetInterface`          | Interface | Single named asset contract                            |
| `AssetInput`              | Input     | Minimal data needed to create an asset                 |
| `AssetManagerInterface`   | Interface | Collection manager for assets (has `emitter` property) |
| `AssetManagerOptions`     | Options   | Asset manager configuration (root, emitter)            |
| `AssetManagerEventMap`    | Event map | `register`, `load`, `clear`, `error`                   |

---

## Helpers

| Function                                  | Purpose                             |
| ----------------------------------------- | ----------------------------------- |
| `platformConfig(platform?)`               | Get platform SEA configuration      |
| `isPlatformSupported(platform?)`          | Check if platform supports SEA      |
| `ensureExists(path, message)`             | Assert path exists or throw         |
| `walkDirectory(dir, baseDir?)`            | Recursively list files              |
| `isCompressible(filePath)`                | Check if file benefits from Brotli  |
| `compressFile(input, output, options?)`   | Brotli-compress a single file       |
| `compressDirectory(dirPath, options?)`    | Compress all files in a directory   |
| `computeSize(original, compressed)`       | Compute size ratio                  |
| `formatSize(bytes)` _(from `@scsr/core`)_ | Human-readable byte string          |
| `runShell(command, options?)`             | Execute shell command synchronously |
| `splitLines(buffer)`                      | Split buffer into trimmed lines     |
| `isPeExecutable(path)`                    | Check for PE signature              |
| `patchPeSubsystem(path, subsystem)`       | Patch Windows subsystem field       |
| `stripPeSignature(path)`                  | Remove Authenticode signature       |
| `patchSentinelFuse(exe, fuse)`            | Patch SEA sentinel fuse `:0` → `:1` |

### Type Guards

| Guard                       | Narrows to            |
| --------------------------- | --------------------- |
| `isExecutableFormat(value)` | `ExecutableFormat`    |
| `isSealCompressionMode`     | `SealCompressionMode` |
| `isSealStatus`              | `SealStatus`          |
| `isSealStep`                | `SealStep`            |
| `isWindowsSubsystem`        | `WindowsSubsystem`    |
| `isSealCompressionSize`     | `SealCompressionSize` |

---

## Constants

| Constant                           | Value                          | Purpose                     |
| ---------------------------------- | ------------------------------ | --------------------------- |
| `SEA_SENTINEL_FUSE`                | `NODE_SEA_FUSE_...`            | SEA sentinel fuse value     |
| `SEA_BLOB_RESOURCE`                | `NODE_SEA_BLOB`                | Blob resource name          |
| `DEFAULT_SEAL_COMPRESSION_QUALITY` | `11`                           | Max Brotli quality          |
| `SEAL_BROTLI_EXTENSION`            | `".br"`                        | Compressed file extension   |
| `SEAL_COMPRESSION_MODE_VALUES`     | `Record<mode, number>`         | Brotli mode constants       |
| `SEAL_PLATFORMS`                   | `Record<string, SealPlatform>` | Per-platform configs        |
| `WINDOWS_SUBSYSTEM_CONSOLE`        | `3`                            | Console app subsystem       |
| `WINDOWS_SUBSYSTEM_GUI`            | `2`                            | GUI app subsystem           |
| `PE_MAGIC`                         | `0x5A4D`                       | DOS MZ header magic         |
| `PE_SIGNATURE`                     | `0x00004550`                   | PE signature                |
| `PE32_MAGIC`                       | `0x10B`                        | PE32 optional header magic  |
| `PE32_PLUS_MAGIC`                  | `0x20B`                        | PE32+ optional header magic |
| `ELF_MAGIC`                        | `0x7F454C46`                   | ELF magic bytes             |
| `ELF_CLASS_64`                     | `2`                            | ELF 64-bit class            |
| `ELF_DATA_LSB`                     | `1`                            | ELF little-endian           |
| `ELF_PT_NOTE`                      | `4`                            | ELF note segment type       |
| `MACHO_MAGIC_64`                   | `0xFEEDFACF`                   | Mach-O 64-bit magic         |
| `MACHO_LC_SEGMENT_64`              | `0x19`                         | Mach-O segment command      |
| `PE_RT_RCDATA`                     | `10`                           | PE resource type: raw data  |
| `PE_RESOURCE_DIR_SIZE`             | `16`                           | IMAGE_RESOURCE_DIRECTORY    |
| `PE_RESOURCE_ENTRY_SIZE`           | `8`                            | IMAGE_RESOURCE_ENTRY        |
| `PE_RESOURCE_DATA_ENTRY_SIZE`      | `16`                           | IMAGE_RESOURCE_DATA_ENTRY   |
| `PE_SECTION_HEADER_SIZE`           | `40`                           | PE section header           |
| `PE_RESOURCE_SUBDIR_FLAG`          | `0x80000000`                   | PE subdirectory flag        |
| `PE_RESOURCE_NAME_FLAG`            | `0x80000000`                   | PE name pointer flag        |
| `PE_SCN_INITIALIZED_DATA`          | `0x00000040`                   | Initialized data section    |
| `PE_SCN_MEM_READ`                  | `0x40000000`                   | Read access section         |
| `BROTLI_EXTENSION`                 | `".br"`                        | Brotli file extension       |
| `CLIENT_ASSET_KEY_RAW`             | `"client.html"`                | Raw client asset key        |
| `CLIENT_ASSET_KEY_BR`              | `"client.html.br"`             | Compressed client key       |

---

## Factories

| Factory                        | Returns                 |
| ------------------------------ | ----------------------- |
| `createSeal(options)`          | `SealInterface`         |
| `createInjector(options)`      | `InjectorInterface`     |
| `createAsset(input)`           | `AssetInterface`        |
| `createAssetManager(options?)` | `AssetManagerInterface` |

---

## Errors

| Class        | Purpose                                           |
| ------------ | ------------------------------------------------- |
| `ShellError` | Shell command failure with captured stdout/stderr |

---

## Build Integration

The seal pipeline produces a standalone executable:

1. Run `npm run build:bin` to build the MCP bin bundle and declarations into `dist/bin`
2. Run `npm run seal` to build `@scsr/server`, rebuild the MCP bin entry, and seal `dist/bin/mcp.cjs` through a single inline `package.json` script
3. Use `createSeal` directly when you need custom automation around the same three-stage pipeline

The workspace now exposes a dedicated MCP seal flow through `package.json`:

```powershell
npm run build:bin
npm run seal
```

### Vite Considerations

Node.js SEA only supports CommonJS entry points. The server Vite config must output a `.cjs` file for the SEA entry. Asset directories listed in `compression.paths` are Brotli-compressed before blob generation.

### Asset Serving in SEA

When a server runs inside an SEA, `AssetManager` loads all embedded assets automatically during construction via `node:sea` APIs. The `Server` owns an `AssetManager` instance exposed via `server.assets`:

```ts
import { createServer } from '@scsr/server'

const server = createServer({
	port: 3000,
	timeout: 5000,
	assets: { root: process.cwd() },
})

// Assets are available via server.assets
server.assets.load() // load from disk in dev mode (no-op in SEA mode)

const asset = server.assets.asset('client.html.br')
if (asset !== undefined) {
	const buffer = Buffer.from(asset.content)
	response.setHeader('Content-Encoding', 'br')
	response.setHeader('Content-Type', 'text/html')
	response.end(buffer)
}
```

The `assets` option on `ServerOptions` is passed through to the `AssetManager` constructor. The `Server` creates the `AssetManager` internally and destroys it during `server.destroy()`.

Outside SEA mode, `load()` reads assets from disk as a fallback for development and pre-built scenarios.

---

## Test Structure

Tests mirror the implementation structure under `tests/src/server/seal/`:

```
tests/src/server/seal/
├── seals/
│   └── Seal.test.ts
├── injectors/
│   └── Injector.test.ts
├── assets/
│   ├── Asset.test.ts
│   └── AssetManager.test.ts
└── integration.test.ts
```

Seal helper tests (compression, platform config, directory walking, etc.) live in the centralized `tests/src/server/helpers.test.ts` under the "Seal Helpers" describe block.

---

## Best Practices

1. **Brotli-compress browser assets** — add `dist/app/browser` to `compression.paths` for maximum static asset compression
2. **Use `seal.execute()` or `npm run seal` in CI** — keep the SEA pipeline explicit and fail the job on any thrown error
3. **Keep `entry` as a CJS bundle** — SEA requires a single CJS entry file; ensure your bundler outputs `.cjs` format
4. **Embed only what is needed** — every embedded asset increases binary size; include only files required at runtime
5. **Sign on macOS after assembly** — Seal runs `codesign` automatically after blob injection; ensure the target has signing configured
6. **Use `AssetManager` at runtime for fallback** — `load()` falls back to disk reads in development so you can test without a full SEA build
7. **Patch PE subsystem for Windows GUI** — use `windows: { subsystem: 'gui' }` to remove the console window for GUI applications
8. **Verify the blob before assembly** — the build pipeline checks the blob hash before injecting; a corrupt blob will abort the build

Test factories (`createSealOptions`, `createInjectorOptions`) are centralized in `tests/setupServer.ts`.
