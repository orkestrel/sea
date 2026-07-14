# seal

> Node.js Single Executable Application builder — zero dependencies, types-first.

## Overview

The `seal` package builds standalone executables from Node.js applications using the [Single Executable Application (SEA)](https://nodejs.org/api/single-executable-applications.html) API. It handles asset compression, blob generation, binary assembly, code signing, and PE subsystem patching.

Includes a built-in cross-platform binary resource injector (`Injector`) that uses pure TypeScript file I/O — no WASM, no external tools, no size ceiling.

## Entities

### Seal

Build orchestrator. Executes a three-step pipeline:

1. **Compress** — Brotli-compress directories listed in `options.compress`
2. **Blob** — Write `sea-config.json`, run `node --experimental-sea-config`, verify blob
3. **Assemble** — Copy node binary, strip signature, inject blob via `Injector`, re-sign (macOS), patch PE (Windows)

```ts
import { createSeal } from '@orkestrel/seal'
import { createReporter } from '@orkestrel/core'

const seal = createSeal({
	name: 'orkestrel',
	entry: 'dist/bin/serve.cjs',
	output: 'dist/sea',
	assets: { 'qwen3-vl-2b-instruct.gguf': 'models/qwen3-vl-2b-instruct.gguf' },
	compress: ['dist/client'],
	subsystem: 'gui',
	reporter: createReporter(),
})

const result = await seal.execute()
// result.executable — absolute path to the output binary
// result.size       — file size in bytes
// result.duration   — build time in ms
```

### Injector

Cross-platform binary resource injector. Detects the executable format from file header magic bytes and injects a resource using pure TypeScript file I/O. Handles blobs of any size — no WASM memory ceiling.

| Format     | Strategy                                                                                           |
| ---------- | -------------------------------------------------------------------------------------------------- |
| **PE**     | Parses existing resource directory, rebuilds with new RT_RCDATA entry, appends as `.rsrc2` section |
| **ELF**    | Appends a PT_NOTE segment with the blob as note data                                               |
| **Mach-O** | Appends an LC_SEGMENT_64 load command with a section containing the blob                           |

The blob data is streamed from disk in 4 MB chunks — never held in memory.

```ts
import { createInjector } from '@orkestrel/seal'

const injector = createInjector({
	executablePath: 'dist/bin/myapp.exe',
	resourceName: 'NODE_SEA_BLOB',
	blobPath: 'dist/bin/sea-prep.blob',
	sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
	machoSegmentName: 'NODE_SEA', // macOS only
})

console.log(injector.format) // 'pe' | 'elf' | 'macho'
injector.inject()
```

### Reporter

Structured build output with ANSI colors, spinners, progress bars, and capture/release for buffered output. Now lives in `@orkestrel/core` for cross-package use.

```ts
import { createReporter } from '@orkestrel/core'

const reporter = createReporter({ silent: false, level: 'info' })

reporter.section('Build')
reporter.step(1, 3, 'Compressing assets...')
reporter.success('Done')
reporter.timing('Compression', 1250)
reporter.pair('Size', '12.5 MB')
```

## Types

| Type                  | Kind          | Purpose                                   |
| --------------------- | ------------- | ----------------------------------------- |
| `InjectorInterface`   | Interface     | Binary resource injector contract         |
| `InjectorOptions`     | Options       | Injection configuration                   |
| `ExecutableFormat`    | Union         | `'pe' \| 'elf' \| 'macho'`                |
| `SealInterface`       | Interface     | Build orchestrator contract               |
| `SealOptions`         | Options       | Build configuration                       |
| `SealResult`          | Result        | Build outcome                             |
| `SealStep`            | Union         | `'compress' \| 'blob' \| 'assemble'`      |
| `SealStatus`          | Union         | `'idle' \| 'active' \| 'done' \| 'error'` |
| `SealSubscriptions`   | Subscriptions | `onStep`, `onComplete`, `onError`         |
| `CompressionResult`   | Result        | Single file compression outcome           |
| `CompressionManifest` | Data          | All compressed assets summary             |
| `CompressionOptions`  | Options       | Brotli quality and mode                   |
| `SizeComparison`      | Data          | Original vs compressed bytes              |
| `Platform`            | Data          | Platform-specific build config            |
| `PeSubsystem`         | Union         | `'console' \| 'gui'`                      |
| `ShellOptions`        | Options       | Shell command execution config            |

## Helpers

| Function                                | Purpose                             |
| --------------------------------------- | ----------------------------------- |
| `platformConfig(platform?)`             | Get platform SEA configuration      |
| `isPlatformSupported(platform?)`        | Check if platform supports SEA      |
| `ensureExists(path, message)`           | Assert path exists or throw         |
| `walkDirectory(dir, baseDir?)`          | Recursively list files              |
| `isCompressible(filePath)`              | Check if file benefits from Brotli  |
| `compressFile(input, output, options?)` | Brotli-compress a single file       |
| `compressDirectory(dirPath, options?)`  | Compress all files in a directory   |
| `computeSize(original, compressed)`     | Compute size ratio                  |
| `formatSize(bytes)`                     | Human-readable byte string          |
| `run(command, options?)`                | Execute shell command synchronously |
| `splitLines(buffer)`                    | Split buffer into trimmed lines     |
| `isPeExecutable(path)`                  | Check for PE signature              |
| `patchPeSubsystem(path, subsystem)`     | Patch Windows subsystem field       |
| `stripPeSignature(path)`                | Remove Authenticode signature       |
| `patchSentinelFuse(exe, fuse)`          | Patch SEA sentinel fuse `:0` → `:1` |

## Constants

| Constant                      | Value                      | Purpose                    |
| ----------------------------- | -------------------------- | -------------------------- |
| `SEA_SENTINEL_FUSE`           | `NODE_SEA_FUSE_...`        | SEA sentinel fuse value    |
| `SEA_BLOB_RESOURCE`           | `NODE_SEA_BLOB`            | Blob resource name         |
| `DEFAULT_COMPRESSION_QUALITY` | `11`                       | Max Brotli quality         |
| `PE_SUBSYSTEM_CONSOLE`        | `3`                        | Console app subsystem      |
| `PE_SUBSYSTEM_WINDOWS`        | `2`                        | GUI app subsystem          |
| `BROTLI_EXTENSION`            | `".br"`                    | Compressed file extension  |
| `PLATFORMS`                   | `Record<string, Platform>` | Per-platform configs       |
| `PE_MAGIC`                    | `0x5A4D`                   | DOS MZ header magic        |
| `PE_SIGNATURE`                | `0x00004550`               | PE signature               |
| `PE_RT_RCDATA`                | `10`                       | PE resource type: raw data |
| `ELF_MAGIC`                   | `0x7F454C46`               | ELF magic bytes            |
| `ELF_PT_NOTE`                 | `4`                        | ELF note segment type      |
| `MACHO_MAGIC_64`              | `0xFEEDFACF`               | Mach-O 64-bit magic        |
| `MACHO_LC_SEGMENT_64`         | `0x19`                     | Mach-O segment command     |

## Build Integration

The `seal` npm script builds a SEA executable:

```powershell
npm run seal
```

This requires a prior `npm run build` to generate the CJS entry point at `dist/bin/serve.cjs`.

### Vite Configuration

- `vite.server.config.ts` — outputs both ESM (`server.js`) and CJS (`server.cjs`)
- `vite.bin.config.ts` — outputs both ESM (`serve.js`) and CJS (`serve.cjs`)
- `vite.seal.config.ts` — outputs both ESM (`seal.js`) and CJS (`seal.cjs`)

The CJS outputs are required because Node.js SEA only supports CommonJS entry points.
