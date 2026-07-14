# SEA — Single Executable Application Builder

> Node.js SEA builder — compress, blob, assemble, sign, and embed assets into a standalone binary. Pure TypeScript, no WASM, no external tools. Source: [`src/server`](../../src/server). Surfaced through the `@orkestrel/sea` barrel.

## Overview

```ts
import { createSEA, formatSize } from '@orkestrel/sea'

const sea = createSEA({
	name: 'myapp',
	entry: 'dist/server/serve.cjs',
	output: 'dist/sea',
	assets: { 'model.gguf': 'models/model.gguf' },
	compression: { paths: ['dist/app/browser'], mode: 'text' },
	windows: { subsystem: 'gui' },
})

const result = await sea.execute()
process.stdout.write(
	`${result.executable} ${formatSize(result.size)} ${String(result.duration)}ms\n`,
)
```

`sea.execute()` runs the three-step pipeline — compress assets, generate the blob, assemble and sign the executable — and transitions `sea.status` from `'idle'` to `'active'` to `'done'` (or `'error'`). `sea.emitter` reports progress on `compress`, `blob`, `assemble`, and `complete`.

## Surface

### Entities

| API            | Kind  | Summary                                                                                           |
| -------------- | ----- | ------------------------------------------------------------------------------------------------- |
| `SEA`          | class | Build orchestrator — `execute` runs compress → blob → assemble; `destroy` tears down the emitter. |
| `Injector`     | class | Cross-platform binary resource injector (PE / ELF / Mach-O) — `inject` writes the resource.       |
| `Asset`        | class | A single named asset — `key` / `content` / `compressed`.                                          |
| `AssetManager` | class | Collection of embedded or disk-loaded assets — `register` / `load` / `asset` / `assets` / `keys`. |

### Factories

| API                  | Kind     | Summary                                                         |
| -------------------- | -------- | --------------------------------------------------------------- |
| `createSEA`          | function | Create a new SEA build orchestrator.                            |
| `createInjector`     | function | Create a cross-platform binary resource injector.               |
| `createAsset`        | function | Create a single named asset.                                    |
| `createAssetManager` | function | Create an asset manager for SEA-embedded or disk-loaded assets. |

### Constants

| API                               | Kind  | Summary                                                                     |
| --------------------------------- | ----- | --------------------------------------------------------------------------- |
| `SEA_SENTINEL_FUSE`               | const | SEA sentinel fuse value embedded in the Node.js binary.                     |
| `SEA_BLOB_RESOURCE`               | const | Resource name for the SEA blob in the executable.                           |
| `DEFAULT_SEA_COMPRESSION_QUALITY` | const | Default Brotli compression quality level (maximum).                         |
| `WINDOWS_SUBSYSTEM_GUI`           | const | Windows PE subsystem value: GUI application (no terminal window).           |
| `WINDOWS_SUBSYSTEM_CONSOLE`       | const | Windows PE subsystem value: console application.                            |
| `BROTLI_EXTENSION`                | const | File extension indicating Brotli compression.                               |
| `SKIP_EXTENSIONS`                 | const | File extensions that should NOT be Brotli-compressed.                       |
| `CLIENT_ASSET_KEY_RAW`            | const | Asset key for the raw (uncompressed) client HTML entry.                     |
| `CLIENT_ASSET_KEY_BR`             | const | Asset key for the Brotli-compressed client HTML entry.                      |
| `PE_MAGIC`                        | const | DOS MZ header magic (first 2 bytes of a PE file).                           |
| `PE_SIGNATURE`                    | const | PE signature: "PE\0\0" as a 32-bit value.                                   |
| `PE32_MAGIC`                      | const | PE32 optional header magic.                                                 |
| `PE32_PLUS_MAGIC`                 | const | PE32+ (64-bit) optional header magic.                                       |
| `ELF_MAGIC`                       | const | ELF magic: 0x7F 'E' 'L' 'F' as a 32-bit big-endian value.                   |
| `ELF_CLASS_64`                    | const | ELF 64-bit class identifier.                                                |
| `ELF_DATA_LSB`                    | const | ELF little-endian data encoding.                                            |
| `ELF_PT_NOTE`                     | const | ELF program header type: note segment.                                      |
| `MACHO_MAGIC_64`                  | const | Mach-O 64-bit magic (little-endian).                                        |
| `MACHO_LC_SEGMENT_64`             | const | Mach-O LC_SEGMENT_64 load command.                                          |
| `PE_RT_RCDATA`                    | const | PE resource type: RT_RCDATA (raw data).                                     |
| `PE_RESOURCE_DIR_SIZE`            | const | Size of IMAGE_RESOURCE_DIRECTORY in bytes.                                  |
| `PE_RESOURCE_ENTRY_SIZE`          | const | Size of IMAGE_RESOURCE_DIRECTORY_ENTRY in bytes.                            |
| `PE_RESOURCE_DATA_ENTRY_SIZE`     | const | Size of IMAGE_RESOURCE_DATA_ENTRY in bytes.                                 |
| `PE_SECTION_HEADER_SIZE`          | const | PE section header size in bytes.                                            |
| `PE_RESOURCE_SUBDIR_FLAG`         | const | High bit mask for resource directory entry offset (indicates subdirectory). |
| `PE_RESOURCE_NAME_FLAG`           | const | High bit mask for resource name entry (indicates named vs integer ID).      |
| `PE_SCN_INITIALIZED_DATA`         | const | Section contains initialized data.                                          |
| `PE_SCN_MEM_READ`                 | const | Section is readable.                                                        |
| `SEA_PLATFORMS`                   | const | Platform-specific SEA build configurations.                                 |
| `SEA_COMPRESSION_MODE_VALUES`     | const | Maps a `SEACompressionMode` to its numeric Brotli mode value.               |

### Helpers and errors

| API                   | Kind     | Summary                                                                 |
| --------------------- | -------- | ----------------------------------------------------------------------- |
| `isExecutableFormat`  | function | Check if a value is a valid `ExecutableFormat`.                         |
| `platformConfig`      | function | Get the platform configuration for the current OS.                      |
| `isPlatformSupported` | function | Check if the current or specified platform is supported for SEA builds. |
| `ensureExists`        | function | Assert that a path exists, throwing with a descriptive message if not.  |
| `isCompressible`      | function | Check if a file should be Brotli-compressed based on its extension.     |
| `walkDirectory`       | function | Recursively walk a directory and return all file paths.                 |
| `runShell`            | function | Run a command synchronously and return stdout; throws `ShellError`.     |
| `computeSize`         | function | Compute a size comparison between original and compressed byte counts.  |
| `compressFile`        | function | Brotli-compress a single file, writing the output alongside it.         |
| `compressDirectory`   | function | Compress all compressible files in a directory tree.                    |
| `parsePEOffset`       | function | Parse the PE header offset from a Windows executable.                   |
| `readU16`             | function | Read a 16-bit unsigned integer from a file descriptor.                  |
| `writeU16`            | function | Write a 16-bit unsigned integer to a file descriptor.                   |
| `isPEExecutable`      | function | Check if a file is a Windows PE executable.                             |
| `patchPESubsystem`    | function | Patch the PE subsystem field in a Windows executable.                   |
| `stripPESignature`    | function | Remove the Authenticode signature from a PE executable.                 |
| `formatSize`          | function | Format a byte count as a human-readable string.                         |
| `patchSentinelFuse`   | function | Patch the sentinel fuse in a binary from `:0` to `:1`.                  |
| `ShellError`          | class    | Error thrown when a shell command run via `runShell` exits non-zero.    |
| `isShellError`        | function | Whether a value is a `ShellError`.                                      |

### Types

| API                      | Kind      | Summary                                                                      |
| ------------------------ | --------- | ---------------------------------------------------------------------------- |
| `SEACompressionSize`     | interface | Size comparison between original and compressed data.                        |
| `SEACompressionMode`     | type      | Brotli compression mode (`generic` / `text` / `font`).                       |
| `SEACompressionInput`    | interface | Input describing a single file to Brotli-compress.                           |
| `SEACompressionResult`   | interface | Result of compressing a single file.                                         |
| `SEACompressionManifest` | interface | Manifest summarizing all compressed assets.                                  |
| `SEACompressionOptions`  | interface | Options controlling Brotli compression of one or more directories.           |
| `SEAPlatform`            | interface | Platform-specific SEA build configuration.                                   |
| `WindowsSubsystem`       | type      | Windows PE subsystem identifier (`console` / `gui`).                         |
| `SEAShellOptions`        | interface | Options for running a shell command.                                         |
| `ExecutableFormat`       | type      | Executable binary format detected from file header magic bytes.              |
| `InjectorOptions`        | interface | Options for injecting a resource into an executable.                         |
| `InjectorMachOOptions`   | interface | Mach-O specific injector options.                                            |
| `InjectorInterface`      | interface | Cross-platform binary resource injector contract.                            |
| `AssetInput`             | interface | Minimal data needed to create an `AssetInterface`.                           |
| `AssetInterface`         | interface | A single named asset wrapping its key, content buffer, and compression flag. |
| `AssetManagerEventMap`   | type      | Events emitted by an `AssetManagerInterface`.                                |
| `AssetManagerOptions`    | interface | Options for creating an `AssetManagerInterface`.                             |
| `AssetManagerInterface`  | interface | Named asset collection with SEA and disk loading.                            |
| `SEAStatus`              | type      | Overall status of the seal build.                                            |
| `SEAEventMap`            | type      | Events emitted by a `SEAInterface`.                                          |
| `SEAOptions`             | interface | Options for creating a SEA build.                                            |
| `SEAWindowsOptions`      | interface | Windows-specific SEA build options.                                          |
| `SEAResult`              | interface | Result of a successful seal build.                                           |
| `SEAInterface`           | interface | SEA build orchestrator contract.                                             |

## Usage

### Injecting a resource directly

```ts
import { createInjector } from '@orkestrel/sea'

const injector = createInjector({
	executable: 'dist/sea/myapp.exe',
	resource: 'NODE_SEA_BLOB',
	blob: 'dist/sea/sea-prep.blob',
	fuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
	macho: { segment: 'NODE_SEA' },
})

injector.format // 'pe' | 'elf' | 'macho'
injector.inject()
```

### Assets

```ts
import { createAsset, createAssetManager } from '@orkestrel/sea'

const asset = createAsset({ key: 'client.html.br', content: compressedBuffer })
asset.key // 'client.html.br'
asset.compressed // true (inferred from .br extension)

const manager = createAssetManager({ root: process.cwd() })
manager.register(asset)
manager.load() // disk fallback outside SEA mode; no-op inside SEA mode
manager.asset('client.html.br')
manager.assets()
manager.keys()
manager.destroy()
```

### Boundary and formatting helpers

```ts
import {
	runShell,
	isShellError,
	platformConfig,
	isPlatformSupported,
	ensureExists,
	isCompressible,
	walkDirectory,
	computeSize,
	compressFile,
	compressDirectory,
	formatSize,
	isExecutableFormat,
	parsePEOffset,
	readU16,
	writeU16,
	isPEExecutable,
	patchPESubsystem,
	stripPESignature,
	patchSentinelFuse,
} from '@orkestrel/sea'

try {
	runShell(['node', '--version'])
} catch (error) {
	if (isShellError(error)) {
		error.stdout // captured stdout Buffer
		error.stderr // captured stderr Buffer
	}
}

platformConfig() // SEAPlatform for process.platform, or undefined
isPlatformSupported() // true on win32 / darwin / linux

ensureExists('dist/server/serve.cjs', 'entry file is missing')
walkDirectory('dist/app/browser') // every relative file path under the directory
isCompressible('dist/app/browser/index.html') // true — not in SKIP_EXTENSIONS

const size = computeSize(1000, 400) // { original: 1000, compressed: 400, ratio: 0.4 }
compressFile('dist/index.html', 'dist/index.html.br')
compressDirectory('dist/app/browser', { paths: ['dist/app/browser'] })

formatSize(size.compressed) // '400 B'

isExecutableFormat('elf') // true

const fd = 0 // an open file descriptor from openSync in real usage
// parsePEOffset(fd) / readU16(fd, offset) / writeU16(fd, offset, value)
// isPEExecutable(path) / patchPESubsystem(path, subsystem) / stripPESignature(path)
// patchSentinelFuse(executable, fuse)
```

## See also

- [`README.md`](../README.md) — the guides index.
