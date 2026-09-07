# SEA

> The Node.js single executable application (SEA) builder: a pure-TypeScript pipeline
> that compresses assets, assembles the SEA blob, injects it into a copy of the host
> Node binary, and signs the result, with no WASM and no external tools.

Every export named here reaches a consumer through the `@orkestrel/sea` barrel, and its
source sits under [`src/server`](../src/server).

## Overview

### Build a single executable

Describe the build to `createSEA` — its entry script, output directory, assets, and compression — then `await sea.execute()` for the finished executable and its size:

```ts
import { createSEA, formatSize } from '@orkestrel/sea'

const sea = createSEA({
	name: 'myapp',
	entry: { path: 'dist/server/serve.cjs' },
	output: 'dist/sea',
	assets: { 'model.gguf': 'models/model.gguf' },
	compression: { paths: ['dist/app/browser'], mode: 'text' },
	windows: { terminal: false },
	timeout: 30_000,
})

const result = await sea.execute()
process.stdout.write(
	`${result.executable} ${formatSize(result.size)} ${String(result.duration)}ms\n`,
)
```

`sea.execute()` runs the pipeline — compress assets, generate the blob, assemble and sign the executable — and transitions `sea.status` from `'idle'` to `'active'` to `'done'` (or `'error'`). `sea.emitter` reports progress on `compress`, `progress` (once per compressed file, with `current`/`total` counts), `blob`, `assemble`, and `complete`.

When an `assets` path is compressed by `compression`, blob generation embeds the Brotli output under that asset's original key. Uncompressed entries keep their original paths, the compression manifest still reports each output path, and SEA does not mutate the caller's `assets` record.

On Windows, `SEAOptions.windows.terminal` (default `true`) selects whether the executable keeps its console window: `false` builds a GUI-subsystem binary that launches without a terminal, at the cost of detached stdio when no console is attached (console output is discarded).

On Windows, `SEAOptions.windows.sign` is optional Authenticode signing. When present, the assembled executable is signed with `signtool` (a certificate `file` with its `password`, or a store `thumbprint` — exactly one of those) and verified as the last content mutation before the atomic finalize; when absent, the output stays unsigned (`SEAResult.signed` is `false`). `buildSignCommand` builds the `signtool` argv and is available standalone.

`SEAOptions.entry` is a `SEAEntryOptions` object (`{ path, format? }`) rather than a bare path — `format` selects the entry module format (`'cjs'` default, or `'esm'` on Node >= 25.7). Every domain failure throws a `SEAError` carrying a machine-readable `SEAErrorCode`; narrow a caught value with `isSEAError`. `SEAResult` additionally reports `signed`, `stripped`, and the patched `terminal` flag (Windows only).

`ROOM` names the applicability limit the host binary itself imposes: a layout the injector cannot write into. The injector reads that layout from the target's headers and load commands and refuses under `ROOM` before any byte reaches the output, for a PE whose header slack is smaller than one section entry, a Mach-O whose first section sits inside the space another load command needs, a Mach-O carrying no `__LINKEDIT` segment, and a `__LINKEDIT` segment carrying sections. Where the injector takes a measurement, that measurement rides in `context`: `availableHeaderSpace` against `requiredHeaderSpace` for the PE case, and `firstSectionOffset` against `requiredOffset` for the load-command case. The `__LINKEDIT` cases carry the executable path alone, because the layout is the whole finding. `INJECT` keeps the failures another host does not clear: a refusal to replace a resource that already exists while `overwrite` is `false`, a malformed resource directory, and a defect the injector reports against its own construction or a write it already made. Retry a `ROOM` build on another host, and read an `INJECT` code against the options you passed, the resource tree in the host binary, or the injector itself.

`SEAOptions.timeout` bounds each spawned blob-generation, stripping, signing, and verification command in milliseconds. Omit it to leave those commands unbounded.

## Surface

### Classes

| API            | Kind  | Summary                                                                    |
| -------------- | ----- | -------------------------------------------------------------------------- |
| `SEA`          | class | Runs a Node.js single executable application build to completion.          |
| `Injector`     | class | Writes a named resource into a PE, ELF, or Mach-O executable in place.     |
| `Asset`        | class | Holds one named asset's key, bytes, and compression state.                 |
| `AssetManager` | class | Collects named assets from a SEA blob or from disk and serves them by key. |

### Factories

| API                  | Kind     | Summary                                                                                                                                                                 |
| -------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createSEA`          | function | Creates a SEA build orchestrator over the given options and returns it as a `SEAInterface`, the published contract a caller holds instead of the `SEA` class.           |
| `createInjector`     | function | Creates a resource injector bound to one target executable and returns it as an `InjectorInterface`, with the executable's format already detected from its header.     |
| `createAsset`        | function | Creates one named asset from a key and a content buffer and returns it as an `AssetInterface`, with `compressed` inferred from the key where the input leaves it unset. |
| `createAssetManager` | function | Creates an asset collection and returns it as an `AssetManagerInterface`, already carrying whatever assets the running SEA blob embeds.                                 |

### Constants

A `Shape` cell holds the constant's declared type.

| API                               | Kind  | Shape                                          | Summary                                                                                                               |
| --------------------------------- | ----- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `SEA_SENTINEL_FUSE`               | const | `string`                                       | Holds the SEA sentinel fuse value embedded in the Node.js binary, `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`.   |
| `SEA_BLOB_RESOURCE`               | const | `string`                                       | Names the SEA blob resource in the executable, `NODE_SEA_BLOB`.                                                       |
| `DEFAULT_SEA_COMPRESSION_QUALITY` | const | `number`                                       | Holds the default Brotli compression quality level, 11, the maximum Brotli accepts.                                   |
| `WINDOWS_SUBSYSTEM_GUI`           | const | `number`                                       | Holds the Windows PE subsystem value for a GUI application, 2, which launches without a terminal window.              |
| `WINDOWS_SUBSYSTEM_CONSOLE`       | const | `number`                                       | Holds the Windows PE subsystem value for a console application, 3.                                                    |
| `BROTLI_EXTENSION`                | const | `string`                                       | Names the file extension indicating Brotli compression, `.br`.                                                        |
| `SKIP_EXTENSIONS`                 | const | `ReadonlySet<string>`                          | Lists the file extensions Brotli compression skips, the already-compressed archive, image, font, and media formats.   |
| `PE_MAGIC`                        | const | `number`                                       | Holds the DOS MZ header magic, 0x5a4d, the first two bytes of a PE file.                                              |
| `PE_SIGNATURE`                    | const | `number`                                       | Holds the PE signature, 0x00004550, the bytes `PE\0\0` read as a 32-bit value.                                        |
| `PE32_MAGIC`                      | const | `number`                                       | Holds the PE32 optional header magic, 0x10b.                                                                          |
| `PE32_PLUS_MAGIC`                 | const | `number`                                       | Holds the PE32+ optional header magic, 0x20b, the 64-bit form.                                                        |
| `ELF_MAGIC`                       | const | `number`                                       | Holds the ELF magic, 0x7f454c46, the bytes 0x7F `E` `L` `F` read as a 32-bit big-endian value.                        |
| `ELF_CLASS_64`                    | const | `number`                                       | Holds the ELF 64-bit class identifier, 2.                                                                             |
| `ELF_DATA_LSB`                    | const | `number`                                       | Holds the ELF little-endian data encoding, 1.                                                                         |
| `ELF_PT_NOTE`                     | const | `number`                                       | Holds the ELF program header type for a note segment, 4.                                                              |
| `ELF_PT_LOAD`                     | const | `number`                                       | Holds the ELF program header type for a loadable segment, 1.                                                          |
| `ELF_PT_PHDR`                     | const | `number`                                       | Holds the ELF program header type for the program header table itself, 6.                                             |
| `ELF_PF_R`                        | const | `number`                                       | Holds the ELF segment permission flag marking a segment readable, 4.                                                  |
| `ELF_PAGE_SIZE`                   | const | `number`                                       | Holds the page size an injected ELF segment is aligned to, 0x1000.                                                    |
| `MACHO_MAGIC_64`                  | const | `number`                                       | Holds the Mach-O 64-bit magic, 0xfeedfacf, in little-endian byte order.                                               |
| `MACHO_LC_SEGMENT_64`             | const | `number`                                       | Holds the Mach-O `LC_SEGMENT_64` load command, 0x19.                                                                  |
| `PE_RT_RCDATA`                    | const | `number`                                       | Holds the PE resource type `RT_RCDATA` for raw data, 10.                                                              |
| `PE_RESOURCE_DIR_SIZE`            | const | `number`                                       | Holds the size of `IMAGE_RESOURCE_DIRECTORY` in bytes, 16.                                                            |
| `PE_RESOURCE_ENTRY_SIZE`          | const | `number`                                       | Holds the size of `IMAGE_RESOURCE_DIRECTORY_ENTRY` in bytes, 8.                                                       |
| `PE_RESOURCE_DATA_ENTRY_SIZE`     | const | `number`                                       | Holds the size of `IMAGE_RESOURCE_DATA_ENTRY` in bytes, 16.                                                           |
| `PE_SECTION_HEADER_SIZE`          | const | `number`                                       | Holds the PE section header size in bytes, 40.                                                                        |
| `PE_RESOURCE_SUBDIR_FLAG`         | const | `number`                                       | Holds the high bit mask marking a resource directory entry offset as a subdirectory, 0x80000000.                      |
| `PE_RESOURCE_NAME_FLAG`           | const | `number`                                       | Holds the high bit mask marking a resource entry as named rather than integer-identified, 0x80000000.                 |
| `PE_SCN_INITIALIZED_DATA`         | const | `number`                                       | Marks a section as containing initialized data, 0x00000040.                                                           |
| `PE_SCN_MEM_READ`                 | const | `number`                                       | Marks a section as readable, 0x40000000.                                                                              |
| `SEA_PLATFORMS`                   | const | `Readonly<Record<string, SEAPlatform>>`        | Holds the platform-specific SEA build configurations, keyed by `process.platform` for `win32`, `darwin`, and `linux`. |
| `SEA_COMPRESSION_MODE_VALUES`     | const | `Readonly<Record<SEACompressionMode, number>>` | Maps a `SEACompressionMode` to its numeric Brotli mode value: `generic` to 0, `text` to 1, and `font` to 2.           |
| `DEFAULT_ENTRY_FORMAT`            | const | `SEAEntryFormat`                               | Names the default SEA entry point module format when none is specified, `cjs`.                                        |

### Helpers and errors

| API                   | Kind     | Summary                                                                                                                                      |
| --------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `isExecutableFormat`  | function | Checks whether a value is a valid `ExecutableFormat`.                                                                                        |
| `resolvePlatform`     | function | Resolves the effective platform configuration.                                                                                               |
| `isPlatformSupported` | function | Checks whether the current or named platform is supported for SEA builds.                                                                    |
| `ensureExists`        | function | Asserts that a path exists, throwing a coded `SEAError` if not.                                                                              |
| `isCompressible`      | function | Checks whether a file's extension is outside `SKIP_EXTENSIONS`, so Brotli compression applies to it.                                         |
| `walkDirectory`       | function | Walks a directory recursively and returns every file path it finds, relative to the base and skipping symlinks.                              |
| `executeShell`        | function | Executes a command synchronously and returns stdout.                                                                                         |
| `redactCommand`       | function | Redacts password arguments from a shell command, so the command is safe to include in an error message.                                      |
| `computeSize`         | function | Computes a size comparison between original and compressed byte counts.                                                                      |
| `compressFile`        | function | Brotli-compresses a single file, writing the output alongside it.                                                                            |
| `compressDirectory`   | function | Compresses all compressible files in a directory tree.                                                                                       |
| `alignTo`             | function | Rounds a value up to the next multiple of an alignment boundary.                                                                             |
| `readPEOffset`        | function | Reads the PE header offset from a Windows executable.                                                                                        |
| `readU16`             | function | Reads a 16-bit unsigned integer from a file descriptor.                                                                                      |
| `readU32`             | function | Reads a 32-bit unsigned little-endian integer from a file descriptor.                                                                        |
| `readU64`             | function | Reads a 64-bit unsigned little-endian integer from a file descriptor.                                                                        |
| `writeU16`            | function | Writes a 16-bit unsigned integer to a file descriptor.                                                                                       |
| `writeU32`            | function | Writes a 32-bit unsigned little-endian integer to a file descriptor.                                                                         |
| `writeU64`            | function | Writes a 64-bit unsigned little-endian integer to a file descriptor.                                                                         |
| `appendFile`          | function | Appends a source file to a target file, streaming in fixed-size chunks.                                                                      |
| `stripTrailingNulls`  | function | Truncates a NUL-padded binary name field at its first NUL character.                                                                         |
| `isPEExecutable`      | function | Checks whether a file is a Windows PE executable.                                                                                            |
| `patchPESubsystem`    | function | Patches the PE subsystem field in a Windows executable.                                                                                      |
| `stripPESignature`    | function | Removes the Authenticode signature from a PE executable by zeroing the security directory entry in the optional header.                      |
| `buildSignCommand`    | function | Builds the `signtool sign` argv for signing a Windows executable.                                                                            |
| `formatSize`          | function | Formats a byte count as a human-readable string.                                                                                             |
| `ensureSafeKey`       | function | Asserts that an asset key is safe to use as a relative filesystem/archive key.                                                               |
| `ensureContained`     | function | Asserts that `path` (resolved against `base`) real-path-resolves to a location inside `base`, defeating a symlink escape.                    |
| `ensureSafeName`      | function | Asserts that `name` is a single safe path segment suitable as an output executable base name.                                                |
| `finalizeExecutable`  | function | Finalizes a built executable by durably flushing it to disk and atomically moving it into place.                                             |
| `syncDirectory`       | function | Fsyncs a directory to durably persist a prior file rename/create within it.                                                                  |
| `buildBlobConfig`     | function | Builds the Node.js `--experimental-sea-config` JSON object for a SEA blob.                                                                   |
| `patchSentinelFuse`   | function | Patches the sentinel fuse in a binary from `:0` to `:1`.                                                                                     |
| `buildELFNoteHeader`  | function | Builds an ELF `PT_NOTE` entry's header bytes (namesz/descsz/type + padded name) for the SEA blob note, without the blob body itself.         |
| `alignELFNoteSize`    | function | Aligns an ELF note component size to its four-byte boundary.                                                                                 |
| `isPowerOfTwo`        | function | Checks whether a number is a nonzero power of two.                                                                                           |
| `copyRange`           | function | Copies a byte range from one open file descriptor to another, streaming in fixed-size chunks instead of buffering the whole range in memory. |
| `openBrowser`         | function | Launches the system default browser at an http(s) URL.                                                                                       |
| `SEAError`            | class    | Represents the coded base error for every failure raised by the SEA build.                                                                   |
| `isSEAError`          | function | Checks whether a value is a `SEAError`.                                                                                                      |
| `ShellError`          | class    | Represents an error thrown when a shell command executed through `executeShell` exits non-zero.                                              |
| `isShellError`        | function | Checks whether a value is a `ShellError`.                                                                                                    |

### Types

A `Shape` cell holds an interface's data members as bare names in braces, `?` marking an optional member and `plus` introducing its call-signature members, and a type alias's own type literal with a union's arms escaped as `\|`. An extended interface's name comes before `plus`, with the members it adds after.

| API                      | Kind      | Shape                                                                                                                                                                     | Summary                                                                                 |
| ------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `SEACompressionSize`     | interface | `{ original, compressed, ratio }`                                                                                                                                         | Represents a size comparison between original and compressed data.                      |
| `SEACompressionMode`     | type      | `'generic' \| 'text' \| 'font'`                                                                                                                                           | Names a Brotli compression mode.                                                        |
| `SEACompressionResult`   | interface | `{ input, output, size }`                                                                                                                                                 | Represents the result of compressing a single file.                                     |
| `SEACompressionManifest` | interface | `{ assets, total }`                                                                                                                                                       | Summarizes all compressed assets.                                                       |
| `SEAProgress`            | interface | `{ path, current, total }`                                                                                                                                                | Represents the progress reported while compressing a directory.                         |
| `SEACompressionHandler`  | type      | `(result: SEACompressionResult) => void`                                                                                                                                  | Describes the callback `compressDirectory` invokes after each file it compresses.       |
| `SEABrotliOptions`       | interface | `{ mode?, quality? }`                                                                                                                                                     | Controls how Brotli encodes one file.                                                   |
| `SEACompressionOptions`  | interface | `SEABrotliOptions plus { paths }`                                                                                                                                         | Controls Brotli compression of one or more directories.                                 |
| `SEAPlatform`            | interface | `{ executable, remove?, sign?, verify? }`                                                                                                                                 | Represents a platform-specific SEA build configuration.                                 |
| `SEAShellOptions`        | interface | `{ cwd?, env?, timeout?, signal? }`                                                                                                                                       | Configures the execution of a shell command.                                            |
| `ExecutableFormat`       | type      | `'pe' \| 'elf' \| 'macho'`                                                                                                                                                | Names an executable binary format detected from file header magic bytes.                |
| `ELFNoteHeader`          | interface | `{ header, total }`                                                                                                                                                       | Holds an ELF `PT_NOTE` entry's header bytes and the on-disk size of the whole entry.    |
| `ELFProgramHeader`       | interface | `{ type, flags, offset, vaddr, paddr, filesz, memsz, align }`                                                                                                             | Holds one ELF64 program header entry.                                                   |
| `PEResourceLeaf`         | interface | `{ typeId, typeName, nameId, nameName, language, codePage, dataRVA, dataSize }`                                                                                           | Holds one leaf of a PE resource directory tree.                                         |
| `PEResourceEntry`        | interface | `{ language, codePage, leafIndex, dataSize }`                                                                                                                             | Holds one language entry of a PE resource name directory.                               |
| `PESection`              | interface | `{ name, virtualSize, virtualAddress, rawSize, rawOffset, characteristics, headerOffset }`                                                                                | Holds one PE section table entry.                                                       |
| `InjectorOptions`        | interface | `{ executable, resource, blob, fuse?, macho?, overwrite? }`                                                                                                               | Configures the injection of a resource into an executable.                              |
| `InjectorMachOOptions`   | interface | `{ segment? }`                                                                                                                                                            | Configures Mach-O specific injector behavior.                                           |
| `InjectorInterface`      | interface | `{ format } plus inject`                                                                                                                                                  | Represents a cross-platform binary resource injector.                                   |
| `AssetInput`             | interface | `{ key, content, compressed? }`                                                                                                                                           | Holds the minimal data needed to create an `AssetInterface`.                            |
| `AssetInterface`         | interface | `{ key, content, compressed }`                                                                                                                                            | Represents a single named asset wrapping its key, content buffer, and compression flag. |
| `AssetManagerEventMap`   | type      | `{ register, load, clear, error }`                                                                                                                                        | Lists the events emitted by an `AssetManagerInterface`.                                 |
| `AssetManagerOptions`    | interface | `{ on?, error?, root?, assets? }`                                                                                                                                         | Configures the creation of an `AssetManagerInterface`.                                  |
| `AssetManagerInterface`  | interface | `{ emitter, count } plus asset, assets, keys, register, load, clear, destroy`                                                                                             | Represents a named asset collection with SEA and disk loading.                          |
| `SEAStatus`              | type      | `'idle' \| 'active' \| 'done' \| 'error'`                                                                                                                                 | Names the overall status of the SEA build.                                              |
| `SEAErrorCode`           | type      | `'PLATFORM' \| 'ENTRY' \| 'ASSET' \| 'BLOB' \| 'FORMAT' \| 'INJECT' \| 'ROOM' \| 'FUSE' \| 'SIGN' \| 'SHELL' \| 'TIMEOUT' \| 'ABORT' \| 'OUTPUT' \| 'STATE' \| 'BROWSER'` | Names the machine-readable error code carried by every `SEAError`.                      |
| `SEAEntryFormat`         | type      | `'cjs' \| 'esm'`                                                                                                                                                          | Names the SEA entry point module format.                                                |
| `SEAEntryOptions`        | interface | `{ path, format? }`                                                                                                                                                       | Describes the SEA entry point.                                                          |
| `SEABlobOptions`         | interface | `{ cache?, snapshot? }`                                                                                                                                                   | Controls generated SEA blob behavior.                                                   |
| `SEAEventMap`            | type      | `{ compress, progress, blob, assemble, complete, error }`                                                                                                                 | Lists the events emitted by a `SEAInterface`.                                           |
| `SEAOptions`             | interface | `{ on?, error?, name, entry, output, assets?, compression?, windows?, root?, signal?, timeout?, blob? }`                                                                  | Configures the creation of a SEA build.                                                 |
| `SEAWindowsOptions`      | interface | `{ terminal?, sign? }`                                                                                                                                                    | Configures Windows-specific SEA build behavior.                                         |
| `SEAWindowsSignOptions`  | interface | `{ file?, password?, thumbprint?, timestamp?, digest? }`                                                                                                                  | Describes the Windows Authenticode signing options passed through to `signtool`.        |
| `SEAResult`              | interface | `{ executable, platform, size, duration, compression?, signed, stripped, terminal? }`                                                                                     | Represents the result of a successful SEA build.                                        |
| `SEAInterface`           | interface | `{ emitter, status } plus execute, destroy`                                                                                                                               | Represents a SEA build orchestrator.                                                    |

## Methods

The public methods of each behavioral interface — one table per type, keyed by its backticked name, every call-signature member listed. A `readonly` data member stays in the interface's `Shape` cell and off these tables: `format` on `InjectorInterface`, `emitter` and `status` on `SEAInterface`, `emitter` and `count` on `AssetManagerInterface`. Each concrete class implements its interface exactly, so this doubles as the class's instance-method surface.

#### `SEAInterface`

`execute` runs the build pipeline; `destroy` tears down the emitter.

| Method    | Returns              | Summary                                                                    |
| --------- | -------------------- | -------------------------------------------------------------------------- |
| `execute` | `Promise<SEAResult>` | Runs the compress, blob, and assemble stages and returns the build result. |
| `destroy` | `void`               | Tears down the emitter.                                                    |

#### `InjectorInterface`

`inject` performs the one-shot resource write.

| Method   | Returns | Summary                                        |
| -------- | ------- | ---------------------------------------------- |
| `inject` | `void`  | Injects the resource data into the executable. |

#### `AssetManagerInterface`

`asset` / `assets` are the singular/plural accessors; `register` / `load` add assets; `clear` / `destroy` are the lifecycle pair.

| Method     | Returns                       | Summary                                                                       |
| ---------- | ----------------------------- | ----------------------------------------------------------------------------- |
| `asset`    | `AssetInterface \| undefined` | Looks up one registered asset by key.                                         |
| `assets`   | `readonly AssetInterface[]`   | Lists every registered asset, in registration order.                          |
| `keys`     | `readonly string[]`           | Lists every registered asset key, in registration order.                      |
| `register` | `void`                        | Registers one asset, or every asset of a list.                                |
| `load`     | `void`                        | Loads the configured assets from disk, and registers nothing inside SEA mode. |
| `clear`    | `void`                        | Removes every registered asset without destroying the manager.                |
| `destroy`  | `void`                        | Clears every registered asset and tears down the emitter.                     |

## Usage

### Injecting a resource directly

Construct an injector over an already-assembled executable, read the format it detected, and call `inject` to write the blob into it:

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

Create an asset from a buffer, register it with a manager configured to load more from disk, then read the collection back and tear it down:

```ts
import { createAsset, createAssetManager } from '@orkestrel/sea'

const asset = createAsset({ key: 'client.html.br', content: compressedBuffer })
asset.key // 'client.html.br'
asset.compressed // true (inferred from .br extension)

const manager = createAssetManager({
	root: process.cwd(),
	assets: { 'client.html.br': 'dist/client/client.html.br' },
})
manager.register(asset)
manager.load() // reads the configured assets outside SEA mode; no-op inside SEA mode
manager.asset('client.html.br')
manager.assets()
manager.keys()
manager.clear()
manager.destroy()
```

### Boundary and formatting helpers

Every helper the build pipeline runs on is exported too, from the shell boundary and the path assertions to the fixed-width binary readers, the PE patches, and the size formatter:

```ts
import {
	executeShell,
	redactCommand,
	isShellError,
	resolvePlatform,
	isPlatformSupported,
	ensureExists,
	isCompressible,
	walkDirectory,
	computeSize,
	compressFile,
	compressDirectory,
	formatSize,
	isExecutableFormat,
	readPEOffset,
	readU16,
	readU32,
	readU64,
	writeU16,
	writeU32,
	writeU64,
	appendFile,
	stripTrailingNulls,
	alignTo,
	isPEExecutable,
	patchPESubsystem,
	stripPESignature,
	patchSentinelFuse,
	ensureContained,
	ensureSafeName,
	openBrowser,
	buildSignCommand,
	syncDirectory,
	alignELFNoteSize,
	isPowerOfTwo,
} from '@orkestrel/sea'

try {
	executeShell(['node', '--version'])
} catch (error) {
	if (isShellError(error)) {
		error.stdout // captured stdout Buffer
		error.stderr // captured stderr Buffer
	}
}

resolvePlatform() // SEAPlatform for process.platform, or undefined
isPlatformSupported() // true on win32 / darwin / linux

ensureExists('dist/server/serve.cjs', 'entry file is missing')
walkDirectory('dist/app/browser') // every relative file path under the directory
isCompressible('dist/app/browser/index.html') // true — not in SKIP_EXTENSIONS

const size = computeSize(1000, 400) // { original: 1000, compressed: 400, ratio: 0.4 }
compressFile('dist/index.html', 'dist/index.html.br')
compressDirectory('dist/app/browser', { mode: 'text' })

formatSize(size.compressed) // '400 B'

isExecutableFormat('elf') // true

const fd = 0 // an open file descriptor from openSync in real usage
// readPEOffset(fd) / readU16(fd, offset) / writeU16(fd, offset, value)
// readU32(fd, offset) / readU64(fd, offset) — 32- and 64-bit little-endian reads
// writeU32(fd, offset, value) / writeU64(fd, offset, value) — the matching writes
// isPEExecutable(path) / patchPESubsystem(path, subsystem) / stripPESignature(path)
// patchSentinelFuse(executable, fuse)
// appendFile('dist/sea/app', 'dist/sea/sea-prep.blob') — streams the blob onto the binary

stripTrailingNulls('.rsrc\0\0\0') // '.rsrc' — a NUL-padded PE section name field

ensureContained('/dist/app', 'browser') // real, symlink-resolved path inside the base root

openBrowser('http://localhost:3000') // best-effort launch of the system default browser
ensureSafeName('myapp') // ok; throws SEAError('ASSET', ...) for '../evil' or 'a/b'

buildSignCommand({ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD' }, 'dist/sea/app.exe')
// ['signtool', 'sign', '/fd', 'sha256', '/sha1', 'AABBCCDDEEFF00112233445566778899AABBCCDD', 'dist/sea/app.exe']

syncDirectory('/dist/sea') // fsync a directory to durably persist a prior rename/create; no-op on win32

redactCommand(['signtool', 'sign', '/p', 'hunter2']) // ['signtool', 'sign', '/p', '***']
alignELFNoteSize(10) // 12 — the next four-byte ELF note boundary
alignTo(4097, 4096) // 8192 — the general form behind every format's alignment
isPowerOfTwo(4096) // true
```

## Tests

- [`tests/guides.test.ts`](../tests/guides.test.ts) — the `## Surface` ↔ `src/server` bijection (value and type exports), the `SEAInterface` ↔ `SEA`, `InjectorInterface` ↔ `Injector`, and `AssetManagerInterface` ↔ `AssetManager` method bijections, and the equality gate: every `Summary` cell against its declaration's description paragraph, the titled `Build a single executable` fence against the `@example` block of that title (pinned so the titled pair cannot be retired silently), and the README pitch against this guide's tagline. It also runs the flagship fences and asserts the values their comments claim.
- [`tests/src/server/seas/SEA.test.ts`](../tests/src/server/seas/SEA.test.ts) — the build pipeline end to end: the status transitions, the emitted `compress` / `progress` / `blob` / `assemble` / `complete` events, the compressed-asset key rewrite that leaves the caller's `assets` record alone, abort through `SEAOptions.signal`, the per-command timeout, and the `windows.sign` option validation.
- [`tests/src/server/injectors/Injector.test.ts`](../tests/src/server/injectors/Injector.test.ts) — format detection from the header magic, and injection into synthetic PE, ELF, and Mach-O fixtures, including the `ROOM` refusals a host layout forces and the `INJECT` failures it does not.
- [`tests/src/server/assets/Asset.test.ts`](../tests/src/server/assets/Asset.test.ts) — the key, the content buffer, and the `compressed` flag inferred from a `.br` suffix or taken from the input.
- [`tests/src/server/assets/AssetManager.test.ts`](../tests/src/server/assets/AssetManager.test.ts) — registration, the singular and plural accessors in registration order, `load` from disk with an `error` event per missing path, `clear`, and `destroy`.
- [`tests/src/server/helpers.test.ts`](../tests/src/server/helpers.test.ts) — every exported helper against real files and real processes: the shell boundary and its `ShellError`, the path and key assertions including symlink escape, Brotli compression and its size arithmetic, the fixed-width binary readers and writers, the PE subsystem and signature patches, the sentinel fuse patch, the ELF note header, the streaming copy and append, the signing argv, and the browser launch.
- [`tests/src/server/factories.test.ts`](../tests/src/server/factories.test.ts) — each factory returns the published contract and honors the options it is given.
- [`tests/src/server/validators.test.ts`](../tests/src/server/validators.test.ts) — `isExecutableFormat` accepts `pe`, `elf`, and `macho` and stays total for every other value.

## See also

- [`README.md`](README.md) — the guides index.
