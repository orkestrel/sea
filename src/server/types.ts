import type { EmitterErrorHandler, EmitterHooks, EmitterInterface } from '@orkestrel/emitter'

// === Compression

/**
 * Represents a size comparison between original and compressed data.
 */
export interface SEACompressionSize {
	readonly original: number
	readonly compressed: number
	readonly ratio: number
}

/**
 * Names a Brotli compression mode.
 *
 * @remarks
 * `generic` — general-purpose data (Brotli mode 0).
 * `text`    — UTF-8 text (Brotli mode 1).
 * `font`    — WOFF2 font data (Brotli mode 2).
 */
export type SEACompressionMode = 'generic' | 'text' | 'font'

/**
 * Represents the result of compressing a single file.
 *
 * @remarks
 * `input`  — absolute path to the original file.
 * `output` — absolute path to the compressed file.
 * `size`   — byte-level comparison.
 */
export interface SEACompressionResult {
	readonly input: string
	readonly output: string
	readonly size: SEACompressionSize
}

/**
 * Summarizes all compressed assets.
 *
 * @remarks
 * Generated after a full directory compression pass.
 */
export interface SEACompressionManifest {
	readonly assets: readonly SEACompressionResult[]
	readonly total: SEACompressionSize
}

/**
 * Represents the progress reported while compressing a directory.
 *
 * @remarks
 * `path`    — absolute path to the file just compressed.
 * `current` — number of files compressed so far (1-based).
 * `total`   — total number of compressible files.
 */
export interface SEAProgress {
	readonly path: string
	readonly current: number
	readonly total: number
}

/**
 * Describes the callback `compressDirectory` invokes after each file it compresses.
 */
export type SEACompressionHandler = (result: SEACompressionResult) => void

/**
 * Controls how Brotli encodes one file.
 *
 * @remarks
 * `mode`    — Brotli mode. Default: `'generic'`.
 * `quality` — Brotli quality level (0–11). Default: 11.
 */
export interface SEABrotliOptions {
	readonly mode?: SEACompressionMode
	readonly quality?: number
}

/**
 * Controls Brotli compression of one or more directories.
 *
 * @remarks
 * `paths` — directories (relative to `SEAOptions.root`) to compress.
 */
export interface SEACompressionOptions extends SEABrotliOptions {
	readonly paths: readonly string[]
}

// === Platform

/**
 * Represents a platform-specific SEA build configuration.
 *
 * @remarks
 * Describes the native Node binary and code signing commands.
 */
export interface SEAPlatform {
	readonly executable: string
	readonly remove?: readonly string[]
	readonly sign?: readonly string[]
	readonly verify?: readonly string[]
}

// === Shell

/**
 * Configures the execution of a shell command.
 *
 * @remarks
 * `cwd` — working directory. Default: `process.cwd()`.
 * `env` — additional environment variables to merge with `process.env`.
 */
export interface SEAShellOptions {
	readonly cwd?: string
	readonly env?: Readonly<Record<string, string>>
	readonly timeout?: number
	readonly signal?: AbortSignal
}

// === Injector

/**
 * Names an executable binary format detected from file header magic bytes.
 */
export type ExecutableFormat = 'pe' | 'elf' | 'macho'

/**
 * Holds an ELF `PT_NOTE` entry's header bytes and the on-disk size of the whole entry.
 *
 * @remarks
 * `header` — the namesz/descsz/type words followed by the NUL-terminated,
 * four-byte-padded note name.
 * `total`  — bytes the complete entry occupies on disk: `header` plus the
 * four-byte-padded blob written after it.
 */
export interface ELFNoteHeader {
	readonly header: Buffer
	readonly total: number
}

/**
 * Holds one ELF64 program header entry.
 *
 * @remarks
 * Transliterates the `Elf64_Phdr` structure of the ELF64 specification field for
 * field, with the `p_` prefix dropped: `type` is `p_type`, `flags` is `p_flags`,
 * `offset` is `p_offset`, `vaddr` is `p_vaddr`, `paddr` is `p_paddr`, `filesz` is
 * `p_filesz`, `memsz` is `p_memsz`, and `align` is `p_align`. Every 64-bit field is
 * carried as a `number` because an executable's offsets stay far inside the safe
 * integer range.
 */
export interface ELFProgramHeader {
	readonly type: number
	readonly flags: number
	readonly offset: number
	readonly vaddr: number
	readonly paddr: number
	readonly filesz: number
	readonly memsz: number
	readonly align: number
}

/**
 * Holds one leaf of a PE resource directory tree.
 *
 * @remarks
 * Flattens the path a resource takes through the three directory levels of the PE
 * `IMAGE_RESOURCE_DIRECTORY` tree — type, name, language — onto the
 * `IMAGE_RESOURCE_DATA_ENTRY` it ends at. A level identifies its entry either by
 * integer id or by name, so `typeId` and `nameId` carry the integer form and
 * `typeName` and `nameName` the named form, whichever the entry used. `dataRVA` and
 * `dataSize` are the data entry's `OffsetToData` and `Size` fields.
 */
export interface PEResourceLeaf {
	readonly typeId: number
	readonly typeName: string | undefined
	readonly nameId: number
	readonly nameName: string | undefined
	readonly language: number
	readonly codePage: number
	readonly dataRVA: number
	readonly dataSize: number
}

/**
 * Holds one language entry of a PE resource name directory.
 *
 * @remarks
 * `leafIndex` addresses the {@link PEResourceLeaf} this entry's bytes come from,
 * within the leaf list the injector gathered from the original executable. A
 * `leafIndex` of `-1` marks the entry the injector is adding, whose bytes are
 * streamed from the blob file rather than copied from an existing leaf.
 */
export interface PEResourceEntry {
	readonly language: number
	readonly codePage: number
	readonly leafIndex: number
	readonly dataSize: number
}

/**
 * Holds one PE section table entry.
 *
 * @remarks
 * Transliterates the PE `IMAGE_SECTION_HEADER` structure: `name` is `Name` with its
 * NUL padding stripped, `virtualSize` is `Misc.VirtualSize`, `virtualAddress` is
 * `VirtualAddress`, `rawSize` is `SizeOfRawData`, `rawOffset` is
 * `PointerToRawData`, and `characteristics` is `Characteristics`. `headerOffset` is
 * not a header field: it records the file offset the entry was read from, so a
 * later write lands on the same bytes.
 */
export interface PESection {
	readonly name: string
	readonly virtualSize: number
	readonly virtualAddress: number
	readonly rawSize: number
	readonly rawOffset: number
	readonly characteristics: number
	readonly headerOffset: number
}

/**
 * Configures the injection of a resource into an executable.
 *
 * @remarks
 * `executable` — absolute path to the target executable.
 * `resource`   — resource identifier (e.g. `"NODE_SEA_BLOB"`).
 * `blob`       — absolute path to the data file to inject.
 * `fuse`       — when set, patches the fuse from `:0` to `:1` after injection.
 * `macho`      — Mach-O specific options; `segment` defaults to `"NODE_SEA"`.
 * `overwrite`  — replace an existing resource with the same name. Default: `true`.
 */
export interface InjectorOptions {
	readonly executable: string
	readonly resource: string
	readonly blob: string
	readonly fuse?: string
	readonly macho?: InjectorMachOOptions
	readonly overwrite?: boolean
}

/**
 * Configures Mach-O specific injector behavior.
 *
 * @remarks
 * `segment` — Mach-O segment name. Default: `"NODE_SEA"`.
 */
export interface InjectorMachOOptions {
	readonly segment?: string
}

/**
 * Represents a cross-platform binary resource injector.
 *
 * @remarks
 * Injects arbitrary data into PE (Windows), ELF (Linux), and Mach-O (macOS)
 * executables using streaming file I/O. No WASM or external tools required.
 */
export interface InjectorInterface {
	/** Holds the detected executable format of the target binary. */
	readonly format: ExecutableFormat
	/** Injects the resource data into the executable. */
	inject(): void
}

// === Asset

/**
 * Holds the minimal data needed to create an {@link AssetInterface}.
 *
 * @remarks
 * `key`        — the asset's lookup key (e.g. `"client.html.br"`).
 * `content`    — raw asset bytes.
 * `compressed` — whether `content` is Brotli-compressed. Default: inferred
 * from a `.br` suffix on `key`.
 */
export interface AssetInput {
	readonly key: string
	readonly content: ArrayBuffer
	readonly compressed?: boolean
}

/**
 * Represents a single named asset wrapping its key, content buffer, and compression flag.
 */
export interface AssetInterface {
	readonly key: string
	readonly content: ArrayBuffer
	readonly compressed: boolean
}

/** Lists the events emitted by an {@link AssetManagerInterface}. */
export type AssetManagerEventMap = {
	readonly register: readonly [asset: AssetInterface]
	readonly load: readonly [keys: readonly string[]]
	readonly clear: readonly []
	readonly error: readonly [error: unknown]
}

/**
 * Configures the creation of an {@link AssetManagerInterface}.
 *
 * @remarks
 * `root`   — project root used to resolve the configured `assets` paths. Default: `process.cwd()`.
 * `assets` — key→path mapping for the assets `load()` reads from disk. Each path is
 * relative to `root`. `load()` registers every path that exists under its key and
 * emits one `error` for each configured path that is missing.
 */
export interface AssetManagerOptions {
	readonly on?: EmitterHooks<AssetManagerEventMap>
	readonly error?: EmitterErrorHandler
	readonly root?: string
	readonly assets?: Readonly<Record<string, string>>
}

/**
 * Represents a named asset collection with SEA and disk loading.
 *
 * @remarks
 * In SEA mode, embedded assets are loaded automatically at construction.
 * Outside SEA, `load()` reads the paths `assets` configures from disk.
 */
export interface AssetManagerInterface {
	readonly emitter: EmitterInterface<AssetManagerEventMap>
	readonly count: number
	asset(key: string): AssetInterface | undefined
	assets(): readonly AssetInterface[]
	keys(): readonly string[]
	register(input: AssetInput | readonly AssetInput[]): void
	load(): void
	clear(): void
	destroy(): void
}

// === SEA

/**
 * Names the overall status of the SEA build.
 */
export type SEAStatus = 'idle' | 'active' | 'done' | 'error'

/**
 * Names the machine-readable error code carried by every {@link SEAError}.
 *
 * @remarks
 * `PLATFORM` — unsupported or misdetected platform.
 * `ENTRY`    — invalid or missing entry point.
 * `ASSET`    — invalid asset key or content.
 * `BLOB`     — SEA blob generation failure.
 * `FORMAT`   — unrecognized executable binary format.
 * `INJECT`   — resource injection failure.
 * `FUSE`     — sentinel fuse patch failure.
 * `SIGN`     — code signing failure.
 * `SHELL`    — shell command exited non-zero.
 * `TIMEOUT`  — shell command exceeded its timeout.
 * `ABORT`    — operation aborted via `AbortSignal`.
 * `OUTPUT`   — final executable write/finalize failure.
 * `STATE`    — invalid internal state or argument.
 * `BROWSER`  — invalid or unsupported URL passed to `openBrowser`.
 */
export type SEAErrorCode =
	| 'PLATFORM'
	| 'ENTRY'
	| 'ASSET'
	| 'BLOB'
	| 'FORMAT'
	| 'INJECT'
	| 'FUSE'
	| 'SIGN'
	| 'SHELL'
	| 'TIMEOUT'
	| 'ABORT'
	| 'OUTPUT'
	| 'STATE'
	| 'BROWSER'

/**
 * Names the SEA entry point module format.
 *
 * @remarks
 * `cjs` — CommonJS entry (Node default).
 * `esm` — ECMAScript module entry (requires Node >= 25.7).
 */
export type SEAEntryFormat = 'cjs' | 'esm'

/**
 * Describes the SEA entry point.
 *
 * @remarks
 * `path`   — path to the entry point to embed.
 * `format` — module format of the entry point. Default: `'cjs'`.
 */
export interface SEAEntryOptions {
	readonly path: string
	readonly format?: SEAEntryFormat
}

/**
 * Controls generated SEA blob behavior.
 *
 * @remarks
 * `cache`    — maps to the SEA config `useCodeCache`. Default: `true`.
 * `snapshot` — maps to the SEA config `useSnapshot`. Default: `false`.
 */
export interface SEABlobOptions {
	readonly cache?: boolean
	readonly snapshot?: boolean
}

/** Lists the events emitted by a {@link SEAInterface}. */
export type SEAEventMap = {
	readonly compress: readonly [compression: SEACompressionManifest | undefined]
	readonly progress: readonly [progress: SEAProgress]
	readonly blob: readonly [blob: string]
	readonly assemble: readonly [executable: string]
	readonly complete: readonly [result: SEAResult]
	readonly error: readonly [error: unknown]
}

/**
 * Configures the creation of a SEA build.
 *
 * @remarks
 * `name`        — output executable name (no extension).
 * `entry`       — the entry point to embed (path and module format).
 * `output`      — directory for the final executable.
 * `assets`      — key→path mapping for SEA embedded assets. When compression
 * writes a mapped path's Brotli output, the blob embeds that output under the
 * original key without mutating this record. Other entries keep their paths.
 * `compression` — directories to Brotli-compress before embedding.
 * `windows`     — Windows-specific build options (console/GUI terminal).
 * `root`        — project root directory. Default: `process.cwd()`.
 * `signal`      — an `AbortSignal` that cancels the build in progress.
 * `timeout`     — milliseconds allowed for each spawned shell command. Omit to disable the timeout.
 * `blob`        — options controlling generated SEA blob behavior.
 */
export interface SEAOptions {
	readonly on?: EmitterHooks<SEAEventMap>
	readonly error?: EmitterErrorHandler
	readonly name: string
	readonly entry: SEAEntryOptions
	readonly output: string
	readonly assets?: Readonly<Record<string, string>>
	readonly compression?: SEACompressionOptions
	readonly windows?: SEAWindowsOptions
	readonly root?: string
	readonly signal?: AbortSignal
	readonly timeout?: number
	readonly blob?: SEABlobOptions
}

/**
 * Configures Windows-specific SEA build behavior.
 *
 * @remarks
 * `terminal` — whether the built executable keeps a console window (PE
 * console subsystem). Defaults to `true`. Set `false` to build a
 * GUI-subsystem binary that launches without a terminal — warning: when
 * launched without an attached console, a GUI-subsystem Node binary has no
 * valid stdio, so `process.stdout`/`stderr`/`stdin` are detached and console
 * output is discarded; use only for windowless apps.
 * `sign`      — Authenticode signing options. When present, the assembled
 * executable is signed with `signtool` (and verified) as the LAST content
 * mutation before the atomic finalize; when absent, the output is unsigned
 * and `SEAResult.signed` is `false`.
 *
 * These options apply only when the build HOST is Windows — there is no
 * cross-compilation, so building on a non-Windows host ignores `windows.*`.
 */
export interface SEAWindowsOptions {
	readonly terminal?: boolean
	readonly sign?: SEAWindowsSignOptions
}

/**
 * Describes the Windows Authenticode signing options passed through to `signtool`.
 *
 * @remarks
 * `file`       — path to a `.pfx`/`.p12` certificate file (`signtool /f`).
 * `password`   — certificate password (`signtool /p`). SENSITIVE — never
 * logged and never included in a thrown error's message or `context`.
 * `thumbprint` — SHA1 thumbprint of a certificate already installed in the
 * Windows certificate store (`signtool /sha1`).
 * `timestamp`  — RFC3161 timestamp server URL (`signtool /tr`, paired with
 * `/td <digest>`).
 * `digest`     — file digest algorithm (`signtool /fd`). Default: `'sha256'`.
 *
 * Exactly ONE of `file` or `thumbprint` must be supplied — they identify two
 * different certificate sources and are mutually exclusive. `password`
 * pairs with `file` (a store-resident certificate referenced by
 * `thumbprint` has no associated password to supply here).
 */
export interface SEAWindowsSignOptions {
	readonly file?: string
	readonly password?: string
	readonly thumbprint?: string
	readonly timestamp?: string
	readonly digest?: string
}

/**
 * Represents the result of a successful SEA build.
 *
 * @remarks
 * `executable`  — absolute path to the output binary.
 * `platform`    — platform identifier (e.g. `"win32"`, `"darwin"`).
 * `size`        — file size of the executable in bytes.
 * `duration`    — build time in milliseconds.
 * `compression` — compression manifest when directories were compressed.
 * `signed`      — whether the executable was code-signed.
 * `stripped`    — whether an existing signature was removed before signing.
 * `terminal`    — `true` when a console window is retained, `false` for a
 * GUI-subsystem build; `undefined` on non-Windows platforms.
 */
export interface SEAResult {
	readonly executable: string
	readonly platform: string
	readonly size: number
	readonly duration: number
	readonly compression?: SEACompressionManifest
	readonly signed: boolean
	readonly stripped: boolean
	readonly terminal?: boolean
}

/**
 * Represents a SEA build orchestrator.
 *
 * @remarks
 * Compresses assets, generates the SEA blob, copies the Node binary,
 * injects the blob via the built-in Injector, and handles platform-specific signing.
 */
export interface SEAInterface {
	readonly emitter: EmitterInterface<SEAEventMap>
	readonly status: SEAStatus
	execute(): Promise<SEAResult>
	destroy(): void
}
