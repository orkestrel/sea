import type { EmitterErrorHandler, EmitterHooks, EmitterInterface } from '@orkestrel/emitter'

// === Compression

/**
 * Size comparison between original and compressed data.
 */
export interface SEACompressionSize {
	readonly original: number
	readonly compressed: number
	readonly ratio: number
}

/**
 * Brotli compression mode.
 *
 * @remarks
 * `generic` — general-purpose data (Brotli mode 0).
 * `text`    — UTF-8 text (Brotli mode 1).
 * `font`    — WOFF2 font data (Brotli mode 2).
 */
export type SEACompressionMode = 'generic' | 'text' | 'font'

/**
 * Result of compressing a single file.
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
 * Manifest summarizing all compressed assets.
 *
 * @remarks
 * Generated after a full directory compression pass.
 */
export interface SEACompressionManifest {
	readonly assets: readonly SEACompressionResult[]
	readonly total: SEACompressionSize
}

/**
 * Progress reported while compressing a directory.
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
 * Callback invoked by the framework after each file is compressed.
 */
export type SEAProgressHandler = (result: SEACompressionResult) => void

/**
 * Options controlling Brotli compression of one or more directories.
 *
 * @remarks
 * `paths`   — directories (relative to `SEAOptions.root`) to compress.
 * `mode`    — Brotli mode. Default: `'generic'`.
 * `quality` — Brotli quality level (0–11). Default: 11.
 */
export interface SEACompressionOptions {
	readonly paths: readonly string[]
	readonly mode?: SEACompressionMode
	readonly quality?: number
}

// === Platform

/**
 * Platform-specific SEA build configuration.
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
 * Options for running a shell command.
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
 * Executable binary format detected from file header magic bytes.
 */
export type ExecutableFormat = 'pe' | 'elf' | 'macho'

/**
 * Options for injecting a resource into an executable.
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
 * Mach-O specific injector options.
 *
 * @remarks
 * `segment` — Mach-O segment name. Default: `"NODE_SEA"`.
 */
export interface InjectorMachOOptions {
	readonly segment?: string
}

/**
 * Cross-platform binary resource injector.
 *
 * @remarks
 * Injects arbitrary data into PE (Windows), ELF (Linux), and Mach-O (macOS)
 * executables using streaming file I/O. No WASM or external tools required.
 */
export interface InjectorInterface {
	/** Detected executable format of the target binary. */
	readonly format: ExecutableFormat
	/** Inject the resource data into the executable. */
	inject(): void
}

// === Asset

/**
 * Minimal data needed to create an {@link AssetInterface}.
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
 * A single named asset wrapping its key, content buffer, and compression flag.
 */
export interface AssetInterface {
	readonly key: string
	readonly content: ArrayBuffer
	readonly compressed: boolean
}

/** Events emitted by an {@link AssetManagerInterface}. */
export type AssetManagerEventMap = {
	readonly register: readonly [asset: AssetInterface]
	readonly load: readonly [keys: readonly string[]]
	readonly clear: readonly []
	readonly error: readonly [error: unknown]
}

/**
 * Options for creating an {@link AssetManagerInterface}.
 *
 * @remarks
 * `root` — project root used to resolve on-disk client assets. Default: `process.cwd()`.
 */
export interface AssetManagerOptions {
	readonly on?: EmitterHooks<AssetManagerEventMap>
	readonly error?: EmitterErrorHandler
	readonly root?: string
}

/**
 * Named asset collection with SEA and disk loading.
 *
 * @remarks
 * In SEA mode, embedded assets are loaded automatically at construction.
 * Outside SEA, `load()` reads client assets from disk.
 */
export interface AssetManagerInterface {
	readonly emitter: EmitterInterface<AssetManagerEventMap>
	readonly count: number
	asset(key: string): AssetInterface | undefined
	assets(): readonly AssetInterface[]
	keys(): readonly string[]
	register(input: AssetInput | AssetInput[]): void
	load(): void
	clear(): void
	destroy(): void
}

// === SEA

/**
 * Overall status of the seal build.
 */
export type SEAStatus = 'idle' | 'active' | 'done' | 'error'

/**
 * Machine-readable error code carried by every {@link SEAError}.
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
 * SEA entry point module format.
 *
 * @remarks
 * `cjs` — CommonJS entry (Node default).
 * `esm` — ECMAScript module entry (requires Node >= 25.7).
 */
export type SEAEntryFormat = 'cjs' | 'esm'

/**
 * Options describing the SEA entry point.
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
 * Options controlling generated SEA blob behavior.
 *
 * @remarks
 * `cache`    — maps to the SEA config `useCodeCache`. Default: `true`.
 * `snapshot` — maps to the SEA config `useSnapshot`. Default: `false`.
 */
export interface SEABlobOptions {
	readonly cache?: boolean
	readonly snapshot?: boolean
}

/** Events emitted by a {@link SEAInterface}. */
export type SEAEventMap = {
	readonly compress: readonly [compression: SEACompressionManifest | undefined]
	readonly progress: readonly [progress: SEAProgress]
	readonly blob: readonly [blob: string]
	readonly assemble: readonly [executable: string]
	readonly complete: readonly [result: SEAResult]
	readonly error: readonly [error: unknown]
}

/**
 * Options for creating a SEA build.
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
 * Windows-specific SEA build options.
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
 * and `SEAResult.signed` is `false` (unchanged default behavior).
 *
 * These options apply only when the build HOST is Windows — there is no
 * cross-compilation, so building on a non-Windows host ignores `windows.*`.
 */
export interface SEAWindowsOptions {
	readonly terminal?: boolean
	readonly sign?: SEAWindowsSignOptions
}

/**
 * Windows Authenticode signing options, passed through to `signtool`.
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
 * Result of a successful seal build.
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
 * SEA build orchestrator.
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
