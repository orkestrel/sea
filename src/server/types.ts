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
 * Input describing a single file to Brotli-compress.
 *
 * @remarks
 * `input`  — absolute path to the original file.
 * `output` — absolute path for the compressed output.
 */
export interface SEACompressionInput {
	readonly input: string
	readonly output: string
}

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
 * `timestamp` is the ISO 8601 timestamp.
 */
export interface SEACompressionManifest {
	readonly timestamp: string
	readonly assets: readonly SEACompressionResult[]
	readonly total: SEACompressionSize
}

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
}

/**
 * Windows PE subsystem identifier.
 *
 * @remarks
 * `console` — console subsystem (shows terminal window).
 * `gui`     — Windows GUI subsystem (no terminal window).
 */
export type WindowsSubsystem = 'console' | 'gui'

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
	register: readonly [asset: AssetInterface]
	load: readonly [keys: readonly string[]]
	clear: readonly []
	error: readonly [error: unknown]
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

/** Events emitted by a {@link SEAInterface}. */
export type SEAEventMap = {
	compress: readonly [compression: SEACompressionManifest | undefined]
	blob: readonly [blob: string]
	assemble: readonly [executable: string]
	complete: readonly [result: SEAResult]
	error: readonly [error: unknown]
}

/**
 * Options for creating a SEA build.
 *
 * @remarks
 * `name`        — output executable name (no extension).
 * `entry`       — path to the CJS entry point to embed.
 * `output`      — directory for the final executable.
 * `assets`      — key→path mapping for SEA embedded assets.
 * `compression` — directories to Brotli-compress before embedding.
 * `windows`     — Windows-specific build options (PE subsystem).
 * `root`        — project root directory. Default: `process.cwd()`.
 */
export interface SEAOptions {
	readonly on?: EmitterHooks<SEAEventMap>
	readonly error?: EmitterErrorHandler
	readonly name: string
	readonly entry: string
	readonly output: string
	readonly assets?: Readonly<Record<string, string>>
	readonly compression?: SEACompressionOptions
	readonly windows?: SEAWindowsOptions
	readonly root?: string
}

/**
 * Windows-specific SEA build options.
 *
 * @remarks
 * `subsystem` — Windows PE subsystem to patch onto the output executable.
 */
export interface SEAWindowsOptions {
	readonly subsystem?: WindowsSubsystem
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
 */
export interface SEAResult {
	readonly executable: string
	readonly platform: string
	readonly size: number
	readonly duration: number
	readonly compression?: SEACompressionManifest
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
