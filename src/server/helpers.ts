import type {
	ExecutableFormat,
	SEABlobOptions,
	SEACompressionManifest,
	SEACompressionOptions,
	SEACompressionResult,
	SEACompressionSize,
	SEAEntryOptions,
	SEAErrorCode,
	SEAPlatform,
	SEAShellOptions,
} from './types.js'
import {
	existsSync,
	openSync,
	readSync,
	readdirSync,
	readFileSync,
	realpathSync,
	writeSync,
	closeSync,
	writeFileSync,
	fsyncSync,
	renameSync,
} from 'node:fs'
import { brotliCompressSync, constants as zlibConstants } from 'node:zlib'
import { resolve, relative, join, extname, isAbsolute, sep } from 'node:path'
import { execFileSync } from 'node:child_process'
import {
	BROTLI_EXTENSION,
	DEFAULT_SEA_COMPRESSION_QUALITY,
	SEA_COMPRESSION_MODE_VALUES,
	SEA_PLATFORMS,
	SKIP_EXTENSIONS,
} from './constants.js'
import { SEAError, ShellError } from './errors.js'

// === Type Guards

/**
 * Check if a value is a valid {@link ExecutableFormat}.
 *
 * @param value - Value to check
 * @returns True when value is `'pe'`, `'elf'`, or `'macho'`
 */
export function isExecutableFormat(value: unknown): value is ExecutableFormat {
	return value === 'pe' || value === 'elf' || value === 'macho'
}

// === Platform Helpers

/**
 * Get the platform configuration for the current OS.
 *
 * @param platform - Platform identifier. Default: `process.platform`.
 * @returns Platform configuration, or undefined if unsupported
 */
export function platformConfig(platform?: string): SEAPlatform | undefined {
	return SEA_PLATFORMS[platform ?? process.platform]
}

/**
 * Check if the current or specified platform is supported for SEA builds.
 *
 * @param platform - Platform identifier to check
 * @returns True when the platform has a known configuration
 */
export function isPlatformSupported(platform?: string): boolean {
	return (platform ?? process.platform) in SEA_PLATFORMS
}

// === Filesystem Helpers

/**
 * Assert that a path exists, throwing a coded {@link SEAError} if not.
 *
 * @param path - Absolute or relative path to check
 * @param message - Error message when path is missing
 * @param code - Error code to throw with. Default: `'STATE'`.
 */
export function ensureExists(path: string, message: string, code?: SEAErrorCode): void {
	if (!existsSync(path)) {
		throw new SEAError(code ?? 'STATE', message, { path })
	}
}

/**
 * Check if a file should be Brotli-compressed based on its extension.
 *
 * @param path - Path to the file
 * @returns True when the file type benefits from compression
 */
export function isCompressible(path: string): boolean {
	const ext = extname(path).toLowerCase()
	return !SKIP_EXTENSIONS.has(ext)
}

/**
 * Recursively walk a directory and return all file paths.
 *
 * @param directory - Directory to walk
 * @param base - Base directory for relative path calculation
 * @returns Array of relative file paths
 */
export function walkDirectory(directory: string, base?: string): readonly string[] {
	const root = base ?? directory
	const result: string[] = []
	const entries = readdirSync(directory, { withFileTypes: true })

	for (const entry of entries) {
		// Symlinks can escape the compression root (point outside `directory`),
		// which would make the walk non-deterministic across platforms/filesystems.
		if (entry.isSymbolicLink()) continue
		const fullPath = join(directory, entry.name)
		if (entry.isDirectory()) {
			result.push(...walkDirectory(fullPath, root))
		} else if (entry.isFile()) {
			result.push(relative(root, fullPath))
		}
	}

	return result
}

// === Shell Helpers

/**
 * Run a command synchronously and return stdout.
 *
 * @param command - Command to execute (first element is the binary)
 * @param options - Shell options (cwd, env, timeout, signal)
 * @returns stdout as a Buffer
 * @throws SEAError with code `'STATE'` when `command` is empty
 * @throws SEAError with code `'ABORT'` when `options.signal` is already aborted
 * @throws SEAError with code `'TIMEOUT'` when the command exceeds `options.timeout`
 * @throws ShellError when the command exits with non-zero status
 */
export function runShell(command: string[], options?: SEAShellOptions): Buffer {
	const [cmd, ...args] = command
	if (cmd === undefined) {
		throw new SEAError('STATE', 'Command array must not be empty')
	}
	if (options?.signal?.aborted === true) {
		throw new SEAError('ABORT', 'Shell command aborted', { command })
	}
	// Node v22+ blocks direct execFileSync of .cmd/.bat files without a shell (EINVAL)
	const useShell = cmd.endsWith('.cmd') || cmd.endsWith('.bat')
	try {
		return execFileSync(cmd, args, {
			cwd: options?.cwd,
			env: options?.env !== undefined ? { ...process.env, ...options.env } : undefined,
			stdio: ['pipe', 'pipe', 'pipe'],
			shell: useShell,
			timeout: options?.timeout,
		})
	} catch (thrown: unknown) {
		if (!(thrown instanceof Error)) {
			throw thrown
		}
		const code = 'code' in thrown && typeof thrown.code === 'string' ? thrown.code : undefined
		if (code === 'ETIMEDOUT') {
			throw new SEAError('TIMEOUT', 'Shell command timed out', {
				command,
				timeout: options?.timeout,
			})
		}
		const stdout =
			'stdout' in thrown && Buffer.isBuffer(thrown.stdout) ? thrown.stdout : Buffer.alloc(0)
		const stderr =
			'stderr' in thrown && Buffer.isBuffer(thrown.stderr) ? thrown.stderr : Buffer.alloc(0)
		throw new ShellError(thrown.message, stdout, stderr)
	}
}

// === Compression Helpers

/**
 * Compute a size comparison between original and compressed byte counts.
 *
 * @param original - Original byte count
 * @param compressed - Compressed byte count
 * @returns SEACompressionSize with ratio
 */
export function computeSize(original: number, compressed: number): SEACompressionSize {
	const ratio = original > 0 ? compressed / original : 0
	return { original, compressed, ratio }
}

/**
 * Brotli-compress a single file, writing the output alongside it.
 *
 * @param input - Absolute path to the source file
 * @param output - Absolute path for the compressed output
 * @param options - Compression options (quality, mode)
 * @returns Compression result with size comparison
 */
export function compressFile(
	input: string,
	output: string,
	options?: SEACompressionOptions,
): SEACompressionResult {
	const quality = options?.quality ?? DEFAULT_SEA_COMPRESSION_QUALITY
	const mode = SEA_COMPRESSION_MODE_VALUES[options?.mode ?? 'generic']

	const raw = readFileSync(input)
	const compressed = brotliCompressSync(raw, {
		params: {
			[zlibConstants.BROTLI_PARAM_QUALITY]: quality,
			[zlibConstants.BROTLI_PARAM_MODE]: mode,
		},
	})

	writeFileSync(output, compressed)

	return {
		input,
		output,
		size: computeSize(raw.length, compressed.length),
	}
}

/**
 * Compress all compressible files in a directory tree.
 *
 * @param directory - Absolute path to the directory
 * @param options - Compression options
 * @returns Compression manifest with all results
 */
export function compressDirectory(
	directory: string,
	options?: SEACompressionOptions,
): SEACompressionManifest {
	const files = walkDirectory(directory)
	const results: SEACompressionResult[] = []
	let totalOriginal = 0
	let totalCompressed = 0

	for (const relativePath of files) {
		const fullPath = resolve(directory, relativePath)
		if (!isCompressible(fullPath)) continue

		const outputPath = fullPath + BROTLI_EXTENSION
		const result = compressFile(fullPath, outputPath, options)
		results.push(result)
		totalOriginal += result.size.original
		totalCompressed += result.size.compressed
	}

	return {
		timestamp: new Date().toISOString(),
		assets: results,
		total: computeSize(totalOriginal, totalCompressed),
	}
}

// === PE Helpers

/**
 * Parse the PE header offset from a Windows executable.
 *
 * @param fd - Open file descriptor
 * @returns The offset to the PE signature
 */
export function parsePEOffset(fd: number): number {
	const buf = Buffer.alloc(4)
	readSync(fd, buf, 0, 4, 0x3c)
	return buf.readUInt32LE(0)
}

/**
 * Read a 16-bit unsigned integer from a file descriptor.
 *
 * @param fd - Open file descriptor
 * @param offset - Byte offset to read from
 * @returns The 16-bit value
 */
export function readU16(fd: number, offset: number): number {
	const buf = Buffer.alloc(2)
	readSync(fd, buf, 0, 2, offset)
	return buf.readUInt16LE(0)
}

/**
 * Write a 16-bit unsigned integer to a file descriptor.
 *
 * @param fd - Open file descriptor
 * @param offset - Byte offset to write at
 * @param value - The 16-bit value to write
 */
export function writeU16(fd: number, offset: number, value: number): void {
	const buf = Buffer.alloc(2)
	buf.writeUInt16LE(value, 0)
	writeSync(fd, buf, 0, 2, offset)
}

/**
 * Check if a file is a Windows PE executable.
 *
 * @param path - Path to the file
 * @returns True when the file has a valid PE signature
 */
export function isPEExecutable(path: string): boolean {
	let fd: number | undefined
	try {
		fd = openSync(path, 'r')
		const peOffset = parsePEOffset(fd)
		const sig = Buffer.alloc(4)
		readSync(fd, sig, 0, 4, peOffset)
		return sig.toString('ascii') === 'PE\0\0'
	} catch {
		return false
	} finally {
		if (fd !== undefined) closeSync(fd)
	}
}

/**
 * Patch the PE subsystem field in a Windows executable.
 *
 * @param path - Path to the executable
 * @param subsystem - Numeric subsystem value (2 = GUI, 3 = Console)
 */
export function patchPESubsystem(path: string, subsystem: number): void {
	const fd = openSync(path, 'r+')
	try {
		const peOffset = parsePEOffset(fd)
		// Subsystem field is at PE offset + 0x5C (in the Optional Header)
		writeU16(fd, peOffset + 0x5c, subsystem)
	} finally {
		closeSync(fd)
	}
}

/**
 * Remove the Authenticode signature from a PE executable by zeroing
 * the security directory entry in the optional header.
 *
 * @param path - Path to the executable
 */
export function stripPESignature(path: string): void {
	const fd = openSync(path, 'r+')
	try {
		const peOffset = parsePEOffset(fd)
		// COFF header: 24 bytes from PE signature
		// Optional header magic at peOffset + 24
		const magic = readU16(fd, peOffset + 24)
		// PE32+ has security dir at different offset than PE32
		const securityDirOffset = magic === 0x20b ? peOffset + 168 : peOffset + 152
		// Zero out the 8-byte security directory entry (VirtualAddress + Size)
		const zeroes = Buffer.alloc(8)
		writeSync(fd, zeroes, 0, 8, securityDirOffset)
	} finally {
		closeSync(fd)
	}
}

// === Formatting Helpers

/**
 * Format a byte count as a human-readable string.
 *
 * @param bytes - Byte count
 * @returns Formatted string (e.g. `"1.23 MB"`, `"456 KB"`)
 */
export function formatSize(bytes: number): string {
	if (bytes < 1024) return `${String(bytes)} B`
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
	return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/**
 * Assert that an asset key is safe to use as a relative filesystem/archive key.
 *
 * @remarks
 * Rejects an empty key, an absolute path, a key containing a backslash, a
 * Windows drive-relative specifier (e.g. `'C:foo'`), or any `/`-separated
 * segment equal to `'..'` — all of which could escape the intended asset root.
 *
 * @param key - Asset key to validate
 * @throws SEAError with code `'ASSET'` when the key is unsafe
 *
 * @example
 * ```ts
 * ensureSafeKey('client.html.br') // ok
 * ensureSafeKey('../secrets') // throws SEAError('ASSET', ...)
 * ensureSafeKey('C:foo') // throws SEAError('ASSET', ...)
 * ```
 */
export function ensureSafeKey(key: string): void {
	if (key.length === 0) {
		throw new SEAError('ASSET', 'Asset key must not be empty', { key })
	}
	if (isAbsolute(key)) {
		throw new SEAError('ASSET', 'Asset key must not be an absolute path', { key })
	}
	if (key.includes('\\')) {
		throw new SEAError('ASSET', 'Asset key must not contain a backslash', { key })
	}
	if (/^[A-Za-z]:/.test(key)) {
		throw new SEAError('ASSET', 'Asset key must not be a drive-relative specifier', { key })
	}
	if (key.split('/').includes('..')) {
		throw new SEAError('ASSET', 'Asset key must not contain a ".." segment', { key })
	}
}

/**
 * Assert that `path` (resolved against `base`) real-path-resolves to a
 * location inside `base`, defeating a symlink escape.
 *
 * @remarks
 * Resolves `path` against `base`, then dereferences both the resolved path
 * and `base` with `realpathSync` and requires the real resolved path to
 * equal the real base or begin with the real base plus a path separator.
 * Dereferencing BOTH sides means a symlinked base itself (e.g. macOS `/tmp`
 * -> `/private/tmp`) still matches, while a symlink inside the tree that
 * points outside the real base is correctly rejected. A `realpathSync`
 * failure (e.g. `ENOENT`) is wrapped as a coded `SEAError` rather than
 * leaking the raw Node error.
 *
 * @param base - Absolute path to the containing root
 * @param path - Path to validate, resolved against `base` if relative
 * @returns The real (symlink-resolved) contained path
 * @throws SEAError with code `'ASSET'` when the real path escapes `base`
 * @throws SEAError with code `'ASSET'` when the path cannot be resolved
 *
 * @example
 * ```ts
 * ensureContained('/dist/app', 'browser') // '/dist/app/browser' (real path)
 * ensureContained('/dist/app', '../../etc') // throws SEAError('ASSET', ...)
 * ```
 */
export function ensureContained(base: string, path: string): string {
	const resolved = resolve(base, path)

	let real: string
	let realBase: string
	try {
		real = realpathSync(resolved)
		realBase = realpathSync(base)
	} catch (thrown: unknown) {
		const cause = thrown instanceof Error ? thrown.message : String(thrown)
		throw new SEAError('ASSET', 'Path not found or unresolvable', { path, cause })
	}

	if (real !== realBase && !real.startsWith(realBase + sep)) {
		throw new SEAError('ASSET', 'Path escapes the build root', { base, path })
	}

	return real
}

/**
 * Assert that `name` is a single safe path segment suitable as an output
 * executable base name.
 *
 * @remarks
 * Rejects an empty name, `'.'`, `'..'`, a name containing a `/` or `\`
 * separator, an absolute path, or a Windows drive-relative specifier (e.g.
 * `'C:foo'`) — all of which could redirect the output executable outside
 * the intended output directory.
 *
 * @param name - Output executable base name to validate
 * @throws SEAError with code `'ASSET'` when the name is unsafe
 *
 * @example
 * ```ts
 * ensureSafeName('myapp') // ok
 * ensureSafeName('../evil') // throws SEAError('ASSET', ...)
 * ```
 */
export function ensureSafeName(name: string): void {
	if (name.length === 0 || name === '.' || name === '..') {
		throw new SEAError('ASSET', 'Executable name must be a single path segment', { name })
	}
	if (name.includes('/') || name.includes('\\')) {
		throw new SEAError('ASSET', 'Executable name must not contain a path separator', { name })
	}
	if (isAbsolute(name)) {
		throw new SEAError('ASSET', 'Executable name must not be an absolute path', { name })
	}
	if (/^[A-Za-z]:/.test(name)) {
		throw new SEAError('ASSET', 'Executable name must not be a drive-relative specifier', {
			name,
		})
	}
}

/**
 * Finalize a built executable by durably flushing it to disk and atomically
 * moving it into place.
 *
 * @remarks
 * Opens `source` for read/write, `fsync`s it to force the OS to flush buffered
 * writes, closes it, then `rename`s it to `target`. Never deletes `target` on
 * failure — the caller retains whatever was previously there.
 *
 * @param source - Absolute path to the built (temporary) executable
 * @param target - Absolute path to move the finalized executable to
 * @throws SEAError with code `'OUTPUT'` when any step fails
 *
 * @example
 * ```ts
 * finalizeExecutable('/tmp/build/app.tmp', '/dist/app')
 * ```
 */
export function finalizeExecutable(source: string, target: string): void {
	try {
		const fd = openSync(source, 'r+')
		try {
			fsyncSync(fd)
		} finally {
			closeSync(fd)
		}
		renameSync(source, target)
	} catch (thrown: unknown) {
		const cause = thrown instanceof Error ? thrown.message : String(thrown)
		throw new SEAError('OUTPUT', 'Failed to finalize executable', { source, target, cause })
	}
}

/**
 * Build the Node.js `--experimental-sea-config` JSON object for a SEA blob.
 *
 * @remarks
 * A pure leaf extracted from the SEA build orchestrator. The `mainFormat`
 * field (`'commonjs' | 'module'`) exists only in Node >= 25.7 — for a `'cjs'`
 * entry (the default) `mainFormat` is OMITTED entirely so the config still
 * builds on older Node hosts where `'commonjs'` is already the implicit
 * default; for an `'esm'` entry `mainFormat: 'module'` is set explicitly
 * (this requires a Node >= 25.7 build host). Node also documents that
 * `useSnapshot` is incompatible with an ESM entry — combining the two throws.
 *
 * @param entry - SEA entry point options
 * @param blob - Absolute output path for the generated blob
 * @param assets - Optional key→path mapping for embedded assets
 * @param options - Optional blob behavior overrides (cache, snapshot)
 * @returns the SEA config object, ready to be written to disk as JSON
 * @throws SEAError with code `'BLOB'` when `useSnapshot` is combined with an ESM entry
 *
 * @example
 * ```ts
 * const config = createBlobConfig({ path: 'dist/bin/serve.cjs' }, 'dist/bin/sea-prep.blob', undefined)
 * ```
 */
export function createBlobConfig(
	entry: SEAEntryOptions,
	blob: string,
	assets: Readonly<Record<string, string>> | undefined,
	options?: SEABlobOptions,
): Readonly<Record<string, unknown>> {
	const format = entry.format ?? 'cjs'
	const snapshot = options?.snapshot ?? false

	if (format === 'esm' && snapshot) {
		throw new SEAError(
			'BLOB',
			'useSnapshot cannot be combined with an ESM entry (mainFormat module)',
		)
	}

	return {
		main: entry.path,
		output: blob,
		disableExperimentalSEAWarning: true,
		useSnapshot: snapshot,
		useCodeCache: options?.cache ?? true,
		...(assets ? { assets } : {}),
		...(format === 'esm' ? { mainFormat: 'module' } : {}),
	}
}

// === SEA Helpers

/**
 * Patch the sentinel fuse in a binary from `:0` to `:1`.
 *
 * Searches the file in 64 MB chunks with overlap to handle any file size.
 * The fuse signals to the Node.js runtime that a SEA blob is present.
 * This is normally handled by the Injector but is also available standalone
 * when using native PE resource injection.
 *
 * @param executable - Absolute path to the executable
 * @param fuse - Sentinel fuse string (without the `:0` suffix)
 */
export function patchSentinelFuse(executable: string, fuse: string): void {
	const fd = openSync(executable, 'r+')
	try {
		const needle = Buffer.from(fuse, 'utf-8')
		const chunkSize = 64 * 1024 * 1024 // 64 MB
		const readSize = chunkSize + needle.length
		const buffer = Buffer.alloc(readSize)

		let offset = 0
		while (true) {
			const bytesRead = readSync(fd, buffer, 0, readSize, offset)
			if (bytesRead === 0) break

			const chunk = buffer.subarray(0, bytesRead)
			const idx = chunk.indexOf(needle)

			if (idx !== -1) {
				const fuseEnd = offset + idx + needle.length
				const valueBuf = Buffer.alloc(2)
				const valueRead = readSync(fd, valueBuf, 0, 2, fuseEnd)

				if (valueRead < 2) {
					throw new SEAError('FUSE', 'Could not read sentinel fuse value', { executable, fuse })
				}

				const value = valueBuf.toString('utf-8')

				if (value === ':0') {
					writeSync(fd, Buffer.from('1', 'utf-8'), 0, 1, fuseEnd + 1)
					return
				}

				if (value === ':1') {
					return // Already patched
				}

				throw new SEAError('FUSE', `Unexpected sentinel fuse value: ${value}`, {
					executable,
					fuse,
				})
			}

			offset += chunkSize
		}

		throw new SEAError('FUSE', `Sentinel fuse not found in executable: ${fuse}`, {
			executable,
			fuse,
		})
	} finally {
		closeSync(fd)
	}
}
