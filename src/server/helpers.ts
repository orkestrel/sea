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
	SEAProgressHandler,
	SEAShellOptions,
	SEAWindowsSignOptions,
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
	ftruncateSync,
	fstatSync,
	lstatSync,
} from 'node:fs'
import { brotliCompressSync, constants as zlibConstants } from 'node:zlib'
import { resolve, relative, join, extname, isAbsolute, sep, dirname } from 'node:path'
import { execFileSync, spawn } from 'node:child_process'
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
	// Sort by byte order (not localeCompare, which is locale-dependent) so
	// asset order is deterministic across platforms and Node builds.
	entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))

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
	// Replace the argv element following a `/p`, `-p`, or `--password` flag
	// (case-insensitive) with a redaction marker, so a secret passed as a
	// discrete argv token (e.g. `signtool /p <password>`) can never leak into
	// an error message or SEAError context, regardless of caller.
	function redactCommand(argv: string[]): string[] {
		const secretFlags = new Set(['/p', '-p', '--password'])
		return argv.map((token, index) => {
			const previous = argv[index - 1]
			if (previous !== undefined && secretFlags.has(previous.toLowerCase())) {
				return '***'
			}
			return token
		})
	}

	const [cmd, ...args] = command
	if (cmd === undefined) {
		throw new SEAError('STATE', 'Command array must not be empty')
	}
	if (options?.signal?.aborted === true) {
		throw new SEAError('ABORT', 'Shell command aborted', { command: redactCommand(command) })
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
		const redacted = redactCommand(command)
		const code = 'code' in thrown && typeof thrown.code === 'string' ? thrown.code : undefined
		if (code === 'ETIMEDOUT') {
			throw new SEAError('TIMEOUT', 'Shell command timed out', {
				command: redacted,
				timeout: options?.timeout,
			})
		}
		const stdout =
			'stdout' in thrown && Buffer.isBuffer(thrown.stdout) ? thrown.stdout : Buffer.alloc(0)
		const stderr =
			'stderr' in thrown && Buffer.isBuffer(thrown.stderr) ? thrown.stderr : Buffer.alloc(0)
		throw new ShellError('Command failed: ' + redacted.join(' '), stdout, stderr)
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

	// walkDirectory already skips symlinks on the read side; mirror that here
	// on the write side so a planted symlink at `output` (e.g. `X.br -> /victim`)
	// cannot redirect this write to an arbitrary file.
	let outputStat: ReturnType<typeof lstatSync> | undefined
	try {
		outputStat = lstatSync(output)
	} catch {
		outputStat = undefined
	}
	if (outputStat !== undefined && outputStat.isSymbolicLink()) {
		throw new SEAError('OUTPUT', 'Refusing to write compressed output through a symlink', {
			output,
		})
	}

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
 * @param progress - Optional callback invoked after each file is compressed
 * @returns Compression manifest with all results
 */
export function compressDirectory(
	directory: string,
	options?: SEACompressionOptions,
	progress?: SEAProgressHandler,
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
		progress?.(result)
	}

	return {
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
 * @remarks
 * If the certificate overlay described by the security directory sits at the
 * very end of the file (the common case for `signtool`-signed binaries), the
 * file is truncated to the certificate's start FIRST so the overlay bytes are
 * discarded rather than left as dead weight for a downstream injector to
 * bury mid-file. The directory read is bounds-checked so a malformed or
 * truncated security directory cannot throw unexpectedly — it is simply
 * skipped and only the directory entry is zeroed.
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

		const dirBuf = Buffer.alloc(8)
		const dirRead = readSync(fd, dirBuf, 0, 8, securityDirOffset)
		if (dirRead === 8) {
			const certOffset = dirBuf.readUInt32LE(0)
			const certSize = dirBuf.readUInt32LE(4)
			if (certOffset > 0 && certSize > 0) {
				const fileSize = fstatSync(fd).size
				if (certOffset <= fileSize && certOffset + certSize === fileSize) {
					ftruncateSync(fd, certOffset)
				}
			}
		}

		// Zero out the 8-byte security directory entry (VirtualAddress + Size)
		const zeroes = Buffer.alloc(8)
		writeSync(fd, zeroes, 0, 8, securityDirOffset)
	} finally {
		closeSync(fd)
	}
}

// === Signing Helpers

/**
 * Build the `signtool sign` argv for signing a Windows executable.
 *
 * @remarks
 * Requires EXACTLY ONE certificate source — `sign.file` (a `.pfx`/`.p12`
 * file, paired with `sign.password` when present) XOR `sign.thumbprint` (a
 * certificate already installed in the Windows store). When `sign.timestamp`
 * is set it is parsed with the `URL` constructor and must be an `http:` or
 * `https:` URL. The returned argv is passed directly to `runShell` — never
 * through a shell — so nothing in `sign` can be interpreted as a flag or
 * injected into a command line. `sign.password` is NEVER included in a
 * thrown error's message or `context`.
 *
 * @param sign - Windows signing options
 * @param target - Absolute path to the executable to sign
 * @returns The `signtool` argv, ready for `runShell`
 * @throws SEAError with code `'SIGN'` when neither `file` nor `thumbprint` is set
 * @throws SEAError with code `'SIGN'` when both `file` and `thumbprint` are set
 * @throws SEAError with code `'SIGN'` when `timestamp` is not a parseable http(s) URL
 * @throws SEAError with code `'SIGN'` when `digest` is not `'sha1'`, `'sha256'`, `'sha384'`, or `'sha512'`
 *
 * @example
 * ```ts
 * createSignCommand({ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD' }, 'dist/sea/app.exe')
 * // ['signtool', 'sign', '/fd', 'sha256', '/sha1', 'AABBCCDDEEFF00112233445566778899AABBCCDD', 'dist/sea/app.exe']
 * ```
 */
export function createSignCommand(sign: SEAWindowsSignOptions, target: string): string[] {
	const hasFile = sign.file !== undefined
	const hasThumbprint = sign.thumbprint !== undefined

	if (!hasFile && !hasThumbprint) {
		throw new SEAError(
			'SIGN',
			'Windows signing requires exactly one of sign.file or sign.thumbprint',
		)
	}
	if (hasFile && hasThumbprint) {
		throw new SEAError(
			'SIGN',
			'Windows signing accepts only one of sign.file or sign.thumbprint, not both',
		)
	}

	if (sign.timestamp !== undefined) {
		let parsed: URL
		try {
			parsed = new URL(sign.timestamp)
		} catch {
			throw new SEAError('SIGN', 'Windows signing timestamp must be an http(s) URL', {
				timestamp: sign.timestamp,
			})
		}
		if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
			throw new SEAError('SIGN', 'Windows signing timestamp must be an http(s) URL', {
				timestamp: sign.timestamp,
			})
		}
	}

	const digest = sign.digest ?? 'sha256'
	const supportedDigests = new Set(['sha1', 'sha256', 'sha384', 'sha512'])
	if (!supportedDigests.has(digest)) {
		throw new SEAError('SIGN', 'Unsupported signing digest', { digest: sign.digest })
	}

	return [
		'signtool',
		'sign',
		'/fd',
		digest,
		...(sign.file !== undefined
			? ['/f', sign.file, ...(sign.password !== undefined ? ['/p', sign.password] : [])]
			: []),
		...(sign.thumbprint !== undefined ? ['/sha1', sign.thumbprint] : []),
		...(sign.timestamp !== undefined ? ['/tr', sign.timestamp, '/td', digest] : []),
		target,
	]
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
 * Fsync a directory to durably persist a prior file rename/create within it.
 *
 * @remarks
 * A `rename`/`create` is only durable once its CONTAINING directory entry is
 * flushed — fsyncing the file itself is not enough. `path` is the directory
 * to fsync (callers pass `dirname(target)`, not the file itself). On Windows
 * there is no directory file handle to fsync, so this is a no-op there (the
 * platform lacks the primitive, not a failure). Some filesystems/platforms
 * return a benign errno for a directory fsync attempt (`EINVAL`, `ENOTSUP`,
 * `EISDIR`, `EPERM`, `EACCES`) — those are treated as "fsync unsupported
 * here" and swallowed; anything else (e.g. `ENOENT`, meaning the directory
 * itself is missing) is a genuine failure and is thrown as a coded `SEAError`.
 *
 * @param path - Directory path to fsync
 * @throws SEAError with code `'OUTPUT'` when the directory sync fails for an
 * unrecognized reason
 *
 * @example
 * ```ts
 * syncDirectory('/dist/app/bin')
 * ```
 */
export function syncDirectory(path: string): void {
	// Windows has no directory file handle to fsync — nothing to do there.
	if (process.platform === 'win32') return

	try {
		const fd = openSync(path, 'r')
		try {
			fsyncSync(fd)
		} finally {
			closeSync(fd)
		}
	} catch (thrown: unknown) {
		const code =
			thrown instanceof Error && 'code' in thrown && typeof thrown.code === 'string'
				? thrown.code
				: undefined
		// These codes mean "this filesystem/platform doesn't support directory
		// fsync" — benign and safe to ignore. Anything else (e.g. ENOENT, the
		// directory truly doesn't exist) is a genuine failure.
		if (
			code === 'EINVAL' ||
			code === 'ENOTSUP' ||
			code === 'EISDIR' ||
			code === 'EPERM' ||
			code === 'EACCES'
		) {
			return
		}
		const cause = thrown instanceof Error ? thrown.message : String(thrown)
		throw new SEAError('OUTPUT', 'Failed to sync output directory', { path, cause })
	}
}

/**
 * Finalize a built executable by durably flushing it to disk and atomically
 * moving it into place.
 *
 * @remarks
 * Opens `source` for read/write, `fsync`s it to force the OS to flush buffered
 * writes, closes it, then `rename`s it to `target`. Never deletes `target` on
 * failure — the caller retains whatever was previously there. After the file
 * is already in place, the containing directory is fsynced ({@link syncDirectory})
 * as a further durability step so the rename itself survives a crash.
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
	syncDirectory(dirname(target))
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

// === ELF Helpers

/**
 * Build an ELF `PT_NOTE` entry's header bytes (namesz/descsz/type + padded
 * name) for the SEA blob note, without the blob body itself.
 *
 * @remarks
 * A pure leaf extracted from the ELF injector: the blob body is streamed
 * from disk separately (never buffered here) so this only produces the
 * fixed-size note header and reports the total on-disk size the complete
 * note entry (header + 4-byte-padded blob) will occupy, so the caller can
 * size the covering `PT_LOAD`/`PT_NOTE` segments before writing anything.
 * The Node.js SEA runtime matches a note by the first 8 bytes of its name
 * (`strncmp(name, "NODE_SEA", 8)`), so `resource` is written in full but
 * only needs to begin with those 8 bytes to be found at runtime.
 *
 * @param resource - Note name (SEA resource identifier, e.g. `NODE_SEA_BLOB`)
 * @param blobSize - Size in bytes of the SEA blob that will follow the header
 * @returns The note header bytes and the total on-disk size of header + blob
 *
 * @example
 * ```ts
 * const { header, entryTotal } = buildELFNoteHeader('NODE_SEA_BLOB', 4096)
 * ```
 */
export function buildELFNoteHeader(
	resource: string,
	blobSize: number,
): { readonly header: Buffer; readonly entryTotal: number } {
	const alignTo4 = (value: number): number => {
		const remainder = value % 4
		return remainder === 0 ? value : value + (4 - remainder)
	}

	const nameBytes = Buffer.from(`${resource}\0`, 'utf-8')
	const alignedNameSize = alignTo4(nameBytes.length)

	const header = Buffer.alloc(12 + alignedNameSize)
	header.writeUInt32LE(nameBytes.length, 0) // namesz
	header.writeUInt32LE(blobSize, 4) // descsz
	header.writeUInt32LE(0, 8) // type
	nameBytes.copy(header, 12)

	const alignedDescSize = alignTo4(blobSize)
	return { header, entryTotal: header.length + alignedDescSize }
}

/**
 * Copy a byte range from one open file descriptor to another, streaming in
 * fixed-size chunks instead of buffering the whole range in memory.
 *
 * @remarks
 * Reads `length` bytes from `source` starting at file offset `start`, in
 * `chunk`-sized reads, and writes each chunk to `target` with a `null`
 * write position so writes land sequentially at `target`'s current file
 * position (rather than at `start`, which is meaningless for `target`). A
 * short read from `source` (fewer bytes returned than requested, including
 * `0` before `length` is exhausted) is treated as a genuine failure and
 * throws rather than silently writing a truncated range.
 *
 * @param source - Open, readable file descriptor to copy from
 * @param target - Open, writable file descriptor to copy to
 * @param start - Byte offset in `source` to begin reading from
 * @param length - Number of bytes to copy; `0` is a no-op
 * @param chunk - Read/write chunk size in bytes, for tuning memory use and
 * exercising the streaming loop in tests. Default: 4 MB.
 * @throws SEAError with code `'OUTPUT'` when `source` is exhausted before
 * `length` bytes have been copied
 *
 * @example
 * ```ts
 * const srcFd = openSync('big.bin', 'r')
 * const dstFd = openSync('out.bin', 'w')
 * copyRange(srcFd, dstFd, 1024, 4096)
 * ```
 */
export function copyRange(
	source: number,
	target: number,
	start: number,
	length: number,
	chunk = 4 * 1024 * 1024,
): void {
	if (length <= 0) return

	const bufferSize = Math.min(chunk, length)
	const buffer = Buffer.alloc(bufferSize)
	let position = start
	let remaining = length

	while (remaining > 0) {
		const toRead = Math.min(chunk, remaining)
		const bytesRead = readSync(source, buffer, 0, toRead, position)
		if (bytesRead === 0) {
			throw new SEAError('OUTPUT', 'Unexpected end of file while copying byte range', {
				start,
				length,
				position,
				remaining,
			})
		}
		writeSync(target, buffer, 0, bytesRead, null)
		position += bytesRead
		remaining -= bytesRead
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

// === Runtime Helpers

/**
 * Launch the system default browser at an http(s) URL.
 *
 * @remarks
 * A best-effort launch for bundled local-UI apps: dispatches by
 * `process.platform` (`win32` -> `rundll32 url.dll,FileProtocolHandler`,
 * `darwin` -> `open`, else -> `xdg-open`), each invoked with an argv array
 * (never a shell) so the URL cannot be interpreted as a flag or injected
 * into a command line. The child process is spawned `detached` with
 * `stdio: 'ignore'` and immediately `unref()`d so it never keeps the host
 * app alive. Only `http:` and `https:` URLs are accepted — any other
 * scheme (including a string that merely looks like a CLI flag, e.g.
 * `'-e ...'`) fails to parse as an http(s) URL and is rejected before
 * anything is spawned.
 *
 * @param url - Absolute http or https URL to open
 * @throws SEAError with code `'BROWSER'` when `url` is not a parseable absolute URL
 * @throws SEAError with code `'BROWSER'` when `url` is not an `http:`/`https:` URL
 *
 * @example
 * ```ts
 * openBrowser('http://localhost:3000')
 * ```
 */
export function openBrowser(url: string): void {
	let parsed: URL
	try {
		parsed = new URL(url)
	} catch {
		throw new SEAError('BROWSER', 'openBrowser requires a valid absolute URL', { url })
	}

	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		throw new SEAError('BROWSER', 'openBrowser only supports http and https URLs', {
			url,
			protocol: parsed.protocol,
		})
	}

	const child =
		process.platform === 'win32'
			? spawn('rundll32', ['url.dll,FileProtocolHandler', parsed.href], {
					detached: true,
					stdio: 'ignore',
				})
			: process.platform === 'darwin'
				? spawn('open', [parsed.href], { detached: true, stdio: 'ignore' })
				: spawn('xdg-open', [parsed.href], { detached: true, stdio: 'ignore' })

	// Best-effort launch: if the target browser opener binary is absent, the
	// child emits an async 'error' (ENOENT) event. There is nothing to recover
	// here (unlike the build pipeline, there is no coded failure to surface to
	// a caller who has already returned) — an unhandled 'error' event would
	// otherwise crash the host app, so this is a deliberate, documented no-op.
	child.on('error', () => {})
	child.unref()
}
