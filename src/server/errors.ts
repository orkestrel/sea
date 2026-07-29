import type { SEAErrorCode } from './types.js'

// Error surface for the seal build. `SEAError` is the coded base every
// domain failure throws through, so a caller can branch on `code` rather
// than parsing a message string. `ShellError` specializes it for the shell
// boundary — `runShell` maps a failed `execFileSync` invocation to a
// `ShellError` carrying the captured stdout/stderr, so a caller can inspect
// the process output rather than parsing the thrown message.

/**
 * The coded base error for every failure raised by the seal build.
 *
 * @remarks
 * Carries a machine-readable {@link SEAErrorCode} and optional `context`
 * for structured diagnostics. Narrow a caught value with {@link isSEAError}.
 *
 * @example
 * ```ts
 * try {
 *     seal.execute()
 * } catch (error) {
 *     if (isSEAError(error)) {
 *         console.error(error.code, error.context)
 *     }
 * }
 * ```
 */
export class SEAError extends Error {
	readonly code: SEAErrorCode
	readonly context?: Readonly<Record<string, unknown>>

	constructor(code: SEAErrorCode, message: string, context?: Readonly<Record<string, unknown>>) {
		super(message)
		this.name = 'SEAError'
		this.code = code
		if (context !== undefined) {
			this.context = context
		}
	}
}

/**
 * Whether a value is a {@link SEAError}.
 *
 * @param value - The value to test
 * @returns `true` when `value` is a `SEAError`
 *
 * @example
 * ```ts
 * if (isSEAError(caught)) {
 *     console.error(caught.code)
 * }
 * ```
 */
export function isSEAError(value: unknown): value is SEAError {
	return value instanceof SEAError
}

/**
 * An error thrown when a shell command run via `runShell` exits non-zero.
 *
 * @remarks
 * Carries the captured `stdout` and `stderr` buffers from the failed process.
 * Always carries {@link SEAErrorCode} `'SHELL'`. Narrow a caught value with
 * {@link isShellError}.
 *
 * @example
 * ```ts
 * try {
 *     runShell(['codesign', '--sign', '-', path])
 * } catch (error) {
 *     if (isShellError(error)) {
 *         console.error(error.stderr.toString())
 *     }
 * }
 * ```
 */
export class ShellError extends SEAError {
	readonly stdout: Buffer
	readonly stderr: Buffer

	constructor(message: string, stdout: Buffer, stderr: Buffer) {
		super('SHELL', message)
		this.name = 'ShellError'
		this.stdout = stdout
		this.stderr = stderr
	}
}

/**
 * Whether a value is a {@link ShellError}.
 *
 * @param value - The value to test
 * @returns `true` when `value` is a `ShellError`
 *
 * @example
 * ```ts
 * if (isShellError(caught)) {
 *     console.error(caught.stdout.toString())
 * }
 * ```
 */
export function isShellError(value: unknown): value is ShellError {
	return value instanceof ShellError
}
