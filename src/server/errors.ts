import type { SEAErrorCode } from './types.js'
import { holds, INTRINSICS, isError, isFunction, isObject } from '@orkestrel/contract'

// Error surface for the SEA build. `SEAError` is the coded base every
// domain failure throws through, so a caller can branch on `code` rather
// than parsing a message string. `ShellError` specializes it for the shell
// boundary — `executeShell` maps a failed `executeSync` invocation to a
// `ShellError` carrying the captured stdout/stderr, so a caller can inspect
// the process output rather than parsing the thrown message.

/**
 * Represents the coded base error for every failure raised by the SEA build.
 *
 * @remarks
 * Carries a machine-readable {@link SEAErrorCode} and optional `context`
 * for structured diagnostics. Narrow a caught value with {@link isSEAError}.
 *
 * @example
 * ```ts
 * try {
 *     sea.execute()
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
		INTRINSICS.define(this, Symbol.for('@orkestrel/sea.SEAError'), { value: this })
		this.name = 'SEAError'
		this.code = code
		if (context !== undefined) {
			this.context = context
		}
	}
}

/**
 * Checks whether a value is a {@link SEAError}.
 *
 * @remarks
 * Recognizes branded errors across package copies, including subclasses, and refuses transparent proxies.
 *
 * @param value - The value to test
 * @returns True if `value` is a `SEAError`; false otherwise
 *
 * @example
 * ```ts
 * if (isSEAError(caught)) {
 *     console.error(caught.code)
 * }
 * ```
 */
export function isSEAError(value: unknown): value is SEAError {
	return holds(() => {
		if (!isError(value) || INTRINSICS.prototype(value) === Error.prototype) return false
		const brand = INTRINSICS.describe(value, Symbol.for('@orkestrel/sea.SEAError'))
		if (brand === undefined || brand.value !== value) return false
		const code: unknown = INTRINSICS.reflect.read(value, 'code')
		if (
			code !== 'PLATFORM' &&
			code !== 'ENTRY' &&
			code !== 'ASSET' &&
			code !== 'BLOB' &&
			code !== 'FORMAT' &&
			code !== 'INJECT' &&
			code !== 'ROOM' &&
			code !== 'FUSE' &&
			code !== 'SIGN' &&
			code !== 'SHELL' &&
			code !== 'TIMEOUT' &&
			code !== 'ABORT' &&
			code !== 'OUTPUT' &&
			code !== 'STATE' &&
			code !== 'BROWSER'
		)
			return false
		const context: unknown = INTRINSICS.reflect.read(value, 'context')
		return context === undefined || isObject(context) || isFunction(context)
	})
}

/**
 * Represents an error thrown when a shell command executed through `executeShell` exits non-zero.
 *
 * @remarks
 * Carries the captured `stdout` and `stderr` buffers from the failed process.
 * Always carries {@link SEAErrorCode} `'SHELL'`. Narrow a caught value with
 * {@link isShellError}.
 *
 * @example
 * ```ts
 * try {
 *     executeShell(['codesign', '--sign', '-', path])
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
		INTRINSICS.define(this, Symbol.for('@orkestrel/sea.ShellError'), { value: this })
		this.name = 'ShellError'
		this.stdout = stdout
		this.stderr = stderr
	}
}

/**
 * Checks whether a value is a {@link ShellError}.
 *
 * @remarks
 * Recognizes branded errors across package copies, including subclasses, and refuses transparent proxies.
 *
 * @param value - The value to test
 * @returns True if `value` is a `ShellError`; false otherwise
 *
 * @example
 * ```ts
 * if (isShellError(caught)) {
 *     console.error(caught.stdout.toString())
 * }
 * ```
 */
export function isShellError(value: unknown): value is ShellError {
	return holds(() => {
		if (!isSEAError(value)) return false
		const brand = INTRINSICS.describe(value, Symbol.for('@orkestrel/sea.ShellError'))
		return (
			brand !== undefined &&
			brand.value === value &&
			Buffer.isBuffer(INTRINSICS.reflect.read(value, 'stdout')) &&
			Buffer.isBuffer(INTRINSICS.reflect.read(value, 'stderr'))
		)
	})
}
