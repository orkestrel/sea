// Error for the seal build's shell boundary. `runShell` maps a failed
// `execFileSync` invocation to a typed `ShellError` carrying the captured
// stdout/stderr, so a caller can inspect the process output rather than
// parsing the thrown message.

/**
 * An error thrown when a shell command run via `runShell` exits non-zero.
 *
 * @remarks
 * Carries the captured `stdout` and `stderr` buffers from the failed process.
 * Narrow a caught value with {@link isShellError}.
 */
export class ShellError extends Error {
	readonly stdout: Buffer
	readonly stderr: Buffer

	constructor(message: string, stdout: Buffer, stderr: Buffer) {
		super(message)
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
 */
export function isShellError(value: unknown): value is ShellError {
	return value instanceof ShellError
}
