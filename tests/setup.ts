// Base test setup — environment-agnostic helpers loaded first by every
// Vitest project (`setupFiles[0]`). Keep this file free of `node:*` and of
// `document` / `window`: node-only helpers live in `setupServer.ts`.

/**
 * Run `thunk` and return the value it threw, or `undefined` if it returned normally — the
 * one shared form of the `try { …; return undefined } catch (error) { return error }` IIFE
 * the error-path tests repeat (AGENTS §16.1). Lets a caller assert on the captured fault
 * unconditionally, never inside a conditional `expect` — e.g. `errorCode(captureError(() =>
 * …))` (where `errorCode` lives in the env-specific setup). For a synchronous throw site; an
 * async rejection is asserted with `await expect(…).rejects` instead.
 *
 * @param thunk - The (synchronous) operation to run and capture the throw of
 * @returns The thrown value, or `undefined` when `thunk` did not throw
 */
export function captureError(thunk: () => unknown): unknown {
	try {
		thunk()
		return undefined
	} catch (error) {
		return error
	}
}

/**
 * Encode `text` as UTF-8 into a freshly allocated `ArrayBuffer` — the asset-content shape
 * `Asset` and `AssetManager` accept. `TextEncoder` returns a view over a buffer the type
 * system knows only as `ArrayBufferLike`, so the bytes are copied into an owned
 * `ArrayBuffer` instead of asserted onto one (AGENTS: never use type assertions).
 *
 * @param text - The string to encode
 * @returns An `ArrayBuffer` holding the UTF-8 bytes of `text`
 */
export function encodeContent(text: string): ArrayBuffer {
	const bytes = new TextEncoder().encode(text)
	const content = new ArrayBuffer(bytes.byteLength)
	new Uint8Array(content).set(bytes)
	return content
}

/** Whether a repository-relative Vue SFC path belongs to the private browser application. */
export function isBrowserVuePath(path: string): boolean {
	const normalized = path.replaceAll('\\', '/')
	return normalized.startsWith('app/browser/')
}
