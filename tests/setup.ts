// Base test setup — environment-agnostic helpers loaded first by every
// Vitest project (`setupFiles[0]`). Keep this file free of `node:*` and of
// `document` / `window`: node-only helpers live in `setupServer.ts`.
//
// The fleet-wide helpers live in `@orkestrel/test`. What remains here is what
// is specific to this package: asset content encoding.

/**
 * Encodes `text` as UTF-8 into a freshly allocated `ArrayBuffer` — the asset-content shape
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

/** Holds the path published by a scratch allocation callback. */
export class SEAPathFixture {
	#value = ''

	get value(): string {
		return this.#value
	}
	set value(value: string) {
		this.#value = value
	}
}

/** Supplies a class-instance error context. */
export class SEAContextFixture {
	readonly id = 'context'
}

/** Supplies a callable error context. */
export function createCallableSEAContext(): (() => void) & { readonly id: string } {
	return Object.assign(() => {}, { id: 'context' })
}
