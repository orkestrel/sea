import type { AssetInput, AssetInterface } from '../types.js'
import { BROTLI_EXTENSION } from '../constants.js'

/**
 * Holds one named asset's key, bytes, and compression state.
 *
 * @remarks
 * `compressed` is inferred from a `.br` suffix on the key whenever the input
 * leaves it unset, so a Brotli output registered under its own name reports itself
 * correctly without the caller restating it.
 *
 * @param input - The asset's key, content bytes, and optional compression flag
 *
 * @example
 * ```ts
 * const asset = new Asset({ key: 'client.html.br', content: compressedBuffer })
 * asset.key // 'client.html.br'
 * asset.compressed // true
 * ```
 */
export class Asset implements AssetInterface {
	readonly key: string
	readonly content: ArrayBuffer
	readonly compressed: boolean

	constructor(input: AssetInput) {
		this.key = input.key
		this.content = input.content
		this.compressed = input.compressed ?? input.key.endsWith(BROTLI_EXTENSION)
	}
}
