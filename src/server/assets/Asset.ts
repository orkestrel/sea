/**
 * Asset
 *
 * A single named asset wrapping its key, content buffer, and compression flag.
 * Infers compression from the `.br` extension when not explicitly provided.
 */

import type { AssetInput, AssetInterface } from '../types.js'
import { BROTLI_EXTENSION } from '../constants.js'

// === Asset

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
