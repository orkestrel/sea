// Proves the behavior `tests/setup.ts` exports for this workspace's suites. Expected bytes are
// written as literals and read back with `TextDecoder`, so no assertion here travels the module's
// own `TextEncoder` route. The asset suites consume the result as `Asset` and `AssetManager`
// content, so exact sizing and real `ArrayBuffer` identity are the contracts, not the encoding call.

import { describe, expect, it } from 'vitest'
import { encodeContent } from './setup.js'

describe('setup', () => {
	describe('encodeContent', () => {
		it('encodes text as its UTF-8 bytes', () => {
			// 'n' is one byte, 'é' is 0xc3 0xa9, and '€' is 0xe2 0x82 0xac.
			const content = encodeContent('né€')

			expect([...new Uint8Array(content)]).toEqual([0x6e, 0xc3, 0xa9, 0xe2, 0x82, 0xac])
			expect(new TextDecoder().decode(content)).toBe('né€')
		})

		it('returns an owned ArrayBuffer sized exactly to the encoded bytes', () => {
			const content = encodeContent('né€')

			expect(content).toBeInstanceOf(ArrayBuffer)
			expect(content.byteLength).toBe(6)
			expect(encodeContent('').byteLength).toBe(0)
		})
	})
})
