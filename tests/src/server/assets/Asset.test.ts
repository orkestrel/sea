import { describe, expect, it } from 'vitest'
import { Asset } from '@scsr/server'

describe('Asset', () => {
	it('stores key and content from input', () => {
		const content = new TextEncoder().encode('hello').buffer as ArrayBuffer
		const asset = new Asset({ key: 'test.txt', content })

		expect(asset.key).toBe('test.txt')
		expect(new Uint8Array(asset.content)).toEqual(new TextEncoder().encode('hello'))
	})

	it('infers compressed true from .br extension', () => {
		const content = new ArrayBuffer(4)
		const asset = new Asset({ key: 'app.html.br', content })

		expect(asset.compressed).toBe(true)
	})

	it('infers compressed false for non-.br keys', () => {
		const content = new ArrayBuffer(4)
		const asset = new Asset({ key: 'app.html', content })

		expect(asset.compressed).toBe(false)
	})

	it('respects explicit compressed flag', () => {
		const content = new ArrayBuffer(4)
		const asset = new Asset({ key: 'app.html', content, compressed: true })

		expect(asset.compressed).toBe(true)
	})
})
