import { describe, expect, it } from 'vitest'
import { AssetManager } from '@src/server'

describe('AssetManager', () => {
	// === count / assets / keys

	it('starts with zero assets', () => {
		const manager = new AssetManager()

		expect(manager.count).toBe(0)
		expect(manager.assets()).toEqual([])
		expect(manager.keys()).toEqual([])

		manager.destroy()
	})

	// === register

	it('registers a single asset', () => {
		const manager = new AssetManager()
		const content = new TextEncoder().encode('hello').buffer as ArrayBuffer

		manager.register({ key: 'test.txt', content })

		expect(manager.count).toBe(1)
		expect(manager.asset('test.txt')).toBeDefined()
		expect(manager.asset('test.txt')?.key).toBe('test.txt')
		expect(manager.keys()).toEqual(['test.txt'])

		manager.destroy()
	})

	it('registers multiple assets at once', () => {
		const manager = new AssetManager()
		const content = new ArrayBuffer(4)

		manager.register([
			{ key: 'a.txt', content },
			{ key: 'b.css', content },
		])

		expect(manager.count).toBe(2)
		expect(manager.keys()).toEqual(['a.txt', 'b.css'])

		manager.destroy()
	})

	it('overwrites duplicate keys without duplicating keys list', () => {
		const manager = new AssetManager()
		const content1 = new TextEncoder().encode('v1').buffer as ArrayBuffer
		const content2 = new TextEncoder().encode('v2').buffer as ArrayBuffer

		manager.register({ key: 'file.txt', content: content1 })
		manager.register({ key: 'file.txt', content: content2 })

		expect(manager.count).toBe(1)
		expect(manager.keys()).toEqual(['file.txt'])

		const asset = manager.asset('file.txt')
		expect(asset).toBeDefined()
		expect(new Uint8Array(asset?.content ?? new ArrayBuffer(0))).toEqual(new Uint8Array(content2))

		manager.destroy()
	})

	// === asset

	it('returns undefined for missing asset keys', () => {
		const manager = new AssetManager()

		expect(manager.asset('missing')).toBeUndefined()

		manager.destroy()
	})

	// === compression inference

	it('infers compression from .br extension', () => {
		const manager = new AssetManager()
		const content = new ArrayBuffer(4)

		manager.register({ key: 'app.html.br', content })

		expect(manager.asset('app.html.br')?.compressed).toBe(true)

		manager.destroy()
	})

	it('marks non-.br keys as uncompressed by default', () => {
		const manager = new AssetManager()
		const content = new ArrayBuffer(4)

		manager.register({ key: 'app.html', content })

		expect(manager.asset('app.html')?.compressed).toBe(false)

		manager.destroy()
	})

	it('respects explicit compressed flag', () => {
		const manager = new AssetManager()
		const content = new ArrayBuffer(4)

		manager.register({ key: 'app.html', content, compressed: true })

		expect(manager.asset('app.html')?.compressed).toBe(true)

		manager.destroy()
	})

	// === clear

	it('clears all registered assets', () => {
		const manager = new AssetManager()
		const content = new ArrayBuffer(4)

		manager.register({ key: 'test.txt', content })
		expect(manager.count).toBe(1)

		manager.clear()

		expect(manager.count).toBe(0)
		expect(manager.assets()).toEqual([])
		expect(manager.keys()).toEqual([])

		manager.destroy()
	})

	// === emitter

	it('emits register events', () => {
		const registered: string[] = []
		const manager = new AssetManager({
			on: {
				register: (asset) => {
					registered.push(asset.key)
				},
			},
		})
		const content = new ArrayBuffer(4)

		manager.register({ key: 'one.txt', content })
		manager.register({ key: 'two.txt', content })

		expect(registered).toEqual(['one.txt', 'two.txt'])

		manager.destroy()
	})

	it('emits clear events', () => {
		let cleared = false
		const manager = new AssetManager({
			on: {
				clear: () => {
					cleared = true
				},
			},
		})

		manager.clear()

		expect(cleared).toBe(true)

		manager.destroy()
	})

	// === SEA-embedded load
	// #loadSea's 'load' event emission runs only when isSea() is true, which
	// vitest never is — that path is unreachable without a real SEA build and
	// is not force-tested here. The existing 'emits register events' /
	// 'clears all registered assets' coverage exercises the same emitter
	// wiring the 'load' event uses.

	// === destroy

	it('destroys the emitter on destroy', () => {
		const manager = new AssetManager()

		manager.destroy()

		expect(manager.emitter.destroyed).toBe(true)
	})
})
