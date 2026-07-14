import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createAsset, createAssetManager, createInjector, createSEA } from '@src/server'
import { createInjectorOptions, createSEAOptions, withTestDir } from '../../setupServer.js'

describe('factories', () => {
	describe('createSEA', () => {
		it('constructs a working SEAInterface without throwing', () => {
			const seal = createSEA(createSEAOptions())

			expect(seal.status).toBe('idle')
			expect(seal.emitter).toBeDefined()
			expect(typeof seal.execute).toBe('function')
			expect(typeof seal.destroy).toBe('function')

			seal.destroy()
		})
	})

	describe('createInjector', () => {
		it('constructs an InjectorInterface that detects the executable format', async () => {
			await withTestDir({}, (dir) => {
				const executable = join(dir.root, 'app.exe')
				const blob = join(dir.root, 'sea-prep.blob')

				// A minimal ELF header is enough for the Injector's format
				// detection to succeed without needing a full PE fixture here.
				const elfHeader = Buffer.alloc(64)
				elfHeader.writeUInt8(0x7f, 0)
				elfHeader.write('ELF', 1, 3, 'ascii')
				writeFileSync(executable, elfHeader)
				writeFileSync(blob, Buffer.from('blob'))

				const injector = createInjector(createInjectorOptions({ executable, blob }))

				expect(injector.format).toBe('elf')
				expect(typeof injector.inject).toBe('function')
			})
		})
	})

	describe('createAsset', () => {
		it('constructs an AssetInterface with the given key and content', () => {
			const content = new ArrayBuffer(4)
			const asset = createAsset({ key: 'client.html', content })

			expect(asset.key).toBe('client.html')
			expect(asset.content).toBe(content)
		})

		it('infers compressed=true from a .br key suffix', () => {
			const asset = createAsset({ key: 'client.html.br', content: new ArrayBuffer(0) })

			expect(asset.compressed).toBe(true)
		})

		it('infers compressed=false for a non-.br key', () => {
			const asset = createAsset({ key: 'client.html', content: new ArrayBuffer(0) })

			expect(asset.compressed).toBe(false)
		})

		it('lets an explicit compressed flag override the .br inference', () => {
			const inferredFalse = createAsset({
				key: 'client.html.br',
				content: new ArrayBuffer(0),
				compressed: false,
			})
			const inferredTrue = createAsset({
				key: 'client.html',
				content: new ArrayBuffer(0),
				compressed: true,
			})

			expect(inferredFalse.compressed).toBe(false)
			expect(inferredTrue.compressed).toBe(true)
		})
	})

	describe('createAssetManager', () => {
		it('constructs an AssetManagerInterface with empty initial state outside SEA', () => {
			const manager = createAssetManager({ root: process.cwd() })

			expect(manager.count).toBe(0)
			expect(manager.assets()).toEqual([])
			expect(manager.keys()).toEqual([])
			expect(manager.asset('missing')).toBeUndefined()

			manager.destroy()
		})

		it('registers, looks up, and clears an asset through the manager API', () => {
			const manager = createAssetManager()
			const content = new ArrayBuffer(2)

			manager.register({ key: 'a.txt', content })

			expect(manager.count).toBe(1)
			expect(manager.keys()).toEqual(['a.txt'])
			expect(manager.asset('a.txt')?.content).toBe(content)

			manager.clear()

			expect(manager.count).toBe(0)
			expect(manager.asset('a.txt')).toBeUndefined()

			manager.destroy()
		})
	})
})
