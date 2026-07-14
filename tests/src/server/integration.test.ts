import { existsSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createInjector, createSeal, isExecutableFormat } from '@scsr/server'
import { createInjectorOptions, createSealOptions, withTestDir } from '../../../setupServer.js'

describe('seal integration', () => {
	it('createSeal creates an idle seal instance', () => {
		const seal = createSeal(createSealOptions())

		expect(seal.status).toBe('idle')
		seal.destroy()
	})

	it('createInjector detects the executable format of the current node binary', async () => {
		await withTestDir({}, async (dir) => {
			const blob = join(dir.root, 'blob.bin')
			writeFileSync(blob, 'blob')

			const injector = createInjector(
				createInjectorOptions({
					executable: process.execPath,
					blob,
				}),
			)

			expect(isExecutableFormat(injector.format)).toBe(true)
		})
	})

	it('builds a single executable application end-to-end', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = createSeal(
					createSealOptions({
						root: dir.root,
					}),
				)

				seal.emitter.on('compress', () => {
					events.push('compress')
				})
				seal.emitter.on('blob', () => {
					events.push('blob')
				})
				seal.emitter.on('assemble', () => {
					events.push('assemble')
				})
				seal.emitter.on('complete', () => {
					events.push('complete')
				})

				const result = await seal.execute()

				expect(result.platform).toBe(process.platform)
				expect(result.size).toBeGreaterThan(0)
				expect(result.duration).toBeGreaterThanOrEqual(0)
				expect(existsSync(result.executable)).toBe(true)
				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])

				seal.destroy()
			},
		)
	}, 120000)
})
