import { describe, expect, it } from 'vitest'
import { Seal } from '@scsr/server'
import { createSealOptions, withTestDir } from '../../../../setupServer.js'

describe('Seal', () => {
	it('starts with idle status', () => {
		const seal = new Seal(createSealOptions())

		expect(seal.status).toBe('idle')
		seal.destroy()
	})

	it('emits error events for build failures', async () => {
		await withTestDir({}, async (dir) => {
			const errors: unknown[] = []
			const seal = new Seal(
				createSealOptions({
					root: dir.root,
					entry: 'missing.cjs',
				}),
			)

			const off = seal.emitter.on('error', (error) => {
				errors.push(error)
			})

			await expect(seal.execute()).rejects.toThrow('Entry not found')
			expect(seal.status).toBe('error')
			expect(errors).toHaveLength(1)

			off()
			seal.destroy()
		})
	})

	it('supports stage hooks through the on option', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = new Seal(
					createSealOptions({
						root: dir.root,
						on: {
							compress: () => {
								events.push('compress')
							},
							blob: () => {
								events.push('blob')
							},
							assemble: () => {
								events.push('assemble')
							},
							complete: () => {
								events.push('complete')
							},
						},
					}),
				)

				await seal.execute()

				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])
				seal.destroy()
			},
		)
	})

	it('destroys its emitter', () => {
		const seal = new Seal(createSealOptions())

		seal.destroy()

		expect(seal.emitter.destroyed).toBe(true)
	})
})
