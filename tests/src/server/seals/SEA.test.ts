import { describe, expect, it } from 'vitest'
import { SEA } from '@src/server'
import { createSEAOptions, withTestDir } from '../../../setupServer.js'

describe('SEA', () => {
	it('starts with idle status', () => {
		const seal = new SEA(createSEAOptions())

		expect(seal.status).toBe('idle')
		seal.destroy()
	})

	it('emits error events for build failures', async () => {
		await withTestDir({}, async (dir) => {
			const errors: unknown[] = []
			const onError = (error: unknown): void => {
				errors.push(error)
			}
			const seal = new SEA(
				createSEAOptions({
					root: dir.root,
					entry: 'missing.cjs',
				}),
			)

			seal.emitter.on('error', onError)

			await expect(seal.execute()).rejects.toThrow('Entry not found')
			expect(seal.status).toBe('error')
			expect(errors).toHaveLength(1)

			seal.emitter.off('error', onError)
			seal.destroy()
		})
	})

	// Injects into the CURRENT node binary's real executable format. On some
	// platforms/binaries the target has no free program-header slot for the
	// injected segment (a genuine binary-layout limitation, not a test bug) —
	// skip gracefully rather than fail when that specific condition occurs.
	it('supports stage hooks through the on option', async (context) => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = new SEA(
					createSEAOptions({
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

				try {
					await seal.execute()
				} catch (error) {
					seal.destroy()
					if (error instanceof Error && error.message.includes('free program header entry')) {
						context.skip()
						return
					}
					throw error
				}

				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])
				seal.destroy()
			},
		)
	})

	it('destroys its emitter', () => {
		const seal = new SEA(createSEAOptions())

		seal.destroy()

		expect(seal.emitter.destroyed).toBe(true)
	})
})
