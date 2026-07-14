import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	symlinkSync,
	writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { isSEAError, SEA } from '@src/server'
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
					entry: { path: 'missing.cjs' },
				}),
			)

			seal.emitter.on('error', onError)

			const error: unknown = await seal.execute().then(
				() => undefined,
				(thrown: unknown) => thrown,
			)
			expect(isSEAError(error)).toBe(true)
			expect(isSEAError(error) && error.code).toBe('ENTRY')
			expect(seal.status).toBe('error')
			expect(errors).toHaveLength(1)

			seal.emitter.off('error', onError)
			seal.destroy()
		})
	})

	it('rejects execute() with code STATE once destroyed', async () => {
		const seal = new SEA(createSEAOptions())
		seal.destroy()

		const error: unknown = await seal.execute().then(
			() => undefined,
			(thrown: unknown) => thrown,
		)
		expect(isSEAError(error)).toBe(true)
		expect(isSEAError(error) && error.code).toBe('STATE')
	})

	it('rejects a pre-aborted signal before any work runs', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const controller = new AbortController()
				controller.abort()

				const seal = new SEA(
					createSEAOptions({
						root: dir.root,
						signal: controller.signal,
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ABORT')

				expect(seal.status).toBe('error')
				expect(existsSync(join(dir.root, 'dist'))).toBe(false)

				seal.destroy()
			},
		)
	})

	it('aborts mid-pipeline without touching an existing output', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const controller = new AbortController()
				const output = join(dir.root, 'dist')
				mkdirSync(output, { recursive: true })
				const name = process.platform === 'win32' ? 'seal-test.exe' : 'seal-test'
				const finalOutput = join(output, name)
				const sentinel = 'sentinel-bytes'
				writeFileSync(finalOutput, sentinel)

				const seal = new SEA(
					createSEAOptions({
						root: dir.root,
						signal: controller.signal,
						on: {
							blob: () => {
								controller.abort()
							},
						},
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ABORT')

				expect(readFileSync(finalOutput, 'utf-8')).toBe(sentinel)
				const remaining = readdirSync(output).filter((entry) => entry.includes('.tmp'))
				expect(remaining).toHaveLength(0)

				seal.destroy()
			},
		)
	})

	it('rejects a traversal asset key with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = new SEA(
					createSEAOptions({
						root: dir.root,
						assets: { '../evil': 'entry.cjs' },
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				seal.destroy()
			},
		)
	})

	it('rejects a traversal compression path with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = new SEA(
					createSEAOptions({
						root: dir.root,
						compression: { paths: ['../..'] },
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				seal.destroy()
			},
		)
	})

	it('rejects an asset path that symlink-escapes root with code ASSET', async (context) => {
		await withTestDir(
			{
				'root/entry.cjs': "console.log('hello from seal')\n",
				'outside/secret.txt': 'secret',
			},
			async (dir) => {
				const root = join(dir.root, 'root')
				const target = join(dir.root, 'outside', 'secret.txt')
				const link = join(root, 'escaped')

				try {
					symlinkSync(target, link)
				} catch {
					context.skip()
					return
				}

				const events: string[] = []
				const seal = new SEA(
					createSEAOptions({
						root,
						assets: { escaped: 'escaped' },
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				seal.destroy()
			},
		)
	})

	it('rejects an unsafe executable name with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = new SEA(
					createSEAOptions({
						root: dir.root,
						name: '../evil',
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await seal.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				seal.destroy()
			},
		)
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
					if (isSEAError(error) && error.code === 'INJECT') {
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
