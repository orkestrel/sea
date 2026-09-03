import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { isSEAError, SEA } from '@src/server'
import { createRecorder } from '@orkestrel/test'
import { createSEAOptions, withTestDir } from '../../../setupServer.js'

describe('SEA', () => {
	it('starts with idle status', () => {
		const sea = new SEA(createSEAOptions())

		expect(sea.status).toBe('idle')
		sea.destroy()
	})

	it('emits error events for build failures', async () => {
		await withTestDir({}, async (scratch) => {
			const recorder = createRecorder<[unknown]>()
			const sea = new SEA(
				createSEAOptions({
					root: scratch.path,
					entry: { path: 'missing.cjs' },
				}),
			)

			sea.emitter.on('error', recorder.handler)

			const error: unknown = await sea.execute().then(
				() => undefined,
				(thrown: unknown) => thrown,
			)
			expect(isSEAError(error)).toBe(true)
			expect(isSEAError(error) && error.code).toBe('ENTRY')
			expect(sea.status).toBe('error')
			expect(recorder.count).toBe(1)

			sea.emitter.off('error', recorder.handler)
			sea.destroy()
		})
	})

	it('rejects execute() with code STATE once destroyed', async () => {
		const sea = new SEA(createSEAOptions())
		sea.destroy()
		// The emitter carries the destroyed fact, and `destroy` stays idempotent.
		sea.destroy()

		expect(sea.emitter.destroyed).toBe(true)

		const error: unknown = await sea.execute().then(
			() => undefined,
			(thrown: unknown) => thrown,
		)
		expect(isSEAError(error)).toBe(true)
		expect(isSEAError(error) && error.code).toBe('STATE')
	})

	it('rejects execute() with code STATE after a consumer destroys sea.emitter directly', async () => {
		const sea = new SEA(createSEAOptions())
		sea.emitter.destroy()

		expect(sea.emitter.destroyed).toBe(true)

		const error: unknown = await sea.execute().then(
			() => undefined,
			(thrown: unknown) => thrown,
		)
		expect(isSEAError(error)).toBe(true)
		expect(isSEAError(error) && error.code).toBe('STATE')
	})

	it('rejects a pre-aborted signal before any work runs', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const controller = new AbortController()
				controller.abort()

				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						signal: controller.signal,
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ABORT')

				expect(sea.status).toBe('error')
				expect(scratch.has('dist')).toBe(false)

				sea.destroy()
			},
		)
	})

	it('completes spawned shell commands within a generous timeout', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						timeout: 30_000,
					}),
				)

				const result = await sea.execute()

				expect(result.size).toBeGreaterThan(0)
				expect(sea.status).toBe('done')
				sea.destroy()
			},
		)
	}, 30_000)

	it('surfaces TIMEOUT when a spawned shell command exceeds its timeout', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						timeout: 1,
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)

				expect(isSEAError(error) && error.code).toBe('TIMEOUT')
				expect(sea.status).toBe('error')
				sea.destroy()
			},
		)
	}, 30_000)

	it('aborts mid-pipeline without touching an existing output', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const controller = new AbortController()
				scratch.ensure('dist')
				const name = process.platform === 'win32' ? 'sea-test.exe' : 'sea-test'
				const sentinel = 'sentinel-bytes'
				scratch.write(`dist/${name}`, sentinel)

				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						signal: controller.signal,
						on: {
							blob: () => {
								controller.abort()
							},
						},
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ABORT')

				expect(scratch.read(`dist/${name}`)).toBe(sentinel)
				const remaining = scratch.names('dist').filter((entry) => entry.includes('.tmp'))
				expect(remaining).toHaveLength(0)

				sea.destroy()
			},
		)
	})

	it('rejects a traversal asset key with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						assets: { '../evil': 'entry.cjs' },
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				sea.destroy()
			},
		)
	})

	it('rejects a traversal compression path with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						compression: { paths: ['../..'] },
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				sea.destroy()
			},
		)
	})

	it('accepts an absolute asset path that resolves inside the build root', async () => {
		await withTestDir(
			{
				'assets/client.html': '<main>client</main>',
			},
			async (scratch) => {
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						assets: { 'client.html': join(scratch.path, 'assets', 'client.html') },
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				// The asset-key guard governs the key alone, so an absolute path reaches
				// containment and the build fails on the missing entry point instead.
				expect(isSEAError(error) && error.code).toBe('ENTRY')

				sea.destroy()
			},
		)
	})

	it('rejects an asset path that symlink-escapes root with code ASSET', async (context) => {
		await withTestDir(
			{
				'root/entry.cjs': "console.log('hello from sea')\n",
				'outside/secret.txt': 'secret',
			},
			async (scratch) => {
				const root = join(scratch.path, 'root')
				const target = join(scratch.path, 'outside', 'secret.txt')
				const link = join(root, 'escaped')

				try {
					scratch.link(link, target)
				} catch {
					context.skip()
					return
				}

				const events: string[] = []
				const sea = new SEA(
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

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				sea.destroy()
			},
		)
	})

	it('rejects an unsafe executable name with code ASSET before any compress event fires', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						name: '../evil',
						on: {
							compress: () => {
								events.push('compress')
							},
						},
					}),
				)

				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ASSET')

				expect(events).toHaveLength(0)
				sea.destroy()
			},
		)
	})

	it('emits progress once per compressible file with an accurate running total', async () => {
		await withTestDir(
			{
				'assets/a.html': '<p>a</p>',
				'assets/b.html': '<p>b</p>',
				'assets/c.png': 'not-really-a-png',
			},
			async (scratch) => {
				const progress: Array<{ current: number; total: number }> = []
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
						entry: { path: 'missing-entry.cjs' },
						compression: { paths: ['assets'] },
						on: {
							progress: (event) => {
								progress.push({ current: event.current, total: event.total })
							},
						},
					}),
				)

				// #compress emits progress for every compressible file BEFORE #blob's
				// ensureExists(entry) rejects with ENTRY — no real build, no node
				// subprocess, no binary copy: fast and deterministic.
				const error: unknown = await sea.execute().then(
					() => undefined,
					(thrown: unknown) => thrown,
				)
				expect(isSEAError(error)).toBe(true)
				expect(isSEAError(error) && error.code).toBe('ENTRY')

				// assets/c.png is skipped (SKIP_EXTENSIONS), so only a.html and b.html compress.
				expect(progress).toHaveLength(2)
				expect(progress.every((event) => event.total === 2)).toBe(true)
				expect(progress.map((event) => event.current)).toEqual([1, 2])

				sea.destroy()
			},
		)
	})

	it('destroys its emitter', () => {
		const sea = new SEA(createSEAOptions())

		sea.destroy()

		expect(sea.emitter.destroyed).toBe(true)
	})

	describe('windows.sign validation', () => {
		it('rejects a sign config with neither file nor thumbprint, code SIGN, before any compress event fires', async () => {
			await withTestDir(
				{
					'entry.cjs': "console.log('hello from sea')\n",
				},
				async (scratch) => {
					const events: string[] = []
					const sea = new SEA(
						createSEAOptions({
							root: scratch.path,
							windows: { sign: {} },
							on: {
								compress: () => {
									events.push('compress')
								},
							},
						}),
					)

					const error: unknown = await sea.execute().then(
						() => undefined,
						(thrown: unknown) => thrown,
					)
					expect(isSEAError(error)).toBe(true)
					expect(isSEAError(error) && error.code).toBe('SIGN')

					expect(events).toHaveLength(0)
					sea.destroy()
				},
			)
		})

		it('rejects a sign config with both file and thumbprint, code SIGN, before any compress event fires', async () => {
			await withTestDir(
				{
					'entry.cjs': "console.log('hello from sea')\n",
					'cert.pfx': 'not-a-real-cert',
				},
				async (scratch) => {
					const events: string[] = []
					const sea = new SEA(
						createSEAOptions({
							root: scratch.path,
							windows: {
								sign: {
									file: 'cert.pfx',
									thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD',
								},
							},
							on: {
								compress: () => {
									events.push('compress')
								},
							},
						}),
					)

					const error: unknown = await sea.execute().then(
						() => undefined,
						(thrown: unknown) => thrown,
					)
					expect(isSEAError(error)).toBe(true)
					expect(isSEAError(error) && error.code).toBe('SIGN')

					expect(events).toHaveLength(0)
					sea.destroy()
				},
			)
		})

		it('rejects a non-http(s) timestamp, code SIGN, before any compress event fires', async () => {
			await withTestDir(
				{
					'entry.cjs': "console.log('hello from sea')\n",
					'cert.pfx': 'not-a-real-cert',
				},
				async (scratch) => {
					const events: string[] = []
					const sea = new SEA(
						createSEAOptions({
							root: scratch.path,
							windows: {
								sign: { file: 'cert.pfx', timestamp: 'ftp://timestamp.example.com' },
							},
							on: {
								compress: () => {
									events.push('compress')
								},
							},
						}),
					)

					const error: unknown = await sea.execute().then(
						() => undefined,
						(thrown: unknown) => thrown,
					)
					expect(isSEAError(error)).toBe(true)
					expect(isSEAError(error) && error.code).toBe('SIGN')

					expect(events).toHaveLength(0)
					sea.destroy()
				},
			)
		})

		it('rejects a missing certificate file, code SIGN, before any compress event fires', async () => {
			await withTestDir(
				{
					'entry.cjs': "console.log('hello from sea')\n",
				},
				async (scratch) => {
					const events: string[] = []
					const sea = new SEA(
						createSEAOptions({
							root: scratch.path,
							windows: { sign: { file: 'missing-cert.pfx' } },
							on: {
								compress: () => {
									events.push('compress')
								},
							},
						}),
					)

					const error: unknown = await sea.execute().then(
						() => undefined,
						(thrown: unknown) => thrown,
					)
					expect(isSEAError(error)).toBe(true)
					expect(isSEAError(error) && error.code).toBe('SIGN')

					expect(events).toHaveLength(0)
					sea.destroy()
				},
			)
		})
	})
})
