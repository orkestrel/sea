// Real SEA build integration battery — these tests copy the real node binary and
// spawn `node --experimental-sea-config`, so they are slow (~100MB copy plus a
// subprocess) and depend on the host binary's layout. They run in the
// `integration` project, which `npm test` reaches through `npm run
// test:integration`.
import type { SEACompressionManifest } from '@src/server'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createSEA, isSEAError, SEA } from '@src/server'
import { requireValue } from '@orkestrel/test'
import { createSEAOptions, withTestDir } from './setupServer.js'

describe('sea integration', () => {
	it('builds a single executable application end-to-end', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const sea = createSEA(
					createSEAOptions({
						root: scratch.path,
					}),
				)

				sea.emitter.on('compress', () => {
					events.push('compress')
				})
				sea.emitter.on('blob', () => {
					events.push('blob')
				})
				sea.emitter.on('assemble', () => {
					events.push('assemble')
				})
				sea.emitter.on('complete', () => {
					events.push('complete')
				})

				let result: Awaited<ReturnType<typeof sea.execute>>
				try {
					result = await sea.execute()
				} catch (error) {
					sea.destroy()
					throw error
				}

				expect(result.platform).toBe(process.platform)
				expect(result.size).toBeGreaterThan(0)
				expect(result.duration).toBeGreaterThanOrEqual(0)
				expect(scratch.has(result.executable)).toBe(true)
				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])

				// Platform-conditional result fields — only meaningful once a real
				// build succeeded on this host, so they piggyback on the same run.
				// Asserted unconditionally against a per-platform expectation map
				// (empty for unlisted platforms) to avoid a conditional `expect`.
				const platformExpectations: Readonly<Record<string, Partial<typeof result>>> = {
					darwin: { signed: true, stripped: true },
					linux: { signed: false, stripped: false },
					win32: { stripped: true, signed: false, terminal: true },
				}
				expect(result).toMatchObject(platformExpectations[process.platform] ?? {})

				sea.destroy()
			},
		)
	}, 120000)

	it('writes a sea-config.json reflecting an explicit entry format', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const sea = createSEA(
					createSEAOptions({
						root: scratch.path,
						entry: { path: 'entry.cjs', format: 'cjs' },
					}),
				)

				try {
					await sea.execute()
				} catch {
					// The config is written by #blob before assembly ever runs, so
					// the assertion below holds even when assemble/injection fails
					// on a constrained CI binary.
				}

				expect(scratch.has('dist/sea-config.json')).toBe(true)

				const config: unknown = JSON.parse(requireValue(scratch.read('dist/sea-config.json')))
				expect(config).toMatchObject({
					main: join(scratch.path, 'entry.cjs'),
					disableExperimentalSEAWarning: true,
					useCodeCache: true,
					useSnapshot: false,
				})

				sea.destroy()
			},
		)
	}, 120000)

	it('embeds compressed asset outputs under original keys without mutating asset options', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
				'assets/index.html': '<main>compressed client</main>',
				'assets/logo.png': 'uncompressed image',
			},
			async (scratch) => {
				const controller = new AbortController()
				const assets = {
					'index.html': 'assets/index.html',
					'logo.png': 'assets/logo.png',
				}
				const reports: SEACompressionManifest[] = []
				const sea = createSEA(
					createSEAOptions({
						root: scratch.path,
						assets,
						compression: { paths: ['assets'], mode: 'text' },
						signal: controller.signal,
						on: {
							compress: (report) => {
								if (report !== undefined) reports.push(report)
							},
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
				expect(scratch.has('dist/sea-prep.blob')).toBe(true)

				const input = join(scratch.path, 'assets', 'index.html')
				const output = `${input}.br`
				expect(reports).toHaveLength(1)
				expect(reports[0]).toMatchObject({ assets: [{ input, output }] })

				const config: unknown = JSON.parse(requireValue(scratch.read('dist/sea-config.json')))
				expect(config).toMatchObject({
					assets: {
						'index.html': output,
						'logo.png': join(scratch.path, 'assets', 'logo.png'),
					},
				})
				expect(assets).toEqual({
					'index.html': 'assets/index.html',
					'logo.png': 'assets/logo.png',
				})

				sea.destroy()
			},
		)
	}, 120000)

	// Injects into the CURRENT node binary's real executable format. A host binary
	// can carry a layout the injector cannot write into: a PE whose header slack is
	// smaller than one section entry, a Mach-O whose first section sits inside the
	// space another segment command needs, a Mach-O with no `__LINKEDIT` segment, or
	// a `__LINKEDIT` segment carrying sections. The injector reads that layout out of
	// the host's headers and load commands before it writes anything and reports it
	// as `ROOM`, which is the only code this skip covers. Every other injector
	// failure, `INJECT` included, fails this test.
	it('supports stage hooks through the on option', async (context) => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from sea')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const sea = new SEA(
					createSEAOptions({
						root: scratch.path,
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
					await sea.execute()
				} catch (error) {
					sea.destroy()
					if (isSEAError(error) && error.code === 'ROOM') {
						context.skip()
						return
					}
					throw error
				}

				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])
				sea.destroy()
			},
		)
	}, 120000)
})
