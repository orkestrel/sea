// Real SEA build integration battery (AGENTS §16.1) — these tests copy the
// real node binary and shell out to `node --experimental-sea-config`, which
// is slow (~100MB copy + subprocess) and environment-dependent, so they are
// kept OUT of the default `test` run and live in this dedicated, opt-in
// `integration` project instead (run via `npm run test:integration`).
import type { SEACompressionManifest } from '@src/server'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createSEA, isSEAError, SEA } from '@src/server'
import { requireValue } from '@orkestrel/test'
import { createSEAOptions, withTestDir } from './setupServer.js'

describe('seal integration', () => {
	// Injects into the CURRENT node binary's real executable format. On some
	// platforms/binaries the target has no free program-header slot for the
	// injected segment (a genuine binary-layout limitation, not a test bug) —
	// skip gracefully rather than fail when that specific condition occurs.
	it('builds a single executable application end-to-end', async (context) => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const seal = createSEA(
					createSEAOptions({
						root: scratch.path,
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

				let result: Awaited<ReturnType<typeof seal.execute>>
				try {
					result = await seal.execute()
				} catch (error) {
					seal.destroy()
					if (error instanceof Error && error.message.includes('free program header entry')) {
						context.skip()
						return
					}
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

				seal.destroy()
			},
		)
	}, 120000)

	it('writes a sea-config.json reflecting an explicit entry format', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (scratch) => {
				const seal = createSEA(
					createSEAOptions({
						root: scratch.path,
						entry: { path: 'entry.cjs', format: 'cjs' },
					}),
				)

				try {
					await seal.execute()
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

				seal.destroy()
			},
		)
	}, 120000)

	it('embeds compressed asset outputs under original keys without mutating asset options', async () => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
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
				const seal = createSEA(
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

				const error: unknown = await seal.execute().then(
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

				seal.destroy()
			},
		)
	}, 120000)

	// Injects into the CURRENT node binary's real executable format. On some
	// platforms/binaries the target has no free program-header slot for the
	// injected segment (a genuine binary-layout limitation, not a test bug) —
	// skip gracefully rather than fail when that specific condition occurs.
	it('supports stage hooks through the on option', async (context) => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (scratch) => {
				const events: string[] = []
				const seal = new SEA(
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
	}, 120000)
})
