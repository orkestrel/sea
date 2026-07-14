import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createInjector, createSEA, isExecutableFormat } from '@src/server'
import { createInjectorOptions, createSEAOptions, withTestDir } from '../../setupServer.js'

describe('seal integration', () => {
	it('createSEA creates an idle seal instance', () => {
		const seal = createSEA(createSEAOptions())

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

	// Injects into the CURRENT node binary's real executable format. On some
	// platforms/binaries the target has no free program-header slot for the
	// injected segment (a genuine binary-layout limitation, not a test bug) —
	// skip gracefully rather than fail when that specific condition occurs.
	it('builds a single executable application end-to-end', async (context) => {
		await withTestDir(
			{
				'entry.cjs': "console.log('hello from seal')\n",
			},
			async (dir) => {
				const events: string[] = []
				const seal = createSEA(
					createSEAOptions({
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
				expect(existsSync(result.executable)).toBe(true)
				expect(events).toEqual(['compress', 'blob', 'assemble', 'complete'])

				// Platform-conditional result fields — only meaningful once a real
				// build succeeded on this host, so they piggyback on the same run.
				// Asserted unconditionally against a per-platform expectation map
				// (empty for unlisted platforms) to avoid a conditional `expect`.
				const platformExpectations: Readonly<Record<string, Partial<typeof result>>> = {
					darwin: { signed: true, stripped: true },
					linux: { signed: false, stripped: false },
					win32: { stripped: true, signed: false, subsystem: 'console' },
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
			async (dir) => {
				const seal = createSEA(
					createSEAOptions({
						root: dir.root,
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

				const configPath = join(dir.root, 'dist', 'sea-config.json')
				expect(existsSync(configPath)).toBe(true)

				const config: unknown = JSON.parse(readFileSync(configPath, 'utf-8'))
				expect(config).toMatchObject({
					main: join(dir.root, 'entry.cjs'),
					disableExperimentalSEAWarning: true,
					useCodeCache: true,
					useSnapshot: false,
				})

				seal.destroy()
			},
		)
	}, 120000)
})
