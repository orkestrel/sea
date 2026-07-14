import { existsSync, readFileSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
	createBlobConfig,
	ensureContained,
	ensureSafeKey,
	ensureSafeName,
	finalizeExecutable,
	isSEAError,
	isShellError,
	runShell,
	walkDirectory,
} from '@src/server'
import { withTestDir } from '../../setupServer.js'
import { captureError } from '../../setup.js'

describe('helpers', () => {
	describe('runShell', () => {
		it('enforces a timeout', () => {
			const error = captureError(() => {
				return runShell([process.execPath, '-e', 'setInterval(()=>{},1000)'], { timeout: 50 })
			})

			expect(isSEAError(error) && error.code === 'TIMEOUT').toBe(true)
		})

		it('rejects an already-aborted signal before spawning', () => {
			const controller = new AbortController()
			controller.abort()

			const error = captureError(() => {
				return runShell(['this-command-does-not-exist'], { signal: controller.signal })
			})

			expect(isSEAError(error) && error.code === 'ABORT').toBe(true)
		})

		it('maps a non-zero exit to a ShellError', () => {
			const error = captureError(() => {
				return runShell([process.execPath, '-e', 'process.exit(3)'])
			})

			expect(isShellError(error) && error.code === 'SHELL').toBe(true)
			expect(isShellError(error) && Buffer.isBuffer(error.stderr)).toBe(true)
		})
	})

	describe('ensureSafeKey', () => {
		it.each(['../x', 'a/../../x', '/abs', 'C:\\x', 'a\\b', 'C:foo'])(
			'rejects unsafe key %s',
			(key) => {
				const error = captureError(() => {
					ensureSafeKey(key)
				})

				expect(isSEAError(error) && error.code === 'ASSET').toBe(true)
			},
		)

		it('accepts a safe nested key', () => {
			expect(() => {
				ensureSafeKey('a/b.html.br')
			}).not.toThrow()
		})
	})

	describe('ensureContained', () => {
		it('accepts a real path inside the base', async () => {
			await withTestDir(
				{
					'base/inside.txt': 'inside',
				},
				(dir) => {
					const base = join(dir.root, 'base')
					const real = ensureContained(base, 'inside.txt')

					expect(existsSync(real)).toBe(true)
				},
			)
		})

		it('rejects a symlink that escapes the base via realpath', async (context) => {
			await withTestDir(
				{
					'base/marker.txt': 'marker',
					'outside/secret.txt': 'secret',
				},
				(dir) => {
					const base = join(dir.root, 'base')
					const outside = join(dir.root, 'outside')
					const link = join(base, 'escaped')

					try {
						symlinkSync(outside, link)
					} catch {
						context.skip()
						return
					}

					const error = captureError(() => {
						ensureContained(base, 'escaped')
					})

					expect(isSEAError(error) && error.code === 'ASSET').toBe(true)
				},
			)
		})

		it('rejects a nonexistent path as ASSET', async () => {
			await withTestDir(
				{
					'base/marker.txt': 'marker',
				},
				(dir) => {
					const base = join(dir.root, 'base')

					const error = captureError(() => {
						ensureContained(base, 'missing.txt')
					})

					expect(isSEAError(error) && error.code === 'ASSET').toBe(true)
				},
			)
		})
	})

	describe('ensureSafeName', () => {
		it.each(['', '.', '..', 'a/b', 'a\\b', '/abs', 'C:x'])('rejects unsafe name %s', (name) => {
			const error = captureError(() => {
				ensureSafeName(name)
			})

			expect(isSEAError(error) && error.code === 'ASSET').toBe(true)
		})

		it('accepts a safe name', () => {
			expect(() => {
				ensureSafeName('smoke')
			}).not.toThrow()
		})
	})

	describe('finalizeExecutable', () => {
		it('atomically replaces an existing target', async () => {
			await withTestDir(
				{
					'app.tmp': 'new content',
					app: 'old content',
				},
				(dir) => {
					const source = join(dir.root, 'app.tmp')
					const target = join(dir.root, 'app')

					finalizeExecutable(source, target)

					expect(readFileSync(target, 'utf-8')).toBe('new content')
					expect(existsSync(source)).toBe(false)
				},
			)
		})
	})

	describe('createBlobConfig', () => {
		it('applies defaults for a cjs entry', () => {
			const config = createBlobConfig({ path: 'entry.cjs' }, 'blob.bin', undefined)

			expect(config.useCodeCache).toBe(true)
			expect(config.useSnapshot).toBe(false)
			expect('mainFormat' in config).toBe(false)
			expect('assets' in config).toBe(false)
		})

		it('flips cache and snapshot from blob options', () => {
			const config = createBlobConfig({ path: 'entry.cjs' }, 'blob.bin', undefined, {
				cache: false,
				snapshot: true,
			})

			expect(config.useCodeCache).toBe(false)
			expect(config.useSnapshot).toBe(true)
		})

		it('emits mainFormat module for an esm entry', () => {
			const config = createBlobConfig({ path: 'entry.mjs', format: 'esm' }, 'blob.bin', undefined)

			expect(config.mainFormat).toBe('module')
		})

		it('throws BLOB when esm is combined with useSnapshot', () => {
			const error = captureError(() => {
				return createBlobConfig({ path: 'entry.mjs', format: 'esm' }, 'blob.bin', undefined, {
					snapshot: true,
				})
			})

			expect(isSEAError(error) && error.code === 'BLOB').toBe(true)
		})

		it('includes assets only when provided', () => {
			const withAssets = createBlobConfig({ path: 'entry.cjs' }, 'blob.bin', { key: 'value' })
			const withoutAssets = createBlobConfig({ path: 'entry.cjs' }, 'blob.bin', undefined)

			expect(withAssets.assets).toEqual({ key: 'value' })
			expect('assets' in withoutAssets).toBe(false)
		})
	})

	describe('walkDirectory', () => {
		it('skips symlinks that escape the walk root', async () => {
			await withTestDir(
				{
					'root/inside.txt': 'inside',
					'outside.txt': 'outside',
				},
				(dir) => {
					const root = join(dir.root, 'root')
					const target = join(dir.root, 'outside.txt')
					const link = join(root, 'escaped.txt')

					try {
						symlinkSync(target, link)
					} catch {
						return
					}

					const files = walkDirectory(root)

					expect(files).toContain('inside.txt')
					expect(files).not.toContain('escaped.txt')
				},
			)
		})
	})
})
