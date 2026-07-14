import { existsSync, mkdirSync, readFileSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
	compressDirectory,
	createBlobConfig,
	createSignCommand,
	ensureContained,
	ensureSafeKey,
	ensureSafeName,
	finalizeExecutable,
	isSEAError,
	isShellError,
	openBrowser,
	runShell,
	syncDirectory,
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

		it('redacts a /p secret from a ShellError message on a non-zero exit', () => {
			const error = captureError(() => {
				return runShell([process.execPath, '-e', 'process.exit(3)', '/p', 'SECRETVALUE'])
			})

			expect(isShellError(error) && error.message.includes('SECRETVALUE')).toBe(false)
			expect(isShellError(error) && error.message.includes('***')).toBe(true)
		})

		it('redacts a /p secret from the SEAError context on an already-aborted signal', () => {
			const controller = new AbortController()
			controller.abort()

			const error = captureError(() => {
				return runShell(['signtool', '/p', 'SECRETVALUE'], { signal: controller.signal })
			})

			const context = isSEAError(error) ? error.context : undefined
			const command = context !== undefined ? context.command : undefined
			const serialized = JSON.stringify(command)

			expect(isSEAError(error) && error.code === 'ABORT').toBe(true)
			expect(serialized.includes('SECRETVALUE')).toBe(false)
			expect(serialized.includes('***')).toBe(true)
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

		it('returns entries in deterministic byte-sorted order', async () => {
			await withTestDir(
				{
					'root/charlie.txt': 'c',
					'root/alpha.txt': 'a',
					'root/bravo/inside.txt': 'b',
				},
				(dir) => {
					const root = join(dir.root, 'root')
					const files = [...walkDirectory(root)]
					const sorted = [...files].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))

					expect(files).toEqual(sorted)
				},
			)
		})
	})

	describe('compressDirectory', () => {
		it('invokes the progress callback once per compressible file', async () => {
			await withTestDir(
				{
					'root/a.html': '<p>a</p>',
					'root/b.html': '<p>b</p>',
					'root/c.png': 'not-really-a-png',
				},
				(dir) => {
					const root = join(dir.root, 'root')
					const results: string[] = []

					const manifest = compressDirectory(root, undefined, (result) => {
						results.push(result.input)
					})

					expect(results).toHaveLength(2)
					expect(manifest.assets).toHaveLength(2)
				},
			)
		})
	})

	describe('syncDirectory', () => {
		it('does not throw for a real directory', async () => {
			await withTestDir(
				{
					'root/marker.txt': 'marker',
				},
				(dir) => {
					const root = join(dir.root, 'root')

					expect(() => {
						syncDirectory(root)
					}).not.toThrow()
				},
			)
		})

		it('throws SEAError with code OUTPUT for a nonexistent path', async () => {
			await withTestDir({}, (dir) => {
				const missing = join(dir.root, 'does-not-exist')

				const error = captureError(() => {
					syncDirectory(missing)
				})

				if (process.platform === 'win32') {
					// syncDirectory is a no-op on win32 — nothing to assert.
					return
				}

				expect(isSEAError(error) && error.code === 'OUTPUT').toBe(true)
			})
		})

		it('is a no-op-safe call after mkdirSync creates the directory', async () => {
			await withTestDir({}, (dir) => {
				const created = join(dir.root, 'created')
				mkdirSync(created)

				expect(() => {
					syncDirectory(created)
				}).not.toThrow()
			})
		})
	})

	describe('openBrowser', () => {
		// The valid-http(s)-URL spawn path is intentionally NOT exercised here —
		// it would launch a real browser process on the test/CI machine. Only
		// the deterministic, side-effect-free rejection paths are covered.

		it('rejects an unparseable URL', () => {
			const error = captureError(() => {
				openBrowser('not a url')
			})

			expect(isSEAError(error) && error.code === 'BROWSER').toBe(true)
		})

		it.each(['file:///etc/passwd', 'ftp://x', 'javascript:alert(1)'])(
			'rejects a non-http(s) scheme %s',
			(url) => {
				const error = captureError(() => {
					openBrowser(url)
				})

				expect(isSEAError(error) && error.code === 'BROWSER').toBe(true)
			},
		)

		it.each(['-e http://x', '--foo'])('rejects an argument-injection attempt %s', (value) => {
			const error = captureError(() => {
				openBrowser(value)
			})

			expect(isSEAError(error) && error.code === 'BROWSER').toBe(true)
		})
	})

	describe('createSignCommand', () => {
		it('builds argv for a cert file + password', () => {
			const argv = createSignCommand(
				{ file: 'cert.pfx', password: 'dummy-password' },
				'dist/app.exe',
			)

			expect(argv).toEqual([
				'signtool',
				'sign',
				'/fd',
				'sha256',
				'/f',
				'cert.pfx',
				'/p',
				'dummy-password',
				'dist/app.exe',
			])
		})

		it('builds argv for a store thumbprint', () => {
			const argv = createSignCommand(
				{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD' },
				'dist/app.exe',
			)

			expect(argv).toEqual([
				'signtool',
				'sign',
				'/fd',
				'sha256',
				'/sha1',
				'AABBCCDDEEFF00112233445566778899AABBCCDD',
				'dist/app.exe',
			])
		})

		it('appends /tr and /td when a timestamp is set', () => {
			const argv = createSignCommand(
				{
					thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD',
					timestamp: 'http://timestamp.example.com',
				},
				'dist/app.exe',
			)

			expect(argv).toEqual([
				'signtool',
				'sign',
				'/fd',
				'sha256',
				'/sha1',
				'AABBCCDDEEFF00112233445566778899AABBCCDD',
				'/tr',
				'http://timestamp.example.com',
				'/td',
				'sha256',
				'dist/app.exe',
			])
		})

		it('uses a custom digest for /fd and /td', () => {
			const argv = createSignCommand(
				{
					thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD',
					timestamp: 'https://timestamp.example.com',
					digest: 'sha1',
				},
				'dist/app.exe',
			)

			expect(argv).toEqual([
				'signtool',
				'sign',
				'/fd',
				'sha1',
				'/sha1',
				'AABBCCDDEEFF00112233445566778899AABBCCDD',
				'/tr',
				'https://timestamp.example.com',
				'/td',
				'sha1',
				'dist/app.exe',
			])
		})

		it('throws SEAError code SIGN when neither file nor thumbprint is set', () => {
			const error = captureError(() => {
				createSignCommand({}, 'dist/app.exe')
			})

			expect(isSEAError(error) && error.code === 'SIGN').toBe(true)
		})

		it('throws SEAError code SIGN when both file and thumbprint are set', () => {
			const error = captureError(() => {
				createSignCommand(
					{ file: 'cert.pfx', thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD' },
					'dist/app.exe',
				)
			})

			expect(isSEAError(error) && error.code === 'SIGN').toBe(true)
		})

		it('throws SEAError code SIGN when timestamp is not an http(s) URL', () => {
			const error = captureError(() => {
				createSignCommand(
					{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD', timestamp: 'ftp://x' },
					'dist/app.exe',
				)
			})

			expect(isSEAError(error) && error.code === 'SIGN').toBe(true)
		})

		it('throws SEAError code SIGN when timestamp is unparseable', () => {
			const error = captureError(() => {
				createSignCommand(
					{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD', timestamp: 'not a url' },
					'dist/app.exe',
				)
			})

			expect(isSEAError(error) && error.code === 'SIGN').toBe(true)
		})

		it('throws SEAError code SIGN for an unsupported digest', () => {
			const error = captureError(() => {
				createSignCommand(
					{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD', digest: 'md5' },
					'dist/app.exe',
				)
			})

			expect(isSEAError(error) && error.code === 'SIGN').toBe(true)
		})

		it('accepts sha384 and emits it for /fd', () => {
			const argv = createSignCommand(
				{ thumbprint: 'AABBCCDDEEFF00112233445566778899AABBCCDD', digest: 'sha384' },
				'dist/app.exe',
			)

			expect(argv).toEqual([
				'signtool',
				'sign',
				'/fd',
				'sha384',
				'/sha1',
				'AABBCCDDEEFF00112233445566778899AABBCCDD',
				'dist/app.exe',
			])
		})
	})
})
