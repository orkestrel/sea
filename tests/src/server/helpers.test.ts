import { closeSync, openSync, readFileSync, readSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
	alignELFNoteSize,
	buildELFNoteHeader,
	compressDirectory,
	compressFile,
	computeSize,
	copyRange,
	createBlobConfig,
	createSignCommand,
	ensureContained,
	ensureSafeKey,
	ensureSafeName,
	finalizeExecutable,
	formatSize,
	isPEExecutable,
	isPowerOfTwo,
	isSEAError,
	isShellError,
	openBrowser,
	parsePEOffset,
	patchPESubsystem,
	patchSentinelFuse,
	readU16,
	redactCommand,
	runShell,
	stripPESignature,
	syncDirectory,
	walkDirectory,
	writeU16,
} from '@src/server'
import { buildPeFixture, withTestDir } from '../../setupServer.js'
import { captureError } from '@orkestrel/test'

describe('helpers', () => {
	describe('redactCommand', () => {
		it('redacts values following case-insensitive password flags without mutating the input', () => {
			const command = ['signtool', '/P', 'secret', '--password', 'other', 'target.exe']

			expect(redactCommand(command)).toEqual([
				'signtool',
				'/P',
				'***',
				'--password',
				'***',
				'target.exe',
			])
			expect(command).toEqual(['signtool', '/P', 'secret', '--password', 'other', 'target.exe'])
		})
	})

	describe('runShell', () => {
		it('returns stdout on success', () => {
			const stdout = runShell([process.execPath, '-e', "process.stdout.write('ok')"])

			expect(stdout.toString('utf-8')).toBe('ok')
		})

		it('throws SEAError code STATE for an empty command array', () => {
			const error = captureError(() => {
				return runShell([])
			})

			expect(isSEAError(error) && error.code === 'STATE').toBe(true)
		})

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
				(scratch) => {
					const base = join(scratch.path, 'base')
					const real = ensureContained(base, 'inside.txt')

					expect(scratch.has(real)).toBe(true)
				},
			)
		})

		it('rejects a symlink that escapes the base via realpath', async (context) => {
			await withTestDir(
				{
					'base/marker.txt': 'marker',
					'outside/secret.txt': 'secret',
				},
				(scratch) => {
					const base = join(scratch.path, 'base')
					const outside = join(scratch.path, 'outside')
					const link = join(base, 'escaped')

					try {
						scratch.link(link, outside)
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
				(scratch) => {
					const base = join(scratch.path, 'base')

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
				(scratch) => {
					const source = join(scratch.path, 'app.tmp')
					const target = join(scratch.path, 'app')

					finalizeExecutable(source, target)

					expect(scratch.read('app')).toBe('new content')
					expect(scratch.has('app.tmp')).toBe(false)
				},
			)
		})
	})

	describe('copyRange', () => {
		it('copies a range from a nonzero start', async () => {
			await withTestDir({}, (scratch) => {
				const sourcePath = join(scratch.path, 'source.bin')
				const targetPath = join(scratch.path, 'target.bin')
				const source = Buffer.from('0123456789abcdefghij', 'utf-8')
				writeFileSync(sourcePath, source)
				writeFileSync(targetPath, Buffer.alloc(0))

				const srcFd = openSync(sourcePath, 'r')
				const dstFd = openSync(targetPath, 'w')
				try {
					copyRange(srcFd, dstFd, 5, 6)
				} finally {
					closeSync(srcFd)
					closeSync(dstFd)
				}

				expect(scratch.read('target.bin')).toBe('56789a')
			})
		})

		it('copies a partial length shorter than the source', async () => {
			await withTestDir({}, (scratch) => {
				const sourcePath = join(scratch.path, 'source.bin')
				const targetPath = join(scratch.path, 'target.bin')
				writeFileSync(sourcePath, Buffer.from('the quick brown fox', 'utf-8'))
				writeFileSync(targetPath, Buffer.alloc(0))

				const srcFd = openSync(sourcePath, 'r')
				const dstFd = openSync(targetPath, 'w')
				try {
					copyRange(srcFd, dstFd, 0, 3)
				} finally {
					closeSync(srcFd)
					closeSync(dstFd)
				}

				expect(scratch.read('target.bin')).toBe('the')
			})
		})

		it('is a no-op when length is 0', async () => {
			await withTestDir({}, (scratch) => {
				const sourcePath = join(scratch.path, 'source.bin')
				const targetPath = join(scratch.path, 'target.bin')
				writeFileSync(sourcePath, Buffer.from('anything', 'utf-8'))
				writeFileSync(targetPath, Buffer.alloc(0))

				const srcFd = openSync(sourcePath, 'r')
				const dstFd = openSync(targetPath, 'w')
				try {
					copyRange(srcFd, dstFd, 2, 0)
				} finally {
					closeSync(srcFd)
					closeSync(dstFd)
				}

				expect(readFileSync(targetPath).length).toBe(0)
			})
		})

		it('spans multiple chunks when the range exceeds chunk size', async () => {
			await withTestDir({}, (scratch) => {
				const sourcePath = join(scratch.path, 'source.bin')
				const targetPath = join(scratch.path, 'target.bin')
				const source = Buffer.from('abcdefghijklmnopqrstuvwxyz', 'utf-8')
				writeFileSync(sourcePath, source)
				writeFileSync(targetPath, Buffer.alloc(0))

				const srcFd = openSync(sourcePath, 'r')
				const dstFd = openSync(targetPath, 'w')
				try {
					// chunk=4 forces the read/write loop to iterate multiple times
					// over the 13-byte range starting at offset 3.
					copyRange(srcFd, dstFd, 3, 13, 4)
				} finally {
					closeSync(srcFd)
					closeSync(dstFd)
				}

				expect(scratch.read('target.bin')).toBe(source.subarray(3, 16).toString('utf-8'))
			})
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
				(scratch) => {
					const root = join(scratch.path, 'root')
					const target = join(scratch.path, 'outside.txt')
					const link = join(root, 'escaped.txt')

					try {
						scratch.link(link, target)
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
				(scratch) => {
					const root = join(scratch.path, 'root')
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
				(scratch) => {
					const root = join(scratch.path, 'root')
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
				(scratch) => {
					const root = join(scratch.path, 'root')

					expect(() => {
						syncDirectory(root)
					}).not.toThrow()
				},
			)
		})

		it('throws SEAError with code OUTPUT for a nonexistent path', async () => {
			await withTestDir({}, (scratch) => {
				const missing = join(scratch.path, 'does-not-exist')

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

		it('is a no-op-safe call after ensure creates the directory', async () => {
			await withTestDir({}, (scratch) => {
				const created = scratch.ensure('created')

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

	describe('parsePEOffset / readU16 / writeU16 / isPEExecutable', () => {
		it('parses the PE header offset from a valid PE fixture', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				const buf = buildPeFixture()
				writeFileSync(path, buf)

				const fd = openSync(path, 'r')
				try {
					expect(parsePEOffset(fd)).toBe(buf.readUInt32LE(0x3c))
				} finally {
					closeSync(fd)
				}
			})
		})

		it('returns 0 for a file too short to contain the e_lfanew field', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'short.bin')
				writeFileSync(path, Buffer.alloc(8))

				const fd = openSync(path, 'r')
				try {
					expect(parsePEOffset(fd)).toBe(0)
				} finally {
					closeSync(fd)
				}
			})
		})

		it('round-trips readU16/writeU16 including boundary values', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'scratch.bin')
				writeFileSync(path, Buffer.alloc(16))

				const fd = openSync(path, 'r+')
				try {
					for (const value of [0, 1, 0x1234, 0xfffe, 0xffff]) {
						writeU16(fd, 4, value)
						expect(readU16(fd, 4)).toBe(value)
					}
				} finally {
					closeSync(fd)
				}
			})
		})

		it('is little-endian', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'endian.bin')
				writeFileSync(path, Buffer.alloc(4))

				const fd = openSync(path, 'r+')
				try {
					writeU16(fd, 0, 0x0102)
					const raw = Buffer.alloc(2)
					readSync(fd, raw, 0, 2, 0)
					expect(raw[0]).toBe(0x02)
					expect(raw[1]).toBe(0x01)
				} finally {
					closeSync(fd)
				}
			})
		})

		it('recognizes a valid PE fixture as a PE executable', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				writeFileSync(path, buildPeFixture())

				expect(isPEExecutable(path)).toBe(true)
			})
		})

		it('rejects non-PE bytes', async () => {
			await withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'not-pe.bin')
				writeFileSync(path, Buffer.from('this is not a PE file at all'))

				expect(isPEExecutable(path)).toBe(false)
			})
		})

		it('rejects a nonexistent path', () => {
			expect(isPEExecutable('/does/not/exist.exe')).toBe(false)
		})
	})

	describe('patchPESubsystem', () => {
		it.each([false, true])(
			'patches the subsystem u16 without touching neighbors (plus=%s)',
			(plus) => {
				return withTestDir({}, (scratch) => {
					const path = join(scratch.path, 'app.exe')
					const original = buildPeFixture({ plus })
					writeFileSync(path, original)

					const peOffset = original.readUInt32LE(0x3c)
					const subsystemOffset = peOffset + 0x5c

					patchPESubsystem(path, 2)

					const patched = readFileSync(path)
					expect(patched.readUInt16LE(subsystemOffset)).toBe(2)
					// Neighboring bytes (DllCharacteristics before, and 2 bytes after)
					// must be untouched.
					expect(patched.readUInt16LE(subsystemOffset - 2)).toBe(
						original.readUInt16LE(subsystemOffset - 2),
					)
					expect(patched.readUInt16LE(subsystemOffset + 2)).toBe(
						original.readUInt16LE(subsystemOffset + 2),
					)
				})
			},
		)
	})

	describe('stripPESignature', () => {
		it.each([false, true])('zeroes the 8-byte security directory entry (plus=%s)', (plus) => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				const buf = buildPeFixture({ plus })
				const peOffset = buf.readUInt32LE(0x3c)
				const securityDirOffset = plus ? peOffset + 168 : peOffset + 152

				// Plant a nonzero directory entry so zeroing is observable, without
				// making it point at a real trailing certificate (offset+size !=
				// EOF here), so no truncation should occur.
				buf.writeUInt32LE(0x1234, securityDirOffset)
				buf.writeUInt32LE(0x10, securityDirOffset + 4)
				const before = Buffer.from(buf)
				writeFileSync(path, buf)

				stripPESignature(path)

				const after = readFileSync(path)
				expect(after.readUInt32LE(securityDirOffset)).toBe(0)
				expect(after.readUInt32LE(securityDirOffset + 4)).toBe(0)
				// Neighbors untouched.
				expect(after.readUInt32LE(securityDirOffset - 4)).toBe(
					before.readUInt32LE(securityDirOffset - 4),
				)
				expect(after.readUInt32LE(securityDirOffset + 8)).toBe(
					before.readUInt32LE(securityDirOffset + 8),
				)
				expect(after.length).toBe(before.length)
			})
		})

		it('truncates a trailing certificate overlay described by the security directory', () => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'signed.exe')
				const certSize = 64
				const withCert = buildPeFixture({ cert: certSize })
				const expectedTruncatedSize = withCert.length - certSize
				writeFileSync(path, withCert)

				stripPESignature(path)

				const after = readFileSync(path)
				expect(after.length).toBe(expectedTruncatedSize)

				const peOffset = after.readUInt32LE(0x3c)
				const securityDirOffset = peOffset + 152
				expect(after.readUInt32LE(securityDirOffset)).toBe(0)
				expect(after.readUInt32LE(securityDirOffset + 4)).toBe(0)
			})
		})
	})

	describe('patchSentinelFuse', () => {
		function buildFuseFixture(fuse: string, value: string): Buffer {
			return Buffer.concat([
				Buffer.from('padding-before-fuse-'),
				Buffer.from(fuse, 'utf-8'),
				Buffer.from(value, 'utf-8'),
				Buffer.from('-padding-after'),
			])
		}

		it('flips an unset fuse from :0 to :1', () => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				writeFileSync(path, buildFuseFixture('MY_FUSE', ':0'))

				patchSentinelFuse(path, 'MY_FUSE')

				const after = scratch.read('app.exe')
				expect(after?.includes('MY_FUSE:1')).toBe(true)
			})
		})

		it('is a no-op when the fuse is already flipped to :1', () => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				const buf = buildFuseFixture('MY_FUSE', ':1')
				writeFileSync(path, buf)

				patchSentinelFuse(path, 'MY_FUSE')

				const after = readFileSync(path)
				expect(Buffer.compare(after, buf)).toBe(0)
			})
		})

		it('throws SEAError code FUSE for an unexpected sentinel value', () => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				writeFileSync(path, buildFuseFixture('MY_FUSE', ':X'))

				const error = captureError(() => {
					patchSentinelFuse(path, 'MY_FUSE')
				})

				expect(isSEAError(error) && error.code === 'FUSE').toBe(true)
			})
		})

		it('throws SEAError code FUSE when the sentinel is not found', () => {
			return withTestDir({}, (scratch) => {
				const path = join(scratch.path, 'app.exe')
				writeFileSync(path, Buffer.from('no fuse token here at all'))

				const error = captureError(() => {
					patchSentinelFuse(path, 'MY_FUSE')
				})

				expect(isSEAError(error) && error.code === 'FUSE').toBe(true)
			})
		})
	})

	describe('computeSize', () => {
		it('returns ratio 0 when original is 0', () => {
			expect(computeSize(0, 0)).toEqual({ original: 0, compressed: 0, ratio: 0 })
		})

		it('computes the compression ratio', () => {
			expect(computeSize(100, 50)).toEqual({ original: 100, compressed: 50, ratio: 0.5 })
		})

		it('allows a ratio above 1 (compressed larger than original)', () => {
			const result = computeSize(10, 20)
			expect(result.ratio).toBe(2)
		})
	})

	describe('formatSize', () => {
		it('formats 0 bytes', () => {
			expect(formatSize(0)).toBe('0 B')
		})

		it('formats bytes below the KB threshold', () => {
			expect(formatSize(1023)).toBe('1023 B')
		})

		it('formats at the KB threshold', () => {
			expect(formatSize(1024)).toBe('1.0 KB')
		})

		it('formats at the MB threshold', () => {
			expect(formatSize(1024 * 1024)).toBe('1.00 MB')
		})

		it('formats a very large value using the MB branch (no GB threshold)', () => {
			expect(formatSize(5 * 1024 * 1024 * 1024)).toBe('5120.00 MB')
		})
	})

	describe('compressFile', () => {
		it('compresses a real file to the requested output', async () => {
			await withTestDir(
				{
					'input.html': '<p>hello hello hello</p>',
				},
				(scratch) => {
					const input = join(scratch.path, 'input.html')
					const output = join(scratch.path, 'input.html.br')

					const result = compressFile(input, output)

					expect(scratch.has('input.html.br')).toBe(true)
					expect(result.input).toBe(input)
					expect(result.output).toBe(output)
					expect(result.size.original).toBeGreaterThan(0)
					expect(result.size.compressed).toBeGreaterThan(0)
				},
			)
		})

		it('refuses to write compressed output through a planted symlink', async (context) => {
			await withTestDir(
				{
					'input.html': '<p>hello</p>',
					'victim.txt': 'do not touch me',
				},
				(scratch) => {
					const input = join(scratch.path, 'input.html')
					const victim = join(scratch.path, 'victim.txt')
					const output = join(scratch.path, 'input.html.br')

					try {
						scratch.link(output, victim)
					} catch {
						context.skip()
						return
					}

					const error = captureError(() => {
						compressFile(input, output)
					})

					expect(isSEAError(error) && error.code === 'OUTPUT').toBe(true)
					expect(scratch.read('victim.txt')).toBe('do not touch me')
				},
			)
		})
	})

	describe('buildELFNoteHeader', () => {
		it('encodes namesz/descsz/type and the 4-padded name', () => {
			const { header, entryTotal } = buildELFNoteHeader('NODE_SEA_BLOB', 4096)

			expect(header.readUInt32LE(0)).toBe('NODE_SEA_BLOB'.length + 1) // namesz includes NUL
			expect(header.readUInt32LE(4)).toBe(4096) // descsz
			expect(header.readUInt32LE(8)).toBe(0) // type
			expect(header.toString('utf-8', 12, 12 + 'NODE_SEA_BLOB'.length + 1)).toBe('NODE_SEA_BLOB\0')
			// name region is 4-byte-padded: namesz=14 aligns up to 16
			expect(header.length).toBe(12 + 16)
			expect(entryTotal).toBe(header.length + 4096)
		})

		it('4-byte-pads the blob size in entryTotal when it is not aligned', () => {
			const { header, entryTotal } = buildELFNoteHeader('X', 10)

			// namesz = 2 ('X\0'), aligned to 4
			expect(header.length).toBe(12 + 4)
			// blobSize 10 aligns up to 12
			expect(entryTotal).toBe(header.length + 12)
		})
	})

	describe('alignELFNoteSize', () => {
		it.each([
			[0, 0],
			[1, 4],
			[4, 4],
			[5, 8],
		])('aligns %i to %i bytes', (value, expected) => {
			expect(alignELFNoteSize(value)).toBe(expected)
		})
	})

	describe('isPowerOfTwo', () => {
		it.each([
			[-2, false],
			[0, false],
			[1, true],
			[2, true],
			[3, false],
			[1024, true],
		])('classifies %i as %s', (value, expected) => {
			expect(isPowerOfTwo(value)).toBe(expected)
		})
	})
})
