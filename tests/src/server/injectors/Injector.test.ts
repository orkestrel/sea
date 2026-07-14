import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { Injector } from '@src/server'
import { createInjectorOptions, withTestDir } from '../../../setupServer.js'

describe('Injector', () => {
	it('detects PE executables', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'test.exe')
			const blob = join(dir.root, 'blob.bin')
			const buffer = Buffer.alloc(0x44)

			buffer.writeUInt16LE(0x5a4d, 0)
			buffer.writeUInt32LE(0x40, 0x3c)
			buffer.writeUInt32LE(0x00004550, 0x40)

			writeFileSync(executable, buffer)
			writeFileSync(blob, 'blob')

			const injector = new Injector(
				createInjectorOptions({
					executable,
					blob,
				}),
			)

			expect(injector.format).toBe('pe')
		})
	})

	it('detects ELF executables', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'test')
			const blob = join(dir.root, 'blob.bin')

			writeFileSync(executable, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
			writeFileSync(blob, 'blob')

			const injector = new Injector(
				createInjectorOptions({
					executable,
					blob,
				}),
			)

			expect(injector.format).toBe('elf')
		})
	})

	it('detects Mach-O executables', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'test')
			const blob = join(dir.root, 'blob.bin')
			const buffer = Buffer.alloc(4)

			buffer.writeUInt32LE(0xfeedfacf, 0)

			writeFileSync(executable, buffer)
			writeFileSync(blob, 'blob')

			const injector = new Injector(
				createInjectorOptions({
					executable,
					blob,
				}),
			)

			expect(injector.format).toBe('macho')
		})
	})

	it('throws for unknown executable formats', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'unknown.bin')
			const blob = join(dir.root, 'blob.bin')

			writeFileSync(executable, Buffer.from([0x00, 0x01, 0x02, 0x03]))
			writeFileSync(blob, 'blob')

			expect(() => {
				return new Injector(
					createInjectorOptions({
						executable,
						blob,
					}),
				)
			}).toThrow('Unknown executable format')
		})
	})
})
