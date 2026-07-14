import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { Injector, isSEAError, SEA_SENTINEL_FUSE } from '@src/server'
import { createInjectorOptions, withTestDir } from '../../../setupServer.js'
import { captureError } from '../../../setup.js'

// Local to this file only (Injector.test.ts owns this fixture; setupServer.ts
// is off-limits in this dispatch) — a minimal but structurally valid PE32
// image with one ".text" section and enough header slack for the injector to
// append a new section header entry.
function buildPeFixture(): Buffer {
	const headerSize = 0x1a0
	const fileAlignment = 0x200
	const fileSize = 0x400
	const buf = Buffer.alloc(fileSize)

	// DOS header
	buf.writeUInt16LE(0x5a4d, 0) // 'MZ'
	buf.writeUInt32LE(0x80, 0x3c) // e_lfanew

	const peOffset = 0x80
	const coffOffset = peOffset + 4
	const optionalOffset = coffOffset + 20
	const sectionTableOffset = optionalOffset + 224

	// PE signature
	buf.writeUInt32LE(0x00004550, peOffset)

	// COFF header
	buf.writeUInt16LE(0x14c, coffOffset) // Machine
	buf.writeUInt16LE(1, coffOffset + 2) // NumberOfSections
	buf.writeUInt32LE(0, coffOffset + 4) // TimeDateStamp
	buf.writeUInt32LE(0, coffOffset + 8) // PointerToSymbolTable
	buf.writeUInt32LE(0, coffOffset + 12) // NumberOfSymbols
	buf.writeUInt16LE(224, coffOffset + 16) // SizeOfOptionalHeader
	buf.writeUInt16LE(0x0102, coffOffset + 18) // Characteristics

	// Optional header (PE32)
	buf.writeUInt16LE(0x10b, optionalOffset) // Magic
	buf.writeUInt8(0, optionalOffset + 2) // MajorLinkerVersion
	buf.writeUInt8(0, optionalOffset + 3) // MinorLinkerVersion
	buf.writeUInt32LE(0, optionalOffset + 4) // SizeOfCode
	buf.writeUInt32LE(0, optionalOffset + 8) // SizeOfInitializedData
	buf.writeUInt32LE(0, optionalOffset + 12) // SizeOfUninitializedData
	buf.writeUInt32LE(0x1000, optionalOffset + 16) // AddressOfEntryPoint
	buf.writeUInt32LE(0x1000, optionalOffset + 20) // BaseOfCode
	buf.writeUInt32LE(0, optionalOffset + 24) // BaseOfData
	buf.writeUInt32LE(0x400000, optionalOffset + 28) // ImageBase
	buf.writeUInt32LE(0x1000, optionalOffset + 32) // SectionAlignment
	buf.writeUInt32LE(fileAlignment, optionalOffset + 36) // FileAlignment
	buf.writeUInt16LE(6, optionalOffset + 40) // MajorOSVersion
	buf.writeUInt16LE(0, optionalOffset + 42) // MinorOSVersion
	buf.writeUInt16LE(0, optionalOffset + 44) // MajorImageVersion
	buf.writeUInt16LE(0, optionalOffset + 46) // MinorImageVersion
	buf.writeUInt16LE(6, optionalOffset + 48) // MajorSubsystemVersion
	buf.writeUInt16LE(0, optionalOffset + 50) // MinorSubsystemVersion
	buf.writeUInt32LE(0, optionalOffset + 52) // Win32VersionValue
	buf.writeUInt32LE(0x2000, optionalOffset + 56) // SizeOfImage
	buf.writeUInt32LE(fileAlignment, optionalOffset + 60) // SizeOfHeaders
	buf.writeUInt32LE(0, optionalOffset + 64) // CheckSum (stale — recomputed by the injector)
	buf.writeUInt16LE(3, optionalOffset + 68) // Subsystem
	buf.writeUInt16LE(0, optionalOffset + 70) // DllCharacteristics
	buf.writeUInt32LE(0x100000, optionalOffset + 72) // SizeOfStackReserve
	buf.writeUInt32LE(0x1000, optionalOffset + 76) // SizeOfStackCommit
	buf.writeUInt32LE(0x100000, optionalOffset + 80) // SizeOfHeapReserve
	buf.writeUInt32LE(0x1000, optionalOffset + 84) // SizeOfHeapCommit
	buf.writeUInt32LE(0, optionalOffset + 88) // LoaderFlags
	buf.writeUInt32LE(16, optionalOffset + 92) // NumberOfRvaAndSizes
	// DataDirectories[16] at optionalOffset + 96 are left zeroed (no resources)

	// Section table: one ".text" section
	buf.write('.text', sectionTableOffset, 8, 'ascii')
	buf.writeUInt32LE(fileAlignment, sectionTableOffset + 8) // VirtualSize
	buf.writeUInt32LE(0x1000, sectionTableOffset + 12) // VirtualAddress
	buf.writeUInt32LE(fileAlignment, sectionTableOffset + 16) // SizeOfRawData
	buf.writeUInt32LE(fileAlignment, sectionTableOffset + 20) // PointerToRawData
	buf.writeUInt32LE(0, sectionTableOffset + 24) // PointerToRelocations
	buf.writeUInt32LE(0, sectionTableOffset + 28) // PointerToLinenumbers
	buf.writeUInt16LE(0, sectionTableOffset + 32) // NumberOfRelocations
	buf.writeUInt16LE(0, sectionTableOffset + 34) // NumberOfLinenumbers
	buf.writeUInt32LE(0x60000020, sectionTableOffset + 36) // Characteristics

	if (sectionTableOffset + 40 !== headerSize) {
		throw new Error('buildPeFixture: section table layout drifted from expected header size')
	}

	return buf
}

// Recomputes the classic Windows IMAGE checksum independently of the
// injector's implementation, to assert against without testing a tautology.
function computePeChecksum(buf: Buffer, checksumOffset: number): number {
	let sum = 0
	const length = buf.length
	for (let i = 0; i < length; i += 2) {
		let word: number
		if (i === checksumOffset || i === checksumOffset + 2) {
			word = 0
		} else if (i + 1 < length) {
			word = buf.readUInt16LE(i)
		} else {
			word = buf.readUInt8(i)
		}
		sum += word
		sum = (sum & 0xffff) + (sum >>> 16)
	}
	sum = (sum & 0xffff) + (sum >>> 16)
	return (sum + length) >>> 0
}

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

	it('recomputes a valid PE checksum after injecting a resource', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'test.exe')
			const blob = join(dir.root, 'blob.bin')

			writeFileSync(executable, buildPeFixture())
			writeFileSync(blob, 'blob content')

			const injector = new Injector(
				createInjectorOptions({
					executable,
					blob,
				}),
			)

			injector.inject()

			const result = readFileSync(executable)
			const peOffset = result.readUInt32LE(0x3c)
			const optionalOffset = peOffset + 4 + 20
			const checksumOffset = optionalOffset + 64
			const storedChecksum = result.readUInt32LE(checksumOffset)

			expect(storedChecksum).not.toBe(0)
			expect(storedChecksum).toBe(computePeChecksum(result, checksumOffset))
		})
	})

	it('recomputes the PE checksum AFTER the sentinel-fuse flip, not before', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'test.exe')
			const blob = join(dir.root, 'blob.bin')

			const fixture = buildPeFixture()
			// Embed the sentinel fuse (unset: ':0') so inject() flips it to ':1' —
			// this is the LAST PE mutation before the checksum must run, and
			// proves the checksum covers it (would fail if computed too early).
			const fuseBuf = Buffer.concat([Buffer.from(SEA_SENTINEL_FUSE, 'utf-8'), Buffer.from(':0')])
			fuseBuf.copy(fixture, fixture.length - fuseBuf.length - 16)

			writeFileSync(executable, fixture)
			writeFileSync(blob, 'blob content')

			const injector = new Injector(
				createInjectorOptions({
					executable,
					blob,
					fuse: SEA_SENTINEL_FUSE,
				}),
			)

			injector.inject()

			const result = readFileSync(executable)
			const peOffset = result.readUInt32LE(0x3c)
			const optionalOffset = peOffset + 4 + 20
			const checksumOffset = optionalOffset + 64
			const storedChecksum = result.readUInt32LE(checksumOffset)

			// Confirm the fuse was actually flipped (sanity check the fixture).
			const fuseIndex = result.indexOf(Buffer.from(SEA_SENTINEL_FUSE, 'utf-8'))
			expect(fuseIndex).not.toBe(-1)
			expect(
				result
					.subarray(fuseIndex + SEA_SENTINEL_FUSE.length, fuseIndex + SEA_SENTINEL_FUSE.length + 2)
					.toString(),
			).toBe(':1')

			// Recompute the checksum independently over the FINAL file (fuse
			// already flipped) — must match exactly, proving the checksum ran
			// after the fuse mutation, not before.
			expect(storedChecksum).not.toBe(0)
			expect(storedChecksum).toBe(computePeChecksum(result, checksumOffset))
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

			const error = captureError(() => {
				return new Injector(
					createInjectorOptions({
						executable,
						blob,
					}),
				)
			})

			expect(isSEAError(error) && error.code === 'FORMAT').toBe(true)
		})
	})

	it('throws for garbage binary content', async () => {
		await withTestDir({}, async (dir) => {
			const executable = join(dir.root, 'garbage.bin')
			const blob = join(dir.root, 'blob.bin')

			writeFileSync(executable, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00]))
			writeFileSync(blob, 'blob')

			const error = captureError(() => {
				return new Injector(
					createInjectorOptions({
						executable,
						blob,
					}),
				)
			})

			expect(isSEAError(error) && error.code === 'FORMAT').toBe(true)
		})
	})
})
