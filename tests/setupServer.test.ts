// Proves the behavior `tests/setupServer.ts` exports for this workspace's suites: the temporary
// directory wrapper, the option builders, and the synthetic PE/ELF/Mach-O fixtures the Injector
// suite parses. Every expectation is derived by a route the module cannot share — real `node:fs`
// reads rather than `ScratchInterface`, and raw header offsets with literal format magics rather
// than the constants the builders write from. The `setup` project runs in Node, so every contract
// here is reachable with real files.

import type { PeResourceLeaf } from './setupServer.js'
import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
	buildElfFixture,
	buildFatMachoFixture,
	buildMachoFixture,
	buildPeFixture,
	createInjectorOptions,
	createSEAOptions,
	findElfNotes,
	findMachoSection,
	parseElfProgramHeaders,
	parseMachoLoadCommands,
	parseMachoSegments,
	parsePeResourceLeaves,
	readPeResourceString,
	walkPeResourceDirectory,
	withTestDir,
	WORKSPACE_ROOT,
} from './setupServer.js'

describe('setupServer', () => {
	describe('WORKSPACE_ROOT', () => {
		it('anchors an absolute path at the directory holding this package manifest', () => {
			expect(isAbsolute(WORKSPACE_ROOT)).toBe(true)

			const manifest: unknown = JSON.parse(
				readFileSync(join(WORKSPACE_ROOT, 'package.json'), 'utf-8'),
			)
			const name =
				typeof manifest === 'object' && manifest !== null && 'name' in manifest
					? manifest.name
					: undefined

			expect(name).toBe('@orkestrel/sea')
		})
	})

	describe('withTestDir', () => {
		it('seeds the allocation, hands it to the callback, and removes it afterwards', async () => {
			let allocated = ''

			const returned = await withTestDir(
				{ 'entry.cjs': "console.log('seeded')\n", 'base/blob.bin': 'payload' },
				(scratch) => {
					allocated = scratch.path
					// Read with `node:fs` rather than `scratch.read`, so the assertion does not
					// return through the writer that seeded the files.
					expect(isAbsolute(scratch.path)).toBe(true)
					expect(readFileSync(join(scratch.path, 'entry.cjs'), 'utf-8')).toBe(
						"console.log('seeded')\n",
					)
					expect(readFileSync(join(scratch.path, 'base', 'blob.bin'), 'utf-8')).toBe('payload')
					return 'callback result'
				},
			)

			expect(returned).toBe('callback result')
			expect(allocated).not.toBe('')
			expect(existsSync(allocated)).toBe(false)
		})

		it('removes the allocation and rethrows when the callback throws', async () => {
			const failure = new Error('callback failed')
			let allocated = ''

			const thrown: unknown = await withTestDir({ 'entry.cjs': '' }, (scratch) => {
				allocated = scratch.path
				expect(existsSync(scratch.path)).toBe(true)
				throw failure
			}).then(
				() => undefined,
				(error: unknown) => error,
			)

			expect(thrown).toBe(failure)
			expect(existsSync(allocated)).toBe(false)
		})
	})

	describe('createSEAOptions', () => {
		it('builds a complete option set an override replaces one field of', () => {
			expect(createSEAOptions()).toEqual({
				name: 'sea-test',
				entry: { path: 'entry.cjs' },
				output: 'dist',
			})
			expect(createSEAOptions({ output: 'build', root: '/tmp/sea' })).toEqual({
				name: 'sea-test',
				entry: { path: 'entry.cjs' },
				output: 'build',
				root: '/tmp/sea',
			})
		})
	})

	describe('createInjectorOptions', () => {
		it('defaults the resource name and omits every option left unset', () => {
			const options = createInjectorOptions({ executable: 'app.exe', blob: 'blob.bin' })

			expect(options).toEqual({
				executable: 'app.exe',
				resource: 'NODE_SEA_BLOB',
				blob: 'blob.bin',
			})
			// An unset option is absent, never a key holding `undefined` — the workspace compiles
			// with `exactOptionalPropertyTypes`, which reads those two states apart.
			expect(
				Object.keys(options).filter((key) => ['fuse', 'overwrite', 'macho'].includes(key)),
			).toEqual([])
		})

		it('carries every supplied option through', () => {
			const options = createInjectorOptions({
				executable: 'app.exe',
				blob: 'blob.bin',
				resource: 'CUSTOM_BLOB',
				fuse: 'fuse-sentinel',
				overwrite: true,
				macho: { segment: 'CUSTOM_SEG' },
			})

			expect(options).toEqual({
				executable: 'app.exe',
				blob: 'blob.bin',
				resource: 'CUSTOM_BLOB',
				fuse: 'fuse-sentinel',
				overwrite: true,
				macho: { segment: 'CUSTOM_SEG' },
			})
		})
	})

	describe('buildPeFixture', () => {
		it('builds a PE32 image whose headers agree with each other', () => {
			const buf = buildPeFixture()

			expect(buf.readUInt16LE(0)).toBe(0x5a4d) // 'MZ'
			const peOffset = buf.readUInt32LE(0x3c)
			expect(buf.readUInt32LE(peOffset)).toBe(0x00004550) // 'PE\0\0'

			const coffOffset = peOffset + 4
			expect(buf.readUInt16LE(coffOffset + 2)).toBe(1) // NumberOfSections
			const optionalHeaderSize = buf.readUInt16LE(coffOffset + 16)
			expect(optionalHeaderSize).toBe(224) // PE32 optional header
			expect(buf.readUInt16LE(coffOffset + 20)).toBe(0x10b) // IMAGE_NT_OPTIONAL_HDR32_MAGIC

			const sectionTableOffset = coffOffset + 20 + optionalHeaderSize
			expect(buf.subarray(sectionTableOffset, sectionTableOffset + 5).toString('ascii')).toBe(
				'.text',
			)
			const rawSize = buf.readUInt32LE(sectionTableOffset + 16)
			const rawOffset = buf.readUInt32LE(sectionTableOffset + 20)
			// Slack past the one written section entry, so the injector can append another.
			expect(rawOffset).toBeGreaterThan(sectionTableOffset + 40)
			expect(rawOffset + rawSize).toBe(buf.length)
		})

		it('widens the optional header for the PE32+ variant', () => {
			const buf = buildPeFixture({ plus: true })
			const coffOffset = buf.readUInt32LE(0x3c) + 4

			expect(buf.readUInt16LE(coffOffset + 16)).toBe(240) // PE32+ optional header
			expect(buf.readUInt16LE(coffOffset + 20)).toBe(0x20b) // IMAGE_NT_OPTIONAL_HDR64_MAGIC

			// The section table follows the widened optional header rather than the PE32 one.
			const sectionTableOffset = coffOffset + 20 + 240
			expect(buf.subarray(sectionTableOffset, sectionTableOffset + 5).toString('ascii')).toBe(
				'.text',
			)
		})

		it('carries a pre-existing resource leaf that reads back through parsePeResourceLeaves', () => {
			const buf = buildPeFixture({ resources: true })
			const peOffset = buf.readUInt32LE(0x3c)

			expect(buf.readUInt16LE(peOffset + 4 + 2)).toBe(2) // NumberOfSections
			// PE32 resource data directory (entry 2): 24 bytes of headers, 96 bytes of fixed
			// optional-header fields, then two 8-byte entries.
			expect(buf.readUInt32LE(peOffset + 24 + 96 + 16)).toBe(0x2000)

			const leaves = parsePeResourceLeaves(buf, '.rsrc')
			expect(leaves.map((leaf) => leaf.nameName)).toEqual(['EXISTING'])
			expect(leaves.map((leaf) => leaf.typeId)).toEqual([3])
			expect(leaves.map((leaf) => leaf.language)).toEqual([0])
			expect(leaves.map((leaf) => leaf.data.toString('ascii'))).toEqual(['EXISTDAT'])

			expect(parsePeResourceLeaves(buf, '.rsrc2')).toEqual([])
		})

		it('appends a certificate overlay the security data directory points at', () => {
			const plain = buildPeFixture()
			const certSize = 512
			const buf = buildPeFixture({ cert: certSize })
			const peOffset = buf.readUInt32LE(0x3c)
			// PE32 security data directory (entry 4). Its VirtualAddress is a file offset, per the
			// PE specification's special case for this entry.
			const securityDirOffset = peOffset + 24 + 96 + 32

			expect(buf.length).toBe(plain.length + certSize)
			expect(buf.readUInt32LE(securityDirOffset)).toBe(plain.length)
			expect(buf.readUInt32LE(securityDirOffset + 4)).toBe(certSize)
			expect(buf.subarray(plain.length).every((byte) => byte === 0xcc)).toBe(true)

			expect(plain.readUInt32LE(plain.readUInt32LE(0x3c) + 24 + 96 + 32)).toBe(0)
		})
	})

	describe('readPeResourceString', () => {
		it('reads the declared number of UTF-16LE characters and stops there', () => {
			const buf = Buffer.alloc(24)
			buf.writeUInt16LE(4, 2)
			buf.write('NAMEtrailing', 4, 'utf16le')

			expect(readPeResourceString(buf, 2)).toBe('NAME')
		})

		it('returns an empty string for a zero-length entry', () => {
			const buf = Buffer.alloc(8)
			buf.writeUInt16LE(0, 0)
			buf.write('XY', 2, 'utf16le')

			expect(readPeResourceString(buf, 0)).toBe('')
		})
	})

	describe('walkPeResourceDirectory', () => {
		it('collects each leaf of a directory tree with its type, name, and data', () => {
			const buf = buildPeFixture({ resources: true })
			// The `.rsrc` header is the second section table entry: 24 bytes of PE and COFF
			// header, the 224-byte PE32 optional header, then one 40-byte entry.
			const rsrcHeaderOffset = buf.readUInt32LE(0x3c) + 24 + 224 + 40
			const section = {
				name: '.rsrc',
				virtualSize: buf.readUInt32LE(rsrcHeaderOffset + 8),
				virtualAddress: buf.readUInt32LE(rsrcHeaderOffset + 12),
				rawSize: buf.readUInt32LE(rsrcHeaderOffset + 16),
				rawOffset: buf.readUInt32LE(rsrcHeaderOffset + 20),
			}

			const leaves: PeResourceLeaf[] = []
			walkPeResourceDirectory(
				buf,
				[section],
				section.rawOffset,
				0,
				0,
				0,
				undefined,
				0,
				undefined,
				leaves,
			)

			expect(leaves.map((leaf) => leaf.typeId)).toEqual([3])
			expect(leaves.map((leaf) => leaf.nameName)).toEqual(['EXISTING'])
			expect(leaves.map((leaf) => leaf.language)).toEqual([0])
			expect(leaves.map((leaf) => leaf.data.toString('ascii'))).toEqual(['EXISTDAT'])
		})
	})

	describe('buildElfFixture', () => {
		it('builds an ELF64 image whose program header table matches its ELF header', () => {
			const buf = buildElfFixture()

			expect(buf.readUInt8(0)).toBe(0x7f)
			expect(buf.subarray(1, 4).toString('ascii')).toBe('ELF')
			expect(buf.readUInt8(4)).toBe(2) // ELFCLASS64
			expect(buf.readUInt8(5)).toBe(1) // ELFDATA2LSB

			const phdrOffset = Number(buf.readBigUInt64LE(32))
			const entrySize = buf.readUInt16LE(54)
			const entryCount = buf.readUInt16LE(56)
			expect(phdrOffset + entryCount * entrySize).toBeLessThanOrEqual(buf.length)

			const headers = parseElfProgramHeaders(buf)
			expect(headers.length).toBe(entryCount)
			// The PT_PHDR entry describes the table the ELF header points at.
			expect(headers.filter((header) => header.type === 6).map((header) => header.filesz)).toEqual([
				entryCount * entrySize,
			])
			const loads = headers.filter((header) => header.type === 1)
			expect(loads.map((header) => header.vaddr)).toEqual([0x400000, 0x401000])
			expect(loads.every((header) => header.offset + header.filesz <= buf.length)).toBe(true)
		})
	})

	describe('findElfNotes', () => {
		it('reports only the notes whose name carries the lookup prefix', () => {
			// The fixture writes no note, so this case writes one by hand over the third program
			// header entry: PT_NOTE pointing at a namesz/descsz/type/name/descriptor payload in the
			// image's trailing slack. Nothing here travels the module's own writer.
			const buf = buildElfFixture()
			const entryOffset = 64 + 2 * 56
			const noteOffset = 0x1000
			buf.writeUInt32LE(4, entryOffset) // p_type = PT_NOTE
			buf.writeBigUInt64LE(BigInt(noteOffset), entryOffset + 8) // p_offset
			buf.writeBigUInt64LE(32n, entryOffset + 32) // p_filesz
			buf.writeUInt32LE(9, noteOffset) // namesz, counting the terminator
			buf.writeUInt32LE(8, noteOffset + 4) // descsz
			buf.writeUInt32LE(1, noteOffset + 8) // note type
			buf.write('NODE_SEA\0', noteOffset + 12, 9, 'ascii')
			// The descriptor follows the name padded up to a 4-byte boundary: 12 + 12.
			buf.write('blobdata', noteOffset + 24, 8, 'ascii')

			const notes = findElfNotes(buf, 'NODE_SEA')
			expect(notes.map((note) => note.name)).toEqual(['NODE_SEA'])
			expect(notes.map((note) => note.descsz)).toEqual([8])
			expect(notes.map((note) => note.descriptor.toString('ascii'))).toEqual(['blobdata'])
			expect(notes.map((note) => note.header.offset)).toEqual([noteOffset])

			expect(findElfNotes(buf, 'GNU')).toEqual([])
		})
	})

	describe('buildMachoFixture', () => {
		it('builds a thin Mach-O 64 whose load commands fill the declared table', () => {
			const buf = buildMachoFixture()

			expect(buf.readUInt32LE(0)).toBe(0xfeedfacf) // MH_MAGIC_64
			expect(buf.readUInt32LE(12)).toBe(2) // MH_EXECUTE
			const commandCount = buf.readUInt32LE(16)
			const commandsSize = buf.readUInt32LE(20)

			const commands = parseMachoLoadCommands(buf)
			expect(commands.length).toBe(commandCount)
			expect(commands.reduce((total, command) => total + command.size, 0)).toBe(commandsSize)
			expect(
				commands.reduce((end, command) => Math.max(end, command.offset + command.size), 0),
			).toBe(32 + commandsSize)

			const segments = parseMachoSegments(buf)
			expect(segments.map((segment) => segment.name)).toEqual(['__TEXT', '__DATA', '__LINKEDIT'])
			// `__TEXT` starts at the file's head and `__LINKEDIT` runs to its end.
			expect(segments.map((segment) => segment.fileoff)).toEqual([0, 0x1100, 0x1200])
			expect(
				segments
					.filter((segment) => segment.name === '__LINKEDIT')
					.map((segment) => segment.fileoff + segment.filesize),
			).toEqual([buf.length])
		})

		it('leaves the tight variant no header room for another segment command', () => {
			const roomy = buildMachoFixture()
			const tight = buildMachoFixture({ tight: true })
			// The injector appends one LC_SEGMENT_64 carrying one section entry: 72 + 80 bytes.
			// A fixture with less than that between the end of the load commands (the 32-byte
			// header plus `sizeofcmds` at offset 20) and the first section's data has no room.
			const appended = 72 + 80
			// The `__TEXT` command sits at offset 32; its section entry follows 72 bytes in and
			// carries that section's file offset 48 bytes into the entry.
			const sectionOffsetField = 32 + 72 + 48

			expect(
				roomy.readUInt32LE(sectionOffsetField) - (32 + roomy.readUInt32LE(20)),
			).toBeGreaterThan(appended)
			expect(tight.readUInt32LE(sectionOffsetField) - (32 + tight.readUInt32LE(20))).toBeLessThan(
				appended,
			)
		})

		it('drops the __LINKEDIT segment command when the linkedit option omits it', () => {
			const roomy = buildMachoFixture()
			const without = buildMachoFixture({ linkedit: { present: false } })

			expect(parseMachoSegments(without).map((segment) => segment.name)).toEqual([
				'__TEXT',
				'__DATA',
			])
			// The table stays self-consistent: `ncmds` at offset 16 and `sizeofcmds` at
			// offset 20 both shrink by the dropped command, and the file keeps its
			// length, so the bytes `__LINKEDIT` covered are still there for `LC_SYMTAB`
			// to point at.
			const commands = parseMachoLoadCommands(without)
			expect(commands.length).toBe(parseMachoLoadCommands(roomy).length - 1)
			expect(commands.reduce((total, command) => total + command.size, 0)).toBe(
				without.readUInt32LE(20),
			)
			expect(without.readUInt32LE(16)).toBe(roomy.readUInt32LE(16) - 1)
			expect(without.length).toBe(roomy.length)
		})

		it('gives the __LINKEDIT segment command the section entries the linkedit option asks for', () => {
			const buf = buildMachoFixture({ linkedit: { sections: 1 } })
			const linkedit = parseMachoSegments(buf).find((segment) => segment.name === '__LINKEDIT')
			const section = findMachoSection(buf, '__LINKEDIT', '__link0')

			expect(linkedit?.nsects).toBe(1)
			// A declared entry is a real one: an LC_SEGMENT_64 command is 72 bytes plus
			// 80 per section entry, and the entry's file offset sits inside the
			// segment's own range rather than ahead of `__TEXT`.
			const commands = parseMachoLoadCommands(buf)
			const roomyCommands = parseMachoLoadCommands(buildMachoFixture())
			expect(roomyCommands[roomyCommands.length - 1]?.size).toBe(72)
			expect(commands[commands.length - 1]?.size).toBe(72 + 80)
			expect(commands.reduce((total, command) => total + command.size, 0)).toBe(
				buf.readUInt32LE(20),
			)
			expect(section?.segment).toBe('__LINKEDIT')
			expect(section?.offset).toBe(linkedit?.fileoff)
		})
	})

	describe('findMachoSection', () => {
		it('finds a section within its segment and refuses a name no segment carries', () => {
			const buf = buildMachoFixture()
			const section = findMachoSection(buf, '__TEXT', '__text')

			expect(section?.segment).toBe('__TEXT')
			expect(section?.offset).toBe(buf.readUInt32LE(32 + 72 + 48))
			expect(section?.size).toBe(buf.readBigUInt64LE(32 + 72 + 40))

			expect(findMachoSection(buf, '__TEXT', '__data')).toBeUndefined()
			expect(findMachoSection(buf, '__NODE_SEA', '__text')).toBeUndefined()
		})
	})

	describe('buildFatMachoFixture', () => {
		it('builds a fat header that carries neither thin magic', () => {
			const buf = buildFatMachoFixture()

			expect(buf.readUInt32BE(0)).toBe(0xcafebabe) // FAT_MAGIC
			expect(buf.readUInt32BE(4)).toBe(1) // nfat_arch
			expect(buf.readUInt32LE(0)).not.toBe(0xfeedfacf)
			expect(buf.readUInt16LE(0)).not.toBe(0x5a4d)
		})
	})
})
