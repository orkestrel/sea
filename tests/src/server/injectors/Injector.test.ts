import { chmodSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { Injector, isSEAError, SEA_SENTINEL_FUSE } from '@src/server'
import {
	buildElfFixture,
	buildFatMachoFixture,
	buildMachoFixture,
	buildPeFixture,
	createInjectorOptions,
	findElfNotes,
	findMachoSection,
	parseElfProgramHeaders,
	parseMachoLoadCommands,
	parseMachoSegments,
	parsePeResourceLeaves,
	withTestDir,
} from '../../../setupServer.js'
import { captureError } from '@orkestrel/test'

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
	describe('detection', () => {
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

				const injector = new Injector(createInjectorOptions({ executable, blob }))

				expect(injector.format).toBe('pe')
			})
		})

		it('detects ELF executables', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
				writeFileSync(blob, 'blob')

				const injector = new Injector(createInjectorOptions({ executable, blob }))

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

				const injector = new Injector(createInjectorOptions({ executable, blob }))

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
					return new Injector(createInjectorOptions({ executable, blob }))
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
					return new Injector(createInjectorOptions({ executable, blob }))
				})

				expect(isSEAError(error) && error.code === 'FORMAT').toBe(true)
			})
		})
	})

	describe('ELF injection', () => {
		it('injects a PT_NOTE that is reachable via a mapped PT_LOAD (memory-residency invariant)', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')
				const blobContent = 'sea blob payload for elf note injection'

				writeFileSync(executable, buildElfFixture())
				writeFileSync(blob, blobContent)

				const injector = new Injector(createInjectorOptions({ executable, blob }))

				expect(() => injector.inject()).not.toThrow()

				const result = readFileSync(executable)
				const headers = parseElfProgramHeaders(result)
				const notes = findElfNotes(result, 'NODE_SEA')

				expect(notes).toHaveLength(1)
				const note = notes[0]
				expect(note).toBeDefined()
				if (note === undefined) return

				expect(note.descsz).toBe(blobContent.length)
				expect(note.descriptor.subarray(0, blobContent.length).toString('utf-8')).toBe(blobContent)

				const covering = headers.find(
					(load) =>
						load.type === 1 &&
						note.header.offset >= load.offset &&
						note.header.offset < load.offset + load.filesz,
				)
				expect(covering).toBeDefined()
				if (covering === undefined) return

				expect(note.header.vaddr).toBe(covering.vaddr + (note.header.offset - covering.offset))

				const originalPhnum = 3
				const newPhnum = result.readUInt16LE(56)
				expect(newPhnum).toBeGreaterThan(originalPhnum)
			})
		})

		it('leaves exactly one active NODE_SEA PT_NOTE when injected twice (overwrite)', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildElfFixture())
				writeFileSync(blob, 'first blob content')

				new Injector(createInjectorOptions({ executable, blob })).inject()

				writeFileSync(blob, 'second, different blob content')
				new Injector(createInjectorOptions({ executable, blob })).inject()

				const result = readFileSync(executable)
				const notes = findElfNotes(result, 'NODE_SEA')

				expect(notes).toHaveLength(1)
				const note = notes[0]
				expect(
					note?.descriptor.subarray(0, 'second, different blob content'.length).toString(),
				).toBe('second, different blob content')
			})
		})
	})

	describe('Mach-O injection', () => {
		it('injects a NODE_SEA segment placed immediately before a relocated __LINKEDIT ending at EOF', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')
				const blobContent = 'sea blob payload for macho segment injection'

				writeFileSync(executable, buildMachoFixture())
				chmodSync(executable, 0o755)
				writeFileSync(blob, blobContent)

				const injector = new Injector(createInjectorOptions({ executable, blob }))
				const modeBefore = statSync(executable).mode

				expect(() => injector.inject()).not.toThrow()

				// The streamed rewrite (temp file + atomic rename) must preserve the
				// executable's mode exactly, and must not leave its `.inject-*.tmp`
				// staging file behind.
				expect(statSync(executable).mode).toBe(modeBefore)
				const leftoverTemp = readdirSync(dir.root).filter((name) => name.startsWith('.inject-'))
				expect(leftoverTemp).toEqual([])

				const result = readFileSync(executable)
				const segments = parseMachoSegments(result)
				const fileLength = result.length

				const linkedit = segments.find((s) => s.name === '__LINKEDIT')
				expect(linkedit).toBeDefined()
				if (linkedit === undefined) return

				// __LINKEDIT is the last segment by fileoff and ends at EOF
				const lastByFileoff = [...segments].sort((a, b) => b.fileoff - a.fileoff)[0]
				expect(lastByFileoff?.name).toBe('__LINKEDIT')
				expect(linkedit.fileoff + linkedit.filesize).toBe(fileLength)

				const nodeSea = segments.find((s) => s.name === 'NODE_SEA')
				expect(nodeSea).toBeDefined()
				if (nodeSea === undefined) return

				expect(nodeSea.fileoff + nodeSea.filesize).toBe(linkedit.fileoff)

				const section = findMachoSection(result, 'NODE_SEA', '__NODE_SEA_BLOB')
				expect(section).toBeDefined()
				if (section === undefined) return

				expect(section.size).toBe(BigInt(blobContent.length))
				expect(
					section.addr >= nodeSea.vmaddr && section.addr < nodeSea.vmaddr + nodeSea.vmsize,
				).toBe(true)

				const blobBytes = result.subarray(section.offset, section.offset + blobContent.length)
				expect(blobBytes.toString('utf-8')).toBe(blobContent)

				// LC_SYMTAB/LC_DYSYMTAB offsets shifted by `shift`, and ncmds/sizeofcmds updated
				const original = buildMachoFixture()
				const originalNcmds = original.readUInt32LE(16)
				const originalSizeofcmds = original.readUInt32LE(20)
				const newNcmds = result.readUInt32LE(16)
				const newSizeofcmds = result.readUInt32LE(20)
				expect(newNcmds).toBe(originalNcmds + 1) // one new NODE_SEA segment command added
				expect(newSizeofcmds).toBeGreaterThan(originalSizeofcmds)

				const shift = nodeSea.filesize
				expect(shift).toBeGreaterThan(0)

				// The NODE_SEA segment command must precede __LINKEDIT's segment
				// command in the rebuilt load-command list, keeping segments in
				// ascending vmaddr order with __LINKEDIT textually last.
				const loadCommands = parseMachoLoadCommands(result)
				const nodeSeaCmdIndex = loadCommands.findIndex((c) => c.offset === nodeSea.offset)
				const linkeditCmdIndex = loadCommands.findIndex((c) => c.offset === linkedit.offset)
				expect(nodeSeaCmdIndex).toBeGreaterThanOrEqual(0)
				expect(linkeditCmdIndex).toBeGreaterThanOrEqual(0)
				expect(nodeSeaCmdIndex).toBeLessThan(linkeditCmdIndex)
			})
		})

		it('leaves exactly one NODE_SEA segment when injected twice (overwrite)', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildMachoFixture())
				writeFileSync(blob, 'first payload')

				new Injector(createInjectorOptions({ executable, blob })).inject()

				writeFileSync(blob, 'second, different payload content')
				new Injector(createInjectorOptions({ executable, blob })).inject()

				const result = readFileSync(executable)
				const nodeSeaSegments = parseMachoSegments(result).filter((s) => s.name === 'NODE_SEA')

				expect(nodeSeaSegments).toHaveLength(1)

				const section = findMachoSection(result, 'NODE_SEA', '__NODE_SEA_BLOB')
				expect(section?.size).toBe(BigInt('second, different payload content'.length))
			})
		})

		it('throws INJECT when there is not enough header space for the new load command', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildMachoFixture({ tightHeaders: true }))
				writeFileSync(blob, 'blob content')

				const error = captureError(() => {
					new Injector(createInjectorOptions({ executable, blob })).inject()
				})

				expect(isSEAError(error) && error.code === 'INJECT').toBe(true)
			})
		})

		it('rejects a fat/universal Mach-O with a coded FORMAT error', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'fat.bin')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildFatMachoFixture())
				writeFileSync(blob, 'blob')

				const error = captureError(() => {
					return new Injector(createInjectorOptions({ executable, blob }))
				})

				expect(isSEAError(error) && error.code === 'FORMAT').toBe(true)
			})
		})
	})

	describe('PE injection', () => {
		it('recomputes a valid PE checksum after injecting a resource', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test.exe')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildPeFixture())
				writeFileSync(blob, 'blob content')

				const injector = new Injector(createInjectorOptions({ executable, blob }))

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
					createInjectorOptions({ executable, blob, fuse: SEA_SENTINEL_FUSE }),
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
						.subarray(
							fuseIndex + SEA_SENTINEL_FUSE.length,
							fuseIndex + SEA_SENTINEL_FUSE.length + 2,
						)
						.toString(),
				).toBe(':1')

				// Recompute the checksum independently over the FINAL file (fuse
				// already flipped) — must match exactly, proving the checksum ran
				// after the fuse mutation, not before.
				expect(storedChecksum).not.toBe(0)
				expect(storedChecksum).toBe(computePeChecksum(result, checksumOffset))
			})
		})

		it('injects into a PE32+ (64-bit) image successfully', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test.exe')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildPeFixture({ plus: true }))
				writeFileSync(blob, 'blob content for pe32plus')

				const injector = new Injector(createInjectorOptions({ executable, blob }))

				expect(() => injector.inject()).not.toThrow()

				const result = readFileSync(executable)
				const leaves = parsePeResourceLeaves(result, '.rsrc2')
				const blobLeaf = leaves.find((l) => l.nameName?.toUpperCase() === 'NODE_SEA_BLOB')

				expect(blobLeaf).toBeDefined()
				expect(blobLeaf?.data.length).toBe('blob content for pe32plus'.length)

				const peOffset = result.readUInt32LE(0x3c)
				const optionalOffset = peOffset + 4 + 20
				const checksumOffset = optionalOffset + 64
				const storedChecksum = result.readUInt32LE(checksumOffset)
				expect(storedChecksum).not.toBe(0)
				expect(storedChecksum).toBe(computePeChecksum(result, checksumOffset))
			})
		})

		it('preserves an existing resource leaf while adding the blob leaf', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test.exe')
				const blob = join(dir.root, 'blob.bin')

				writeFileSync(executable, buildPeFixture({ resources: true }))
				writeFileSync(blob, 'the injected blob')

				const injector = new Injector(createInjectorOptions({ executable, blob }))
				injector.inject()

				const result = readFileSync(executable)
				const leaves = parsePeResourceLeaves(result, '.rsrc2')

				const existingLeaf = leaves.find((l) => l.nameName === 'EXISTING')
				expect(existingLeaf).toBeDefined()
				expect(existingLeaf?.data.toString('ascii')).toBe('EXISTDAT')

				const blobLeaf = leaves.find((l) => l.nameName?.toUpperCase() === 'NODE_SEA_BLOB')
				expect(blobLeaf).toBeDefined()
				expect(blobLeaf?.data.length).toBe('the injected blob'.length)
			})
		})

		it('throws FORMAT for malformed (non-power-of-two) PE alignment', async () => {
			await withTestDir({}, async (dir) => {
				const executable = join(dir.root, 'test.exe')
				const blob = join(dir.root, 'blob.bin')

				const fixture = buildPeFixture()
				const peOffset = fixture.readUInt32LE(0x3c)
				const optionalOffset = peOffset + 4 + 20
				fixture.writeUInt32LE(0, optionalOffset + 36) // FileAlignment = 0

				writeFileSync(executable, fixture)
				writeFileSync(blob, 'blob content')

				const error = captureError(() => {
					new Injector(createInjectorOptions({ executable, blob })).inject()
				})

				expect(isSEAError(error) && error.code === 'FORMAT').toBe(true)
			})
		})
	})
})
