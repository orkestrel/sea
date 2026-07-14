// Server-test setup — node-only helpers, loaded after `setup.ts` for the node
// `src:server` (and `guides`) projects. `node:fs` / `node:path` imports belong
// here, never in `setup.ts`. Anchor every path to `WORKSPACE_ROOT` so the
// runner's cwd never matters (AGENTS §16.1).

import type { InjectorOptions, SEAOptions } from '@src/server'
import * as fs from 'node:fs'
import * as nodePath from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import {
	ELF_CLASS_64,
	ELF_DATA_LSB,
	ELF_PT_NOTE,
	MACHO_LC_SEGMENT_64,
	MACHO_MAGIC_64,
	PE32_MAGIC,
	PE32_PLUS_MAGIC,
	PE_MAGIC,
	PE_SIGNATURE,
} from '@src/server'

export const WORKSPACE_ROOT = fileURLToPath(new URL('..', import.meta.url))

// === Temp directories

/** A temporary directory created for one test, cleaned up via {@link withTestDir}. */
export interface TestDir {
	readonly root: string
}

/**
 * Create a fresh temporary directory pre-populated with `files`, under the OS
 * tmp root — NOT anchored under `WORKSPACE_ROOT`, since a seal build writes a
 * real executable that must never land in source control (AGENTS §16.1).
 *
 * @param files - Record of relative path to file content, written before returning
 * @returns A {@link TestDir} wrapping the created directory's absolute path
 */
export function createTestDir(files: Record<string, string> = {}): TestDir {
	const root = fs.mkdtempSync(nodePath.join(tmpdir(), 'sea-test-'))
	for (const [relativePath, content] of Object.entries(files)) {
		const target = nodePath.join(root, relativePath)
		fs.mkdirSync(nodePath.dirname(target), { recursive: true })
		fs.writeFileSync(target, content, 'utf8')
	}
	return { root }
}

/** Remove a {@link TestDir} and everything inside it. */
export function destroyTestDir(dir: TestDir): void {
	fs.rmSync(dir.root, { recursive: true, force: true })
}

/**
 * Run `fn` with a fresh {@link TestDir} pre-populated with `files`, then clean
 * it up unconditionally — the shared create/use/destroy wrapper every
 * seal/injector test repeats (AGENTS §16.1).
 *
 * @param files - Record of relative path to file content
 * @param fn - Callback receiving the created {@link TestDir}
 * @returns The callback's return value
 */
export async function withTestDir<T>(
	files: Record<string, string>,
	fn: (dir: TestDir) => Promise<T> | T,
): Promise<T> {
	const dir = createTestDir(files)
	try {
		return await fn(dir)
	} finally {
		destroyTestDir(dir)
	}
}

/** Read a file's UTF-8 content relative to `root`. */
export function readFromDisk(root: string, relativePath: string): string {
	return fs.readFileSync(nodePath.join(root, relativePath), 'utf-8')
}

/** Check whether a path relative to `root` exists on disk. */
export function existsOnDisk(root: string, relativePath: string): boolean {
	return fs.existsSync(nodePath.join(root, relativePath))
}

// === Option builders

/**
 * Build valid {@link SEAOptions} for a test — `name`, `entry`, and `output`
 * default to a minimal working scenario; override any field to exercise a
 * specific case.
 */
export function createSEAOptions(overrides?: Partial<SEAOptions>): SEAOptions {
	return {
		name: 'seal-test',
		entry: { path: 'entry.cjs' },
		output: 'dist',
		...overrides,
	}
}

/**
 * Build valid {@link InjectorOptions} for a test — `resource` defaults to the
 * standard SEA blob resource name.
 */
export function createInjectorOptions(options: {
	readonly executable: string
	readonly blob: string
	readonly resource?: string
	readonly fuse?: string
	readonly overwrite?: boolean
	readonly macho?: InjectorOptions['macho']
}): InjectorOptions {
	return {
		executable: options.executable,
		resource: options.resource ?? 'NODE_SEA_BLOB',
		blob: options.blob,
		fuse: options.fuse,
		overwrite: options.overwrite,
		macho: options.macho,
	}
}

// === Binary fixture builders (Injector tests)
//
// Synthetic executables containing exactly the fields the Injector parses —
// enough to exercise real injection logic against real byte layouts, never
// against real toolchain output (AGENTS §16.1: no network, deterministic).

/** Options for {@link buildPeFixture}. */
export interface PeFixtureOptions {
	/** Build a PE32+ (64-bit) optional header instead of PE32. Default: false. */
	readonly plus?: boolean
	/** Include a pre-existing `.rsrc` section with one named leaf. Default: false. */
	readonly resources?: boolean
}

function alignUp(value: number, alignment: number): number {
	const remainder = value % alignment
	return remainder === 0 ? value : value + (alignment - remainder)
}

function bePeResourceFlag(value: number): number {
	return (value | 0x80000000) >>> 0
}

// Builds the raw bytes of a minimal PE resource directory tree containing one
// existing leaf: type ID 3 (never RT_RCDATA, so the injector's overwrite
// filter never touches it), name "EXISTING", language 0, data "EXISTDAT".
function buildPeResourceFixtureBytes(sectionVa: number): Buffer {
	const buf = Buffer.alloc(114)

	// Root directory (depth 0): 1 ID entry (typeId 3)
	buf.writeUInt16LE(0, 12) // NumberOfNamedEntries
	buf.writeUInt16LE(1, 14) // NumberOfIdEntries
	buf.writeUInt32LE(3, 16) // entry.NameOrId = typeId 3
	buf.writeUInt32LE(bePeResourceFlag(24), 20) // entry.OffsetToData -> subdir @24

	// Type subdirectory (depth 1 entries = names): 1 named entry "EXISTING"
	buf.writeUInt16LE(1, 24 + 12)
	buf.writeUInt16LE(0, 24 + 14)
	buf.writeUInt32LE(bePeResourceFlag(72), 40) // NAME_FLAG | string offset 72
	buf.writeUInt32LE(bePeResourceFlag(48), 44) // subdir @48

	// Name subdirectory (depth 2 entries = languages): 1 ID entry (language 0)
	buf.writeUInt16LE(0, 48 + 12)
	buf.writeUInt16LE(1, 48 + 14)
	buf.writeUInt32LE(0, 64) // language 0
	buf.writeUInt32LE(90, 68) // data entry @90 (no subdir flag)

	// String pool: IMAGE_RESOURCE_DIR_STRING_U "EXISTING"
	buf.writeUInt16LE(8, 72)
	buf.write('EXISTING', 74, 16, 'utf16le')

	// Data entry: DataRVA, Size, CodePage, Reserved
	buf.writeUInt32LE((sectionVa + 106) >>> 0, 90)
	buf.writeUInt32LE(8, 94)
	buf.writeUInt32LE(0, 98)
	buf.writeUInt32LE(0, 102)

	// Leaf data
	buf.write('EXISTDAT', 106, 8, 'ascii')

	return buf
}

/**
 * Build a minimal but structurally valid synthetic PE image for Injector
 * tests — one `.text` section, header slack for a new section entry, and
 * optionally PE32+ magic or a pre-existing `.rsrc` section.
 */
export function buildPeFixture(options?: PeFixtureOptions): Buffer {
	const plus = options?.plus ?? false
	const resources = options?.resources ?? false

	const fileAlignment = 0x200
	const sectionAlignment = 0x1000
	const optionalHeaderSize = plus ? 240 : 224
	const magic = plus ? PE32_PLUS_MAGIC : PE32_MAGIC
	const dataDirRelOffset = plus ? 112 : 96

	const peOffset = 0x80
	const coffOffset = peOffset + 4
	const optionalOffset = coffOffset + 20
	const sectionTableOffset = optionalOffset + optionalHeaderSize

	const numberOfSections = resources ? 2 : 1
	const textRawOffset = fileAlignment
	const textRawSize = fileAlignment
	const textVa = 0x1000

	const rsrcVa = 0x2000
	const resourceBuf = resources ? buildPeResourceFixtureBytes(rsrcVa) : undefined
	const rsrcRawOffset = textRawOffset + textRawSize
	const rsrcRawSize = resourceBuf !== undefined ? alignUp(resourceBuf.length, fileAlignment) : 0

	const fileSize = resources ? rsrcRawOffset + rsrcRawSize : textRawOffset + textRawSize
	const buf = Buffer.alloc(fileSize)

	// DOS header
	buf.writeUInt16LE(PE_MAGIC, 0)
	buf.writeUInt32LE(peOffset, 0x3c)

	// PE signature
	buf.writeUInt32LE(PE_SIGNATURE, peOffset)

	// COFF header
	buf.writeUInt16LE(0x14c, coffOffset)
	buf.writeUInt16LE(numberOfSections, coffOffset + 2)
	buf.writeUInt32LE(0, coffOffset + 4)
	buf.writeUInt32LE(0, coffOffset + 8)
	buf.writeUInt32LE(0, coffOffset + 12)
	buf.writeUInt16LE(optionalHeaderSize, coffOffset + 16)
	buf.writeUInt16LE(0x0102, coffOffset + 18)

	// Optional header — fields at and after +32 (SectionAlignment) share the
	// same byte offsets in PE32 and PE32+ (BaseOfData's 4 bytes are absorbed
	// by ImageBase growing from 4 to 8 bytes), so only Magic/SizeOfOptionalHeader
	// and the data-directory offset differ between the two variants here.
	buf.writeUInt16LE(magic, optionalOffset)
	buf.writeUInt8(0, optionalOffset + 2)
	buf.writeUInt8(0, optionalOffset + 3)
	buf.writeUInt32LE(0, optionalOffset + 4)
	buf.writeUInt32LE(0, optionalOffset + 8)
	buf.writeUInt32LE(0, optionalOffset + 12)
	buf.writeUInt32LE(0x1000, optionalOffset + 16)
	buf.writeUInt32LE(0x1000, optionalOffset + 20)
	buf.writeUInt32LE(0x400000, optionalOffset + 28)
	buf.writeUInt32LE(sectionAlignment, optionalOffset + 32)
	buf.writeUInt32LE(fileAlignment, optionalOffset + 36)
	buf.writeUInt16LE(6, optionalOffset + 40)
	buf.writeUInt16LE(0, optionalOffset + 42)
	buf.writeUInt16LE(0, optionalOffset + 44)
	buf.writeUInt16LE(0, optionalOffset + 46)
	buf.writeUInt16LE(6, optionalOffset + 48)
	buf.writeUInt16LE(0, optionalOffset + 50)
	buf.writeUInt32LE(0, optionalOffset + 52)
	buf.writeUInt32LE(0x10000, optionalOffset + 56) // SizeOfImage (recomputed by the injector)
	buf.writeUInt32LE(fileAlignment, optionalOffset + 60)
	buf.writeUInt32LE(0, optionalOffset + 64) // CheckSum (recomputed by the injector)
	buf.writeUInt16LE(3, optionalOffset + 68)
	buf.writeUInt16LE(0, optionalOffset + 70)
	buf.writeUInt32LE(0x100000, optionalOffset + 72)
	buf.writeUInt32LE(0x1000, optionalOffset + 76)
	buf.writeUInt32LE(0x100000, optionalOffset + 80)
	buf.writeUInt32LE(0x1000, optionalOffset + 84)
	buf.writeUInt32LE(0, optionalOffset + 88)
	buf.writeUInt32LE(16, optionalOffset + 92)

	if (resourceBuf !== undefined) {
		const resourceDirOffset = optionalOffset + dataDirRelOffset + 2 * 8
		buf.writeUInt32LE(rsrcVa, resourceDirOffset)
		buf.writeUInt32LE(resourceBuf.length, resourceDirOffset + 4)
	}

	// Section table: .text
	buf.write('.text', sectionTableOffset, 8, 'ascii')
	buf.writeUInt32LE(textRawSize, sectionTableOffset + 8)
	buf.writeUInt32LE(textVa, sectionTableOffset + 12)
	buf.writeUInt32LE(textRawSize, sectionTableOffset + 16)
	buf.writeUInt32LE(textRawOffset, sectionTableOffset + 20)
	buf.writeUInt32LE(0, sectionTableOffset + 24)
	buf.writeUInt32LE(0, sectionTableOffset + 28)
	buf.writeUInt16LE(0, sectionTableOffset + 32)
	buf.writeUInt16LE(0, sectionTableOffset + 34)
	buf.writeUInt32LE(0x60000020, sectionTableOffset + 36)

	if (resourceBuf !== undefined) {
		const rsrcHeaderOffset = sectionTableOffset + 40
		buf.write('.rsrc', rsrcHeaderOffset, 8, 'ascii')
		buf.writeUInt32LE(resourceBuf.length, rsrcHeaderOffset + 8)
		buf.writeUInt32LE(rsrcVa, rsrcHeaderOffset + 12)
		buf.writeUInt32LE(rsrcRawSize, rsrcHeaderOffset + 16)
		buf.writeUInt32LE(rsrcRawOffset, rsrcHeaderOffset + 20)
		buf.writeUInt32LE(0, rsrcHeaderOffset + 24)
		buf.writeUInt32LE(0, rsrcHeaderOffset + 28)
		buf.writeUInt16LE(0, rsrcHeaderOffset + 32)
		buf.writeUInt16LE(0, rsrcHeaderOffset + 34)
		buf.writeUInt32LE(0x40000040, rsrcHeaderOffset + 36)

		resourceBuf.copy(buf, rsrcRawOffset)
	}

	return buf
}

/** One parsed PE resource leaf, returned by {@link parsePeResourceLeaves}. */
export interface PeResourceLeaf {
	readonly typeId: number
	readonly typeName: string | undefined
	readonly nameId: number
	readonly nameName: string | undefined
	readonly language: number
	readonly codePage: number
	readonly data: Buffer
}

interface PeSectionInfo {
	readonly name: string
	readonly virtualAddress: number
	readonly virtualSize: number
	readonly rawSize: number
	readonly rawOffset: number
}

function parsePeSections(buf: Buffer): readonly PeSectionInfo[] {
	const peOffset = buf.readUInt32LE(0x3c)
	const coffOffset = peOffset + 4
	const numberOfSections = buf.readUInt16LE(coffOffset + 2)
	const optionalHeaderSize = buf.readUInt16LE(coffOffset + 16)
	const sectionTableOffset = coffOffset + 20 + optionalHeaderSize

	const sections: PeSectionInfo[] = []
	for (let i = 0; i < numberOfSections; i++) {
		const off = sectionTableOffset + i * 40
		const name = buf
			.subarray(off, off + 8)
			.toString('ascii')
			.replace(/\0+$/, '')
		sections.push({
			name,
			virtualSize: buf.readUInt32LE(off + 8),
			virtualAddress: buf.readUInt32LE(off + 12),
			rawSize: buf.readUInt32LE(off + 16),
			rawOffset: buf.readUInt32LE(off + 20),
		})
	}
	return sections
}

function rvaToFileOffsetPe(rva: number, sections: readonly PeSectionInfo[]): number {
	for (const s of sections) {
		const end = s.virtualAddress + Math.max(s.virtualSize, s.rawSize)
		if (rva >= s.virtualAddress && rva < end) return rva - s.virtualAddress + s.rawOffset
	}
	return -1
}

/**
 * Re-parse a PE resource directory tree from a named section (e.g. the
 * Injector's `.rsrc2` output section) into a flat list of leaves, for
 * asserting on injected/preserved resource data after `inject()`.
 */
export function parsePeResourceLeaves(buf: Buffer, sectionName: string): readonly PeResourceLeaf[] {
	const sections = parsePeSections(buf)
	const section = sections.find((s) => s.name === sectionName)
	if (section === undefined) return []

	const leaves: PeResourceLeaf[] = []

	const readString = (offset: number): string => {
		const charCount = buf.readUInt16LE(offset)
		return buf.subarray(offset + 2, offset + 2 + charCount * 2).toString('utf16le')
	}

	const walk = (
		dirOffset: number,
		depth: number,
		typeId: number,
		typeName: string | undefined,
		nameId: number,
		nameName: string | undefined,
	): void => {
		const absOffset = section.rawOffset + dirOffset
		const numNamed = buf.readUInt16LE(absOffset + 12)
		const numId = buf.readUInt16LE(absOffset + 14)
		const total = numNamed + numId

		for (let i = 0; i < total; i++) {
			const entryOffset = absOffset + 16 + i * 8
			const nameOrId = buf.readUInt32LE(entryOffset)
			const offsetOrData = buf.readUInt32LE(entryOffset + 4)

			let entryId = 0
			let entryName: string | undefined
			if ((nameOrId & 0x80000000) !== 0) {
				entryName = readString(section.rawOffset + (nameOrId & 0x7fffffff))
			} else {
				entryId = nameOrId
			}

			let nextTypeId = typeId
			let nextTypeName = typeName
			let nextNameId = nameId
			let nextNameName = nameName
			if (depth === 0) {
				nextTypeId = entryId
				nextTypeName = entryName
			} else if (depth === 1) {
				nextNameId = entryId
				nextNameName = entryName
			}

			if ((offsetOrData & 0x80000000) !== 0) {
				const subOffset = offsetOrData & 0x7fffffff
				walk(subOffset, depth + 1, nextTypeId, nextTypeName, nextNameId, nextNameName)
			} else {
				const dataEntryOffset = section.rawOffset + offsetOrData
				const dataRva = buf.readUInt32LE(dataEntryOffset)
				const dataSize = buf.readUInt32LE(dataEntryOffset + 4)
				const codePage = buf.readUInt32LE(dataEntryOffset + 8)
				const language = depth === 2 ? entryId : 0
				const fileOffset = rvaToFileOffsetPe(dataRva, sections)
				const data =
					fileOffset >= 0 ? buf.subarray(fileOffset, fileOffset + dataSize) : Buffer.alloc(0)
				leaves.push({
					typeId: nextTypeId,
					typeName: nextTypeName,
					nameId: nextNameId,
					nameName: nextNameName,
					language,
					codePage,
					data,
				})
			}
		}
	}

	walk(0, 0, 0, undefined, 0, undefined)
	return leaves
}

/** One ELF64 program header entry, built and parsed by the ELF fixture helpers. */
export interface ElfProgramHeader {
	readonly type: number
	readonly flags: number
	readonly offset: number
	readonly vaddr: number
	readonly paddr: number
	readonly filesz: number
	readonly memsz: number
	readonly align: number
}

function writeElfProgramHeader(buf: Buffer, pos: number, entry: ElfProgramHeader): void {
	buf.writeUInt32LE(entry.type >>> 0, pos)
	buf.writeUInt32LE(entry.flags >>> 0, pos + 4)
	buf.writeBigUInt64LE(BigInt(entry.offset), pos + 8)
	buf.writeBigUInt64LE(BigInt(entry.vaddr), pos + 16)
	buf.writeBigUInt64LE(BigInt(entry.paddr), pos + 24)
	buf.writeBigUInt64LE(BigInt(entry.filesz), pos + 32)
	buf.writeBigUInt64LE(BigInt(entry.memsz), pos + 40)
	buf.writeBigUInt64LE(BigInt(entry.align), pos + 48)
}

/**
 * Build a minimal but structurally valid synthetic ELF64 little-endian
 * executable for Injector tests: a PT_PHDR entry plus two PT_LOAD segments,
 * with e_phoff/e_phnum/e_phentsize consistent with the written table.
 */
export function buildElfFixture(): Buffer {
	const phdrOffset = 64
	const phdrEntrySize = 56
	const phdrCount = 3
	const fileSize = 0x1100

	const buf = Buffer.alloc(fileSize)

	// e_ident
	buf.writeUInt8(0x7f, 0)
	buf.write('ELF', 1, 3, 'ascii')
	buf.writeUInt8(ELF_CLASS_64, 4)
	buf.writeUInt8(ELF_DATA_LSB, 5)
	buf.writeUInt8(1, 6) // EI_VERSION

	buf.writeUInt16LE(2, 16) // e_type = ET_EXEC
	buf.writeUInt16LE(0x3e, 18) // e_machine = EM_X86_64
	buf.writeUInt32LE(1, 20) // e_version
	buf.writeBigUInt64LE(0x401000n, 24) // e_entry
	buf.writeBigUInt64LE(BigInt(phdrOffset), 32) // e_phoff
	buf.writeBigUInt64LE(0n, 40) // e_shoff
	buf.writeUInt32LE(0, 48) // e_flags
	buf.writeUInt16LE(64, 52) // e_ehsize
	buf.writeUInt16LE(phdrEntrySize, 54) // e_phentsize
	buf.writeUInt16LE(phdrCount, 56) // e_phnum
	buf.writeUInt16LE(0, 58) // e_shentsize
	buf.writeUInt16LE(0, 60) // e_shnum
	buf.writeUInt16LE(0, 62) // e_shstrndx

	// PT_PHDR
	writeElfProgramHeader(buf, phdrOffset + 0 * phdrEntrySize, {
		type: 6,
		flags: 4,
		offset: phdrOffset,
		vaddr: 0x400000 + phdrOffset,
		paddr: 0x400000 + phdrOffset,
		filesz: phdrCount * phdrEntrySize,
		memsz: phdrCount * phdrEntrySize,
		align: 8,
	})
	// PT_LOAD #1: covers the ELF/program headers
	writeElfProgramHeader(buf, phdrOffset + 1 * phdrEntrySize, {
		type: 1,
		flags: 5,
		offset: 0,
		vaddr: 0x400000,
		paddr: 0x400000,
		filesz: 0x1000,
		memsz: 0x1000,
		align: 0x1000,
	})
	// PT_LOAD #2: a second, higher-addressed load segment so maxVaddrEnd is meaningful
	writeElfProgramHeader(buf, phdrOffset + 2 * phdrEntrySize, {
		type: 1,
		flags: 6,
		offset: 0x1000,
		vaddr: 0x401000,
		paddr: 0x401000,
		filesz: 0x100,
		memsz: 0x200,
		align: 0x1000,
	})

	return buf
}

/** Parse all ELF64 program header entries out of a buffer. */
export function parseElfProgramHeaders(buf: Buffer): readonly ElfProgramHeader[] {
	const phdrOffset = Number(buf.readBigUInt64LE(32))
	const phdrEntrySize = buf.readUInt16LE(54)
	const phdrCount = buf.readUInt16LE(56)

	const headers: ElfProgramHeader[] = []
	for (let i = 0; i < phdrCount; i++) {
		const off = phdrOffset + i * phdrEntrySize
		headers.push({
			type: buf.readUInt32LE(off),
			flags: buf.readUInt32LE(off + 4),
			offset: Number(buf.readBigUInt64LE(off + 8)),
			vaddr: Number(buf.readBigUInt64LE(off + 16)),
			paddr: Number(buf.readBigUInt64LE(off + 24)),
			filesz: Number(buf.readBigUInt64LE(off + 32)),
			memsz: Number(buf.readBigUInt64LE(off + 40)),
			align: Number(buf.readBigUInt64LE(off + 48)),
		})
	}
	return headers
}

/** A parsed, active (non-PT_NULL) ELF note whose name matches a lookup prefix. */
export interface ElfNote {
	readonly header: ElfProgramHeader
	readonly name: string
	readonly descsz: number
	readonly descriptor: Buffer
}

/**
 * Find every active PT_NOTE program header whose note name starts with
 * `namePrefix`, re-parsed from the note's file offset (namesz/descsz/name +
 * 4-byte-aligned descriptor), for asserting on injected ELF note content.
 */
export function findElfNotes(buf: Buffer, namePrefix: string): readonly ElfNote[] {
	const alignTo4 = (value: number): number => {
		const remainder = value % 4
		return remainder === 0 ? value : value + (4 - remainder)
	}

	const notes: ElfNote[] = []
	for (const header of parseElfProgramHeaders(buf)) {
		if (header.type !== ELF_PT_NOTE) continue
		const namesz = buf.readUInt32LE(header.offset)
		const descsz = buf.readUInt32LE(header.offset + 4)
		if (namesz === 0 || namesz > 256) continue
		const nameBuf = buf.subarray(header.offset + 12, header.offset + 12 + namesz)
		const name = nameBuf.toString('utf-8').replace(/\0+$/, '')
		if (!name.startsWith(namePrefix)) continue
		const descOffset = header.offset + 12 + alignTo4(namesz)
		notes.push({ header, name, descsz, descriptor: buf.subarray(descOffset, descOffset + descsz) })
	}
	return notes
}

interface MachoSegmentFixture {
	readonly cmd: number
	readonly size: number
	readonly segName: string
	readonly vmaddr: bigint
	readonly vmsize: bigint
	readonly fileoff: bigint
	readonly filesize: bigint
	readonly maxprot: number
	readonly initprot: number
	readonly nsects: number
	readonly flags: number
}

function writeMachoSegment(buf: Buffer, offset: number, segment: MachoSegmentFixture): void {
	buf.writeUInt32LE(segment.cmd, offset)
	buf.writeUInt32LE(segment.size, offset + 4)
	buf.write(segment.segName, offset + 8, 16, 'ascii')
	buf.writeBigUInt64LE(segment.vmaddr, offset + 24)
	buf.writeBigUInt64LE(segment.vmsize, offset + 32)
	buf.writeBigUInt64LE(segment.fileoff, offset + 40)
	buf.writeBigUInt64LE(segment.filesize, offset + 48)
	buf.writeUInt32LE(segment.maxprot, offset + 56)
	buf.writeUInt32LE(segment.initprot, offset + 60)
	buf.writeUInt32LE(segment.nsects, offset + 64)
	buf.writeUInt32LE(segment.flags, offset + 68)
}

interface MachoSectionFixture {
	readonly sectName: string
	readonly segName: string
	readonly addr: bigint
	readonly size: bigint
	readonly offset: number
}

function writeMachoSectionEntry(buf: Buffer, offset: number, section: MachoSectionFixture): void {
	buf.write(section.sectName, offset, 16, 'ascii')
	buf.write(section.segName, offset + 16, 16, 'ascii')
	buf.writeBigUInt64LE(section.addr, offset + 32)
	buf.writeBigUInt64LE(section.size, offset + 40)
	buf.writeUInt32LE(section.offset, offset + 48)
	buf.writeUInt32LE(0, offset + 52)
	buf.writeUInt32LE(0, offset + 56)
	buf.writeUInt32LE(0, offset + 60)
	buf.writeUInt32LE(0, offset + 64)
	buf.writeUInt32LE(0, offset + 68)
	buf.writeUInt32LE(0, offset + 72)
	buf.writeUInt32LE(0, offset + 76)
}

/** Options for {@link buildMachoFixture}. */
export interface MachoFixtureOptions {
	/** Place sections almost flush against the load-command table, so the
	 * Injector's header-space ceiling check fails. Default: false. */
	readonly tightHeaders?: boolean
}

/**
 * Build a minimal but structurally valid synthetic thin Mach-O 64 (x86_64)
 * executable for Injector tests: `__TEXT` (fileoff 0), `__DATA`, `__LINKEDIT`
 * (last), plus an `LC_SYMTAB` and `LC_DYSYMTAB` whose offsets point into
 * `__LINKEDIT` — enough for `#injectMacho` to parse, shift, and inject.
 */
export function buildMachoFixture(options?: MachoFixtureOptions): Buffer {
	const tight = options?.tightHeaders ?? false

	const headerSize = 32
	const textCmdSize = 152 // 72-byte segment header + one 80-byte section
	const dataCmdSize = 152
	const symtabCmdSize = 24
	const dysymtabCmdSize = 80
	const linkeditCmdSize = 72
	const sizeofcmds = textCmdSize + dataCmdSize + symtabCmdSize + dysymtabCmdSize + linkeditCmdSize
	const ncmds = 5

	const textCmdOffset = headerSize
	const dataCmdOffset = textCmdOffset + textCmdSize
	const symtabCmdOffset = dataCmdOffset + dataCmdSize
	const dysymtabCmdOffset = symtabCmdOffset + symtabCmdSize
	const linkeditCmdOffset = dysymtabCmdOffset + dysymtabCmdSize

	const textSectionFileOffset = tight ? 600 : 0x1000
	const dataSegmentFileOffset = textSectionFileOffset + 0x100
	const linkeditFileOffset = dataSegmentFileOffset + 0x100
	const linkeditSize = 0x200
	const fileSize = linkeditFileOffset + linkeditSize

	const buf = Buffer.alloc(fileSize)

	buf.writeUInt32LE(MACHO_MAGIC_64, 0)
	buf.writeUInt32LE(0x01000007, 4) // cputype: x86_64 (4K pages)
	buf.writeUInt32LE(0x00000003, 8) // cpusubtype
	buf.writeUInt32LE(2, 12) // filetype: MH_EXECUTE
	buf.writeUInt32LE(ncmds, 16)
	buf.writeUInt32LE(sizeofcmds, 20)
	buf.writeUInt32LE(0, 24) // flags
	buf.writeUInt32LE(0, 28) // reserved

	writeMachoSegment(buf, textCmdOffset, {
		cmd: MACHO_LC_SEGMENT_64,
		size: textCmdSize,
		segName: '__TEXT',
		vmaddr: 0x100000000n,
		vmsize: BigInt(textSectionFileOffset + 0x100),
		fileoff: 0n,
		filesize: BigInt(textSectionFileOffset + 0x100),
		maxprot: 1,
		initprot: 1,
		nsects: 1,
		flags: 0,
	})
	writeMachoSectionEntry(buf, textCmdOffset + 72, {
		sectName: '__text',
		segName: '__TEXT',
		addr: 0x100000000n + BigInt(textSectionFileOffset),
		size: 0x100n,
		offset: textSectionFileOffset,
	})

	writeMachoSegment(buf, dataCmdOffset, {
		cmd: MACHO_LC_SEGMENT_64,
		size: dataCmdSize,
		segName: '__DATA',
		vmaddr: 0x100000000n + BigInt(dataSegmentFileOffset),
		vmsize: 0x100n,
		fileoff: BigInt(dataSegmentFileOffset),
		filesize: 0x100n,
		maxprot: 3,
		initprot: 3,
		nsects: 1,
		flags: 0,
	})
	writeMachoSectionEntry(buf, dataCmdOffset + 72, {
		sectName: '__data',
		segName: '__DATA',
		addr: 0x100000000n + BigInt(dataSegmentFileOffset),
		size: 0x40n,
		offset: dataSegmentFileOffset,
	})

	// LC_SYMTAB
	buf.writeUInt32LE(0x2, symtabCmdOffset)
	buf.writeUInt32LE(symtabCmdSize, symtabCmdOffset + 4)
	buf.writeUInt32LE(linkeditFileOffset, symtabCmdOffset + 8) // symoff
	buf.writeUInt32LE(0, symtabCmdOffset + 12) // nsyms
	buf.writeUInt32LE(linkeditFileOffset + 16, symtabCmdOffset + 16) // stroff
	buf.writeUInt32LE(8, symtabCmdOffset + 20) // strsize

	// LC_DYSYMTAB
	buf.writeUInt32LE(0xb, dysymtabCmdOffset)
	buf.writeUInt32LE(dysymtabCmdSize, dysymtabCmdOffset + 4)
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 32) // tocoff
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 40) // modtaboff
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 48) // extrefsymoff
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 56) // indirectsymoff
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 64) // extreloff
	buf.writeUInt32LE(linkeditFileOffset, dysymtabCmdOffset + 72) // locreloff

	// LC_SEGMENT_64 __LINKEDIT (last)
	writeMachoSegment(buf, linkeditCmdOffset, {
		cmd: MACHO_LC_SEGMENT_64,
		size: linkeditCmdSize,
		segName: '__LINKEDIT',
		vmaddr: 0x100000000n + BigInt(linkeditFileOffset),
		vmsize: BigInt(linkeditSize),
		fileoff: BigInt(linkeditFileOffset),
		filesize: BigInt(linkeditSize),
		maxprot: 1,
		initprot: 1,
		nsects: 0,
		flags: 0,
	})

	return buf
}

/** Build a fat/universal Mach-O header (magic 0xcafebabe) for format-rejection tests. */
export function buildFatMachoFixture(): Buffer {
	const buf = Buffer.alloc(32)
	buf.writeUInt32BE(0xcafebabe, 0) // FAT_MAGIC
	buf.writeUInt32BE(1, 4) // nfat_arch
	return buf
}

/** One raw Mach-O load command header (cmd, size, byte offset). */
export interface MachoLoadCommand {
	readonly cmd: number
	readonly size: number
	readonly offset: number
}

/** Parse every load command header out of a Mach-O 64 buffer. */
export function parseMachoLoadCommands(buf: Buffer): readonly MachoLoadCommand[] {
	const ncmds = buf.readUInt32LE(16)
	const commands: MachoLoadCommand[] = []
	let offset = 32
	for (let i = 0; i < ncmds; i++) {
		const cmd = buf.readUInt32LE(offset)
		const size = buf.readUInt32LE(offset + 4)
		commands.push({ cmd, size, offset })
		offset += size
	}
	return commands
}

/** One parsed LC_SEGMENT_64 load command. */
export interface MachoSegment {
	readonly name: string
	readonly vmaddr: bigint
	readonly vmsize: bigint
	readonly fileoff: number
	readonly filesize: number
	readonly nsects: number
	readonly offset: number
}

function stripMachoNulls(value: string): string {
	const idx = value.indexOf('\0')
	return idx === -1 ? value : value.slice(0, idx)
}

/** Parse every LC_SEGMENT_64 command out of a Mach-O 64 buffer. */
export function parseMachoSegments(buf: Buffer): readonly MachoSegment[] {
	return parseMachoLoadCommands(buf)
		.filter((c) => c.cmd === MACHO_LC_SEGMENT_64)
		.map((c) => ({
			name: stripMachoNulls(buf.subarray(c.offset + 8, c.offset + 24).toString('ascii')),
			vmaddr: buf.readBigUInt64LE(c.offset + 24),
			vmsize: buf.readBigUInt64LE(c.offset + 32),
			fileoff: Number(buf.readBigUInt64LE(c.offset + 40)),
			filesize: Number(buf.readBigUInt64LE(c.offset + 48)),
			nsects: buf.readUInt32LE(c.offset + 64),
			offset: c.offset,
		}))
}

/** One parsed Mach-O section-table entry, found via {@link findMachoSection}. */
export interface MachoSection {
	readonly name: string
	readonly segment: string
	readonly addr: bigint
	readonly size: bigint
	readonly offset: number
}

/** Find a named section within a named segment in a Mach-O 64 buffer. */
export function findMachoSection(
	buf: Buffer,
	segmentName: string,
	sectionName: string,
): MachoSection | undefined {
	const segment = parseMachoSegments(buf).find((s) => s.name === segmentName)
	if (segment === undefined) return undefined
	for (let i = 0; i < segment.nsects; i++) {
		const sectOff = segment.offset + 72 + i * 80
		const name = stripMachoNulls(buf.subarray(sectOff, sectOff + 16).toString('ascii'))
		if (name !== sectionName) continue
		return {
			name,
			segment: stripMachoNulls(buf.subarray(sectOff + 16, sectOff + 32).toString('ascii')),
			addr: buf.readBigUInt64LE(sectOff + 32),
			size: buf.readBigUInt64LE(sectOff + 40),
			offset: buf.readUInt32LE(sectOff + 48),
		}
	}
	return undefined
}
