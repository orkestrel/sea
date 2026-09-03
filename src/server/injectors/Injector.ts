import type {
	ELFProgramHeader,
	ExecutableFormat,
	InjectorInterface,
	InjectorOptions,
	PEResourceEntry,
	PEResourceLeaf,
	PESection,
} from '../types.js'
import {
	openSync,
	readSync,
	writeSync,
	closeSync,
	statSync,
	fstatSync,
	chmodSync,
	rmSync,
	appendFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import {
	PE_MAGIC,
	PE_SIGNATURE,
	PE32_MAGIC,
	PE32_PLUS_MAGIC,
	PE_RT_RCDATA,
	PE_RESOURCE_DIR_SIZE,
	PE_RESOURCE_ENTRY_SIZE,
	PE_RESOURCE_DATA_ENTRY_SIZE,
	PE_SECTION_HEADER_SIZE,
	PE_RESOURCE_SUBDIR_FLAG,
	PE_RESOURCE_NAME_FLAG,
	PE_SCN_INITIALIZED_DATA,
	PE_SCN_MEM_READ,
	ELF_MAGIC,
	ELF_CLASS_64,
	ELF_DATA_LSB,
	ELF_PT_NOTE,
	ELF_PT_LOAD,
	ELF_PT_PHDR,
	ELF_PF_R,
	ELF_PAGE_SIZE,
	MACHO_MAGIC_64,
	MACHO_LC_SEGMENT_64,
} from '../constants.js'
import {
	alignTo,
	appendFile,
	buildELFNoteHeader,
	copyRange,
	finalizeExecutable,
	isPowerOfTwo,
	patchSentinelFuse,
	readU16,
	readU32,
	readU64,
	stripTrailingNulls,
	writeU16,
	writeU32,
	writeU64,
} from '../helpers.js'
import { SEAError } from '../errors.js'

/**
 * Writes a named resource into a PE, ELF, or Mach-O executable in place.
 *
 * @remarks
 * The format is detected from the file's magic bytes at construction, and each
 * format takes its own strategy: PE adds an `RT_RCDATA` resource by rebuilding the
 * resource directory, ELF appends a `PT_NOTE` segment carrying the blob as note
 * data, and Mach-O appends an `LC_SEGMENT_64` load command with one section. The
 * blob is streamed from disk in every case, so its size is bounded by the
 * filesystem rather than by memory.
 *
 * @param options - Injector options: the target executable, the resource name, the
 * blob path, and the optional sentinel fuse and Mach-O segment
 *
 * @example
 * ```ts
 * const injector = new Injector({
 *     executable: 'dist/sea/myapp.exe',
 *     resource: 'NODE_SEA_BLOB',
 *     blob: 'dist/sea/sea-prep.blob',
 *     fuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
 * })
 * injector.format // 'pe' | 'elf' | 'macho'
 * injector.inject()
 * ```
 */
export class Injector implements InjectorInterface {
	#options: InjectorOptions
	#format: ExecutableFormat

	constructor(options: InjectorOptions) {
		this.#options = options
		this.#format = this.#detect()
	}

	get format(): ExecutableFormat {
		return this.#format
	}

	inject(): void {
		let peOptionalOffset: number | undefined
		switch (this.#format) {
			case 'pe':
				peOptionalOffset = this.#injectPE()
				break
			case 'elf':
				this.#injectELF()
				break
			case 'macho':
				this.#injectMachO()
				break
		}

		if (this.#options.fuse !== undefined) {
			patchSentinelFuse(this.#options.executable, this.#options.fuse)
		}

		// The checksum must be the TRUE last PE write — computed after the
		// sentinel-fuse byte flip above — or an unsigned build ships a stale
		// checksum that doesn't cover the fuse mutation.
		if (peOptionalOffset !== undefined) {
			this.#patchChecksum(peOptionalOffset)
		}
	}

	// === Format Detection

	#detect(): ExecutableFormat {
		const fd = openSync(this.#options.executable, 'r')
		try {
			const header = Buffer.alloc(4)
			readSync(fd, header, 0, 4, 0)
			const magic16 = header.readUInt16LE(0)
			const magic32 = header.readUInt32BE(0)
			const magic32le = header.readUInt32LE(0)

			if (magic16 === PE_MAGIC) return 'pe'
			if (magic32 === ELF_MAGIC) return 'elf'
			if (magic32le === MACHO_MAGIC_64) return 'macho'

			// Fat/universal Mach-O (either byte order) — dedicated message so
			// callers know exactly why: this injector only handles thin binaries.
			if (magic32 === 0xcafebabe || magic32 === 0xbebafeca) {
				throw new SEAError(
					'FORMAT',
					'Mach-O universal/fat binaries are not supported; provide a thin arm64 or x86_64 binary',
					{ executable: this.#options.executable, magic: magic32 },
				)
			}

			// 32-bit or big-endian thin Mach-O (magic 0xfeedface / 0xcefaedfe) —
			// only 64-bit little-endian Mach-O (0xfeedfacf) is supported.
			if (
				magic32le === 0xfeedface ||
				magic32le === 0xcefaedfe ||
				magic32 === 0xfeedface ||
				magic32 === 0xcefaedfe
			) {
				throw new SEAError('FORMAT', 'Only 64-bit little-endian Mach-O is supported', {
					executable: this.#options.executable,
					magic: magic32,
				})
			}

			throw new SEAError(
				'FORMAT',
				`Unknown executable format (magic: 0x${magic32.toString(16).padStart(8, '0')})`,
				{ executable: this.#options.executable, magic: magic32 },
			)
		} finally {
			closeSync(fd)
		}
	}

	// =========================================================================
	// PE Injection
	// =========================================================================
	//
	// Strategy: parse the existing PE structure, gather all current resource
	// entries (preserving icons, manifests, version info), build a new .rsrc
	// section that includes the existing resources plus the injected blob,
	// append it to the file, add a new section header entry, and update the
	// PE headers (resource data directory, SizeOfImage, NumberOfSections).
	//
	// The blob data is streamed from disk — never held in memory.

	#injectPE(): number {
		const fd = openSync(this.#options.executable, 'r+')
		try {
			// --- Parse PE headers ---
			const peOffset = readU32(fd, 0x3c)
			const sig = readU32(fd, peOffset)
			if (sig !== PE_SIGNATURE) {
				throw new SEAError('FORMAT', 'Invalid PE signature', {
					executable: this.#options.executable,
					signature: sig,
				})
			}

			const coffOffset = peOffset + 4
			const numberOfSections = readU16(fd, coffOffset + 2)
			const optionalHeaderSize = readU16(fd, coffOffset + 16)
			const optionalOffset = coffOffset + 20

			const optMagic = readU16(fd, optionalOffset)
			const is64 = optMagic === PE32_PLUS_MAGIC
			if (optMagic !== PE32_MAGIC && optMagic !== PE32_PLUS_MAGIC) {
				throw new SEAError(
					'FORMAT',
					`Unsupported PE optional header magic: 0x${optMagic.toString(16)}`,
					{ executable: this.#options.executable, optionalHeaderMagic: optMagic },
				)
			}

			const sectionAlignment = readU32(fd, optionalOffset + 32)
			const fileAlignment = readU32(fd, optionalOffset + 36)
			this.#ensureValidPEAlignment(sectionAlignment, fileAlignment)

			// SizeOfImage offset: same in PE32 and PE32+
			const sizeOfImageOffset = optionalOffset + 56

			// Data directory starts after the fixed optional header fields
			// PE32: 96 bytes fixed + data dirs; PE32+: 112 bytes fixed + data dirs
			const dataDirOffset = optionalOffset + (is64 ? 112 : 96)

			// Resource table is data directory entry index 2
			const resourceDirRvaOffset = dataDirOffset + 2 * 8
			const resourceDirSizeOffset = resourceDirRvaOffset + 4
			const existingResourceRVA = readU32(fd, resourceDirRvaOffset)

			// --- Parse section table ---
			const sectionTableOffset = optionalOffset + optionalHeaderSize

			// Collect all sections and find the resource section
			const sections: PESection[] = []

			let rsrcSectionIndex = -1

			for (let i = 0; i < numberOfSections; i++) {
				const off = sectionTableOffset + i * PE_SECTION_HEADER_SIZE
				const nameBuf = Buffer.alloc(8)
				readSync(fd, nameBuf, 0, 8, off)
				const name = stripTrailingNulls(nameBuf.toString('ascii'))
				const virtualSize = readU32(fd, off + 8)
				const virtualAddress = readU32(fd, off + 12)
				const rawSize = readU32(fd, off + 16)
				const rawOffset = readU32(fd, off + 20)
				const characteristics = readU32(fd, off + 36)

				sections.push({
					name,
					virtualSize,
					virtualAddress,
					rawSize,
					rawOffset,
					characteristics,
					headerOffset: off,
				})

				if (
					existingResourceRVA >= virtualAddress &&
					existingResourceRVA < virtualAddress + Math.max(virtualSize, rawSize)
				) {
					rsrcSectionIndex = i
				}
			}

			// --- Check space for a new section header entry ---
			const sectionTableEnd = sectionTableOffset + numberOfSections * PE_SECTION_HEADER_SIZE
			const firstSectionFileOffset = sections.reduce(
				(min, s) => (s.rawOffset > 0 && s.rawOffset < min ? s.rawOffset : min),
				Infinity,
			)
			const availableHeaderSpace = firstSectionFileOffset - sectionTableEnd
			if (availableHeaderSpace < PE_SECTION_HEADER_SIZE) {
				throw new SEAError(
					'INJECT',
					'No room in PE header for a new section entry ' +
						`(${String(availableHeaderSpace)} bytes available, need ${String(PE_SECTION_HEADER_SIZE)})`,
					{
						executable: this.#options.executable,
						availableHeaderSpace,
						requiredHeaderSpace: PE_SECTION_HEADER_SIZE,
					},
				)
			}

			// --- Gather existing resource leaves ---
			const existingLeaves: PEResourceLeaf[] = []

			if (rsrcSectionIndex !== -1 && existingResourceRVA !== 0) {
				const rsrc = sections[rsrcSectionIndex]
				if (rsrc !== undefined) {
					this.#parseResourceDirectory(
						fd,
						rsrc.rawOffset,
						existingResourceRVA,
						0,
						existingLeaves,
						0,
						0,
						undefined,
						0,
						undefined,
					)
				}
			}

			// --- Remove old blob entry if overwriting ---
			const overwrite = this.#options.overwrite !== false
			const upperName = this.#options.resource.toUpperCase()
			const filteredLeaves = existingLeaves.filter((leaf) => {
				if (!overwrite) return true
				if (leaf.typeId !== PE_RT_RCDATA) return true
				return leaf.nameName?.toUpperCase() !== upperName
			})

			// --- Read existing resource data ---
			// For each existing leaf, read its data from the original file
			const leafDataMap = new Map<number, Buffer>()
			for (let i = 0; i < filteredLeaves.length; i++) {
				const leaf = filteredLeaves[i]
				if (leaf === undefined) continue
				// Convert data RVA to file offset
				const fileOffset = this.#rvaToFileOffset(leaf.dataRVA, sections)
				if (fileOffset >= 0) {
					const buf = Buffer.alloc(leaf.dataSize)
					readSync(fd, buf, 0, leaf.dataSize, fileOffset)
					leafDataMap.set(i, buf)
				}
			}

			// --- Build new resource section ---
			const blobSize = statSync(this.#options.blob).size

			// Build resource tree: group by type → name → language
			const tree = this.#buildResourceTree(filteredLeaves, upperName, blobSize)

			// Serialize the resource directory + data entries (without blob data)
			const { directoryBuffer, dataRegionSize } = this.#serializeResourceTree(
				tree,
				leafDataMap,
				blobSize,
			)

			// Total section raw size = directory + data region (existing data + blob)
			const totalRawSize = directoryBuffer.length + dataRegionSize
			const alignedRawSize = alignTo(totalRawSize, fileAlignment)

			// --- Determine new section placement ---
			// Virtual address: highest VA end of all sections, aligned
			let highestVaEnd = 0
			for (const s of sections) {
				const end = s.virtualAddress + Math.max(s.virtualSize, s.rawSize)
				if (end > highestVaEnd) highestVaEnd = end
			}
			const newVa = alignTo(highestVaEnd, sectionAlignment)
			const newVirtualSize = totalRawSize

			// File offset: end of file, aligned
			const fileSize = statSync(this.#options.executable).size
			const newRawOffset = alignTo(fileSize, fileAlignment)

			// --- Write new section header ---
			const newHeaderOffset = sectionTableEnd
			const headerBuf = Buffer.alloc(PE_SECTION_HEADER_SIZE)

			// Section name: .rsrc2 (avoids confusion with existing .rsrc)
			headerBuf.write('.rsrc2', 0, 6, 'ascii')
			headerBuf.writeUInt32LE(newVirtualSize, 8) // VirtualSize
			headerBuf.writeUInt32LE(newVa, 12) // VirtualAddress
			headerBuf.writeUInt32LE(alignedRawSize, 16) // SizeOfRawData
			headerBuf.writeUInt32LE(newRawOffset, 20) // PointerToRawData
			headerBuf.writeUInt32LE(0, 24) // PointerToRelocations
			headerBuf.writeUInt32LE(0, 28) // PointerToLinenumbers
			headerBuf.writeUInt16LE(0, 32) // NumberOfRelocations
			headerBuf.writeUInt16LE(0, 34) // NumberOfLinenumbers
			headerBuf.writeUInt32LE(PE_SCN_INITIALIZED_DATA | PE_SCN_MEM_READ, 36) // Characteristics

			writeSync(fd, headerBuf, 0, PE_SECTION_HEADER_SIZE, newHeaderOffset)

			// --- Update PE headers ---
			// NumberOfSections
			writeU16(fd, coffOffset + 2, numberOfSections + 1)

			// Resource data directory → point to new section
			writeU32(fd, resourceDirRvaOffset, newVa)
			writeU32(fd, resourceDirSizeOffset, directoryBuffer.length)

			// SizeOfImage — must cover the new section
			const newSizeOfImage = alignTo(
				newVa + Math.max(newVirtualSize, alignedRawSize),
				sectionAlignment,
			)
			writeU32(fd, sizeOfImageOffset, newSizeOfImage)

			closeSync(fd)

			// --- Write new section data to file ---
			// Pad file to aligned offset
			const currentFileSize = statSync(this.#options.executable).size
			if (newRawOffset > currentFileSize) {
				const padding = Buffer.alloc(newRawOffset - currentFileSize)
				appendFileSync(this.#options.executable, padding)
			}

			// Fixup RVAs in the directory buffer: add newVa as base
			this.#fixupDataEntries(directoryBuffer, 0, newVa)

			// Write the directory buffer
			appendFileSync(this.#options.executable, directoryBuffer)

			// Write existing resource data
			for (let i = 0; i < filteredLeaves.length; i++) {
				const data = leafDataMap.get(i)
				if (data !== undefined) {
					appendFileSync(this.#options.executable, data)
					// Pad to DWORD alignment
					const padLen = alignTo(data.length, 4) - data.length
					if (padLen > 0) {
						appendFileSync(this.#options.executable, Buffer.alloc(padLen))
					}
				}
			}

			// Stream the blob from disk
			appendFile(this.#options.executable, this.#options.blob)

			// Pad the section to aligned raw size
			const writtenSize = statSync(this.#options.executable).size - newRawOffset
			if (writtenSize < alignedRawSize) {
				appendFileSync(this.#options.executable, Buffer.alloc(alignedRawSize - writtenSize))
			}

			// The checksum is recomputed by the caller (inject()) AFTER the
			// sentinel-fuse byte flip, so it covers every prior header/section
			// change plus the fuse mutation. Return the offset for that call.
			return optionalOffset
		} catch (error: unknown) {
			try {
				closeSync(fd)
			} catch {
				/* already closed */
			}
			throw error
		}
	}

	// --- PE: parse resource directory tree recursively ---

	#parseResourceDirectory(
		fd: number,
		sectionFileOffset: number,
		sectionRva: number,
		dirOffset: number,
		leaves: PEResourceLeaf[],
		depth: number,
		currentTypeId: number,
		currentTypeName: string | undefined,
		currentNameId: number,
		currentNameName: string | undefined,
	): void {
		const absOffset = sectionFileOffset + dirOffset

		// IMAGE_RESOURCE_DIRECTORY: 16 bytes
		const numNamedEntries = readU16(fd, absOffset + 12)
		const numIdEntries = readU16(fd, absOffset + 14)
		const totalEntries = numNamedEntries + numIdEntries

		for (let i = 0; i < totalEntries; i++) {
			const entryOffset = absOffset + PE_RESOURCE_DIR_SIZE + i * PE_RESOURCE_ENTRY_SIZE
			const nameOrId = readU32(fd, entryOffset)
			const offsetOrData = readU32(fd, entryOffset + 4)

			// Resolve name or ID
			let entryId = 0
			let entryName: string | undefined

			if ((nameOrId & PE_RESOURCE_NAME_FLAG) !== 0) {
				// Named entry — offset to IMAGE_RESOURCE_DIR_STRING_U
				const stringOffset = nameOrId & ~PE_RESOURCE_NAME_FLAG
				entryName = this.#readResourceString(fd, sectionFileOffset + stringOffset)
			} else {
				entryId = nameOrId
			}

			// Track current type/name based on depth
			let typeId = currentTypeId
			let typeName = currentTypeName
			let nameId = currentNameId
			let nameName = currentNameName

			if (depth === 0) {
				typeId = entryId
				typeName = entryName
			} else if (depth === 1) {
				nameId = entryId
				nameName = entryName
			}

			if ((offsetOrData & PE_RESOURCE_SUBDIR_FLAG) !== 0) {
				// Subdirectory
				const subDirOffset = offsetOrData & ~PE_RESOURCE_SUBDIR_FLAG
				this.#parseResourceDirectory(
					fd,
					sectionFileOffset,
					sectionRva,
					subDirOffset,
					leaves,
					depth + 1,
					typeId,
					typeName,
					nameId,
					nameName,
				)
			} else {
				// Data entry (leaf)
				const dataEntryFileOffset = sectionFileOffset + offsetOrData
				const dataRVA = readU32(fd, dataEntryFileOffset)
				const dataSize = readU32(fd, dataEntryFileOffset + 4)
				const codePage = readU32(fd, dataEntryFileOffset + 8)

				const language = depth === 2 ? entryId : 0

				leaves.push({
					typeId,
					typeName,
					nameId,
					nameName,
					language,
					codePage,
					dataRVA,
					dataSize,
				})
			}
		}
	}

	// --- PE: read a Unicode resource string ---

	#readResourceString(fd: number, offset: number): string {
		const lenBuf = Buffer.alloc(2)
		readSync(fd, lenBuf, 0, 2, offset)
		const charCount = lenBuf.readUInt16LE(0)
		if (charCount === 0) return ''
		const strBuf = Buffer.alloc(charCount * 2)
		readSync(fd, strBuf, 0, charCount * 2, offset + 2)
		return strBuf.toString('utf16le')
	}

	// --- PE: convert RVA to file offset using section table ---

	#rvaToFileOffset(rva: number, sections: readonly PESection[]): number {
		for (const s of sections) {
			const sectionEnd = s.virtualAddress + Math.max(s.virtualSize, s.rawSize)
			if (rva >= s.virtualAddress && rva < sectionEnd) {
				return rva - s.virtualAddress + s.rawOffset
			}
		}
		return -1
	}

	// --- PE: build the resource tree for serialization ---

	#buildResourceTree(
		existingLeaves: readonly PEResourceLeaf[],
		blobName: string,
		blobSize: number,
	): Map<string, Map<string, PEResourceEntry[]>> {
		// Tree: typeKey → nameKey → language entries
		// typeKey/nameKey encode both named and integer IDs
		const tree = new Map<string, Map<string, PEResourceEntry[]>>()

		// Add existing leaves
		for (let i = 0; i < existingLeaves.length; i++) {
			const leaf = existingLeaves[i]
			if (leaf === undefined) continue
			const typeKey =
				leaf.typeName !== undefined ? `n:${leaf.typeName}` : `i:${String(leaf.typeId)}`
			const nameKey =
				leaf.nameName !== undefined ? `n:${leaf.nameName}` : `i:${String(leaf.nameId)}`

			let typeMap = tree.get(typeKey)
			if (typeMap === undefined) {
				typeMap = new Map()
				tree.set(typeKey, typeMap)
			}
			let langArr = typeMap.get(nameKey)
			if (langArr === undefined) {
				langArr = []
				typeMap.set(nameKey, langArr)
			}
			langArr.push({
				language: leaf.language,
				codePage: leaf.codePage,
				leafIndex: i,
				dataSize: leaf.dataSize,
			})
		}

		// Add the new blob entry
		const blobTypeKey = `i:${String(PE_RT_RCDATA)}`
		const blobNameKey = `n:${blobName}`

		let typeMap = tree.get(blobTypeKey)
		if (typeMap === undefined) {
			typeMap = new Map()
			tree.set(blobTypeKey, typeMap)
		}
		typeMap.set(blobNameKey, [
			{
				language: 0,
				codePage: 0,
				leafIndex: -1, // -1 signals "this is the blob"
				dataSize: blobSize,
			},
		])

		return tree
	}

	// --- PE: serialize the resource tree into a buffer ---

	#serializeResourceTree(
		tree: ReadonlyMap<string, ReadonlyMap<string, readonly PEResourceEntry[]>>,
		leafDataMap: Map<number, Buffer>,
		blobSize: number,
	): {
		directoryBuffer: Buffer
		dataRegionSize: number
		blobDataOffset: number
	} {
		// Phase 1: Calculate sizes
		// Level 0 (root): 1 directory + entries for each type
		// Level 1 (per type): 1 directory + entries for each name
		// Level 2 (per name): 1 directory + entries for each language
		// Then: all name strings, all data entries

		let dirTableSize = 0
		let stringPoolSize = 0
		let dataEntryCount = 0

		// Root directory
		dirTableSize += PE_RESOURCE_DIR_SIZE + tree.size * PE_RESOURCE_ENTRY_SIZE

		const allStrings: Array<{ key: string; value: string }> = []
		const allLeafEntries: Array<{
			leafIndex: number
			dataSize: number
			codePage: number
		}> = []

		for (const [typeKey, nameMap] of tree) {
			// Type directory
			dirTableSize += PE_RESOURCE_DIR_SIZE + nameMap.size * PE_RESOURCE_ENTRY_SIZE

			// Collect type name string if named
			if (typeKey.startsWith('n:')) {
				const str = typeKey.slice(2)
				allStrings.push({ key: typeKey, value: str })
				stringPoolSize += 2 + str.length * 2 // length (u16) + UTF-16LE chars
				stringPoolSize = alignTo(stringPoolSize, 2) // WORD align strings
			}

			for (const [nameKey, langEntries] of nameMap) {
				// Name directory
				dirTableSize += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE

				// Collect name string if named
				if (nameKey.startsWith('n:')) {
					const str = nameKey.slice(2)
					allStrings.push({ key: nameKey, value: str })
					stringPoolSize += 2 + str.length * 2
					stringPoolSize = alignTo(stringPoolSize, 2)
				}

				for (const entry of langEntries) {
					allLeafEntries.push({
						leafIndex: entry.leafIndex,
						dataSize: entry.dataSize,
						codePage: entry.codePage,
					})
					dataEntryCount++
				}
			}
		}

		const dataEntriesSize = dataEntryCount * PE_RESOURCE_DATA_ENTRY_SIZE
		const headerSize = dirTableSize + stringPoolSize + dataEntriesSize

		// Phase 2: Calculate data region (existing leaves + blob)
		let dataRegionOffset = 0
		const leafFileOffsets = new Map<number, number>() // leafIndex → offset within data region

		for (let i = 0; i < allLeafEntries.length; i++) {
			const entry = allLeafEntries[i]
			if (entry === undefined) continue
			if (entry.leafIndex === -1) continue // blob handled separately

			const data = leafDataMap.get(entry.leafIndex)
			if (data !== undefined) {
				leafFileOffsets.set(entry.leafIndex, dataRegionOffset)
				dataRegionOffset += alignTo(data.length, 4)
			}
		}

		const blobDataOffset = dataRegionOffset
		dataRegionOffset += blobSize
		const dataRegionSize = dataRegionOffset

		// Phase 3: Build the directory buffer with placeholder RVAs
		// RVAs will be fixed up later with the actual section VA
		const buf = Buffer.alloc(headerSize)
		let dirPos = 0
		let stringPos = dirTableSize
		let dataEntryPos = dirTableSize + stringPoolSize

		// String offset lookup: key → offset within directory buffer
		const stringOffsets = new Map<string, number>()
		for (const { key, value } of allStrings) {
			stringOffsets.set(key, stringPos)
			buf.writeUInt16LE(value.length, stringPos)
			buf.write(value, stringPos + 2, value.length * 2, 'utf16le')
			stringPos += 2 + value.length * 2
			stringPos = alignTo(stringPos, 2)
		}

		// Sort tree entries: named entries first (sorted by name), then ID entries (sorted by ID)
		const sortedTypeKeys = this.#sortResourceKeys([...tree.keys()])

		// Helper to track subdirectory offsets for linking
		const nextDirOffset = PE_RESOURCE_DIR_SIZE + tree.size * PE_RESOURCE_ENTRY_SIZE

		// --- Write root directory ---
		const namedTypes = sortedTypeKeys.filter((k) => k.startsWith('n:'))
		const idTypes = sortedTypeKeys.filter((k) => k.startsWith('i:'))

		buf.writeUInt32LE(0, dirPos) // Characteristics
		buf.writeUInt32LE(0, dirPos + 4) // TimeDateStamp
		buf.writeUInt16LE(0, dirPos + 8) // MajorVersion
		buf.writeUInt16LE(0, dirPos + 10) // MinorVersion
		buf.writeUInt16LE(namedTypes.length, dirPos + 12)
		buf.writeUInt16LE(idTypes.length, dirPos + 14)
		dirPos += PE_RESOURCE_DIR_SIZE

		// Pre-calculate all type subdirectory offsets
		const typeDirOffsets = new Map<string, number>()
		let accDirOffset = nextDirOffset
		for (const typeKey of sortedTypeKeys) {
			typeDirOffsets.set(typeKey, accDirOffset)
			const nameMap = tree.get(typeKey)
			if (nameMap === undefined) continue
			const typeEntryCount = nameMap.size
			accDirOffset += PE_RESOURCE_DIR_SIZE + typeEntryCount * PE_RESOURCE_ENTRY_SIZE
			for (const [, langEntries] of nameMap) {
				accDirOffset += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE
			}
		}

		// Write root entries
		for (const typeKey of sortedTypeKeys) {
			const isNamed = typeKey.startsWith('n:')
			const nameOrId = isNamed
				? (stringOffsets.get(typeKey) ?? 0) | PE_RESOURCE_NAME_FLAG
				: parseInt(typeKey.slice(2), 10)
			const subdirOffset = (typeDirOffsets.get(typeKey) ?? 0) | PE_RESOURCE_SUBDIR_FLAG

			buf.writeUInt32LE(nameOrId >>> 0, dirPos)
			buf.writeUInt32LE(subdirOffset >>> 0, dirPos + 4)
			dirPos += PE_RESOURCE_ENTRY_SIZE
		}

		// --- Write type subdirectories ---
		for (const typeKey of sortedTypeKeys) {
			const nameMap = tree.get(typeKey)
			if (nameMap === undefined) continue
			const sortedNameKeys = this.#sortResourceKeys([...nameMap.keys()])
			const namedNames = sortedNameKeys.filter((k) => k.startsWith('n:'))
			const idNames = sortedNameKeys.filter((k) => k.startsWith('i:'))

			buf.writeUInt32LE(0, dirPos)
			buf.writeUInt32LE(0, dirPos + 4)
			buf.writeUInt16LE(0, dirPos + 8)
			buf.writeUInt16LE(0, dirPos + 10)
			buf.writeUInt16LE(namedNames.length, dirPos + 12)
			buf.writeUInt16LE(idNames.length, dirPos + 14)
			dirPos += PE_RESOURCE_DIR_SIZE

			// Calculate offset of each name's language subdirectory
			// These come sequentially after the current type directory and its entries
			let langSubdirCursor = dirPos + sortedNameKeys.length * PE_RESOURCE_ENTRY_SIZE

			for (const nameKey of sortedNameKeys) {
				const isNamed = nameKey.startsWith('n:')
				const nameOrId = isNamed
					? (stringOffsets.get(nameKey) ?? 0) | PE_RESOURCE_NAME_FLAG
					: parseInt(nameKey.slice(2), 10)

				// The language subdirectory offset is relative to resource section start
				const langSubDirRelOffset = langSubdirCursor | PE_RESOURCE_SUBDIR_FLAG

				buf.writeUInt32LE(nameOrId >>> 0, dirPos)
				buf.writeUInt32LE(langSubDirRelOffset >>> 0, dirPos + 4)
				dirPos += PE_RESOURCE_ENTRY_SIZE

				const langEntries = nameMap.get(nameKey)
				if (langEntries !== undefined) {
					langSubdirCursor += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE
				}
			}

			// Write language subdirectories for each name
			for (const nameKey of sortedNameKeys) {
				const langEntries = nameMap.get(nameKey)
				if (langEntries === undefined) continue

				buf.writeUInt32LE(0, dirPos)
				buf.writeUInt32LE(0, dirPos + 4)
				buf.writeUInt16LE(0, dirPos + 8)
				buf.writeUInt16LE(0, dirPos + 10)
				buf.writeUInt16LE(0, dirPos + 12) // no named language entries
				buf.writeUInt16LE(langEntries.length, dirPos + 14)
				dirPos += PE_RESOURCE_DIR_SIZE

				for (const entry of langEntries) {
					// Language ID
					buf.writeUInt32LE(entry.language, dirPos)

					// Data entry offset (not a subdirectory — no high bit)
					buf.writeUInt32LE(dataEntryPos, dirPos + 4)
					dirPos += PE_RESOURCE_ENTRY_SIZE

					// Write the data entry
					// DataRVA — placeholder, will be fixed up with actual VA
					let dataOffset: number
					if (entry.leafIndex === -1) {
						// Blob
						dataOffset = headerSize + blobDataOffset
					} else {
						const resolvedOffset = leafFileOffsets.get(entry.leafIndex)
						if (resolvedOffset === undefined) {
							throw new SEAError('INJECT', 'unresolvable resource RVA', {
								executable: this.#options.executable,
								leafIndex: entry.leafIndex,
							})
						}
						dataOffset = headerSize + resolvedOffset
					}

					// Store as relative offset from section start for now;
					// #fixupDataEntries will add the section VA
					buf.writeUInt32LE(dataOffset, dataEntryPos) // DataRVA (placeholder)
					buf.writeUInt32LE(entry.dataSize, dataEntryPos + 4) // Size
					buf.writeUInt32LE(entry.codePage, dataEntryPos + 8) // CodePage
					buf.writeUInt32LE(0, dataEntryPos + 12) // Reserved
					dataEntryPos += PE_RESOURCE_DATA_ENTRY_SIZE
				}
			}
		}

		return { directoryBuffer: buf, dataRegionSize, blobDataOffset }
	}

	// --- PE: fix up all data entry RVAs by adding the section's virtual address ---
	//
	// The serialized layout is [directories] [strings] [data entries], and each
	// data entry's first DWORD is the DataRVA that gains the section VA. The
	// entries are reached by re-walking the directory tree, whose level-2 entries
	// point at them.

	#fixupDataEntries(buf: Buffer, dirOffset: number, sectionVA: number): void {
		if (dirOffset + PE_RESOURCE_DIR_SIZE > buf.length) return

		const namedCount = buf.readUInt16LE(dirOffset + 12)
		const idCount = buf.readUInt16LE(dirOffset + 14)
		const totalEntries = namedCount + idCount

		for (let i = 0; i < totalEntries; i++) {
			const entryOffset = dirOffset + PE_RESOURCE_DIR_SIZE + i * PE_RESOURCE_ENTRY_SIZE
			if (entryOffset + PE_RESOURCE_ENTRY_SIZE > buf.length) return

			const offsetOrData = buf.readUInt32LE(entryOffset + 4)

			if ((offsetOrData & PE_RESOURCE_SUBDIR_FLAG) !== 0) {
				// Subdirectory — recurse
				const subOffset = offsetOrData & ~PE_RESOURCE_SUBDIR_FLAG
				this.#fixupDataEntries(buf, subOffset, sectionVA)
			} else {
				// Data entry — fix up the RVA
				if (offsetOrData + 4 <= buf.length) {
					const currentRva = buf.readUInt32LE(offsetOrData)
					buf.writeUInt32LE((currentRva + sectionVA) >>> 0, offsetOrData)
				}
			}
		}
	}

	// --- PE: recompute and write the OptionalHeader.CheckSum ---
	//
	// The classic Windows IMAGE checksum: sum the whole file as little-endian
	// 16-bit words (the existing checksum's 4 bytes treated as zero), fold
	// carries into a 16-bit accumulator, then add the file length. Streamed in
	// chunks (like `appendFile`) so a large SEA binary is never fully buffered.

	#patchChecksum(optionalOffset: number): void {
		const checksumOffset = optionalOffset + 64
		const fd = openSync(this.#options.executable, 'r+')
		try {
			const fileSize = statSync(this.#options.executable).size
			const chunkSize = 4 * 1024 * 1024
			const chunk = Buffer.alloc(Math.min(chunkSize, fileSize))

			let sum = 0
			let offset = 0
			while (offset < fileSize) {
				const toRead = Math.min(chunkSize, fileSize - offset)
				const bytesRead = readSync(fd, chunk, 0, toRead, offset)
				if (bytesRead === 0) break

				for (let i = 0; i < bytesRead; i += 2) {
					const absolute = offset + i
					let word: number
					if (absolute === checksumOffset || absolute === checksumOffset + 2) {
						word = 0
					} else if (i + 1 < bytesRead) {
						word = chunk.readUInt16LE(i)
					} else {
						word = chunk.readUInt8(i)
					}
					sum += word
					sum = (sum & 0xffff) + (sum >>> 16)
				}

				offset += bytesRead
			}

			sum = (sum & 0xffff) + (sum >>> 16)
			const checksum = (sum + fileSize) >>> 0

			writeU32(fd, checksumOffset, checksum)
		} finally {
			closeSync(fd)
		}
	}

	// --- PE: sort resource keys (named first alphabetically, then IDs numerically) ---

	#sortResourceKeys(keys: string[]): readonly string[] {
		const named = keys
			.filter((k) => k.startsWith('n:'))
			.sort((a, b) => a.slice(2).localeCompare(b.slice(2), 'en', { sensitivity: 'base' }))
		const ids = keys
			.filter((k) => k.startsWith('i:'))
			.sort((a, b) => {
				const ia = parseInt(a.slice(2), 10)
				const ib = parseInt(b.slice(2), 10)
				return ia - ib
			})
		return [...named, ...ids]
	}

	// =========================================================================
	// ELF Injection
	// =========================================================================
	//
	// Strategy: append a PT_NOTE segment to the ELF. The note contains
	// the resource name and blob data. We find an existing PT_NOTE in the
	// program header table and repurpose it, or find space in the phdr
	// table for a new entry.
	//
	// Node.js SEA on Linux reads PT_NOTE segments via dl_iterate_phdr,
	// searching for a note whose name matches the resource name.

	#injectELF(): void {
		const exePath = this.#options.executable
		const resource = this.#options.resource
		const overwrite = this.#options.overwrite !== false

		let phdrOffset: number
		let phdrEntrySize: number
		let phdrCount: number
		let headers: readonly ELFProgramHeader[]

		const fd = openSync(exePath, 'r')
		try {
			// --- Parse ELF header ---
			const identBuf = Buffer.alloc(16)
			readSync(fd, identBuf, 0, 16, 0)

			const elfClass = identBuf.readUInt8(4)
			const elfData = identBuf.readUInt8(5)

			if (elfClass !== ELF_CLASS_64) {
				throw new SEAError('FORMAT', 'Only 64-bit ELF executables are supported', {
					executable: exePath,
					elfClass,
				})
			}
			if (elfData !== ELF_DATA_LSB) {
				throw new SEAError('FORMAT', 'Only little-endian ELF executables are supported', {
					executable: exePath,
					elfData,
				})
			}

			phdrOffset = Number(readU64(fd, 32)) // e_phoff
			phdrEntrySize = readU16(fd, 54) // e_phentsize
			phdrCount = readU16(fd, 56) // e_phnum

			headers = this.#readELFProgramHeaders(fd, phdrOffset, phdrEntrySize, phdrCount)

			// Collect any stale PT_NOTE with a matching name, refusing the whole
			// injection first when the caller forbade an overwrite.
			const stale = new Set<number>()
			for (let i = 0; i < headers.length; i++) {
				const header = headers[i]
				if (header === undefined || header.type !== ELF_PT_NOTE) continue
				const existingName = this.#readELFNoteName(fd, header.offset, header.filesz)
				if (existingName === undefined || !existingName.startsWith('NODE_SEA')) continue
				if (!overwrite) {
					throw new SEAError('INJECT', `Note with name "${resource}" already exists`, {
						executable: exePath,
						resource,
					})
				}
				stale.add(i)
			}

			// Neutralize each stale note so overwrite never leaves two competing
			// "NODE_SEA*" notes visible to postject_find_resource — runtime skips
			// any non-PT_NOTE entry.
			headers = headers.map((header, index) => (stale.has(index) ? { ...header, type: 0 } : header))
		} finally {
			closeSync(fd)
		}

		// --- Compute the new PT_LOAD/PT_NOTE placement ---
		// The note MUST live inside a PT_LOAD so the runtime's dl_iterate_phdr
		// walk can read it from the mapped virtual address (Node reads
		// NODE_SEA notes from memory, never from the file).
		let maxVaddrEnd = 0
		for (const header of headers) {
			if (header.type !== ELF_PT_LOAD) continue
			const end = header.vaddr + header.memsz
			if (end > maxVaddrEnd) maxVaddrEnd = end
		}
		const regionVaddr = alignTo(maxVaddrEnd, ELF_PAGE_SIZE)

		const blobSize = statSync(this.#options.blob).size
		const { header: noteHeader, total: noteTotal } = buildELFNoteHeader(resource, blobSize)
		const noteAreaSize = alignTo(noteTotal, 8)

		const newEntryCount = headers.length + 2
		const phtSize = newEntryCount * phdrEntrySize
		const regionSize = noteAreaSize + phtSize

		const fileSize = statSync(exePath).size
		const regionStart = alignTo(fileSize, ELF_PAGE_SIZE)
		const phtOff = regionStart + noteAreaSize

		const newLoad: ELFProgramHeader = {
			type: ELF_PT_LOAD,
			flags: ELF_PF_R,
			offset: regionStart,
			vaddr: regionVaddr,
			paddr: regionVaddr,
			filesz: regionSize,
			memsz: regionSize,
			align: ELF_PAGE_SIZE,
		}
		const newNote: ELFProgramHeader = {
			type: ELF_PT_NOTE,
			flags: ELF_PF_R,
			offset: regionStart,
			vaddr: regionVaddr,
			paddr: regionVaddr,
			filesz: noteTotal,
			memsz: noteTotal,
			align: 4,
		}

		// Relocate PT_PHDR (if present) to point at the enlarged table, which
		// itself lives inside the new PT_LOAD right after the note — keeping
		// PT_PHDR's p_vaddr congruent with its covering segment. This relies on
		// a modern-kernel loader that computes AT_PHDR from the PT_LOAD
		// covering e_phoff (Linux ~5.x+ / the Node>=24 target); a pre-5.x
		// kernel that instead computes AT_PHDR = load_addr + e_phoff would
		// derive a wrong value here since the PHT no longer sits at its
		// original load-relative offset.
		const finalHeaders = headers.map((header) => {
			if (header.type !== ELF_PT_PHDR) return header
			const relVaddr = regionVaddr + (phtOff - regionStart)
			return {
				...header,
				offset: phtOff,
				vaddr: relVaddr,
				paddr: relVaddr,
				filesz: phtSize,
				memsz: phtSize,
			}
		})
		finalHeaders.push(newLoad, newNote)

		const phtBuffer = Buffer.alloc(phtSize)
		for (let i = 0; i < finalHeaders.length; i++) {
			const entry = finalHeaders[i]
			if (entry === undefined) continue
			this.#writeELFProgramHeaderEntry(phtBuffer, i * phdrEntrySize, entry)
		}

		// --- Append the new region: note header + streamed blob + padding + PHT ---
		if (regionStart > fileSize) {
			appendFileSync(exePath, Buffer.alloc(regionStart - fileSize))
		}
		appendFileSync(exePath, noteHeader)
		appendFile(exePath, this.#options.blob)

		const alignedDescSize = alignTo(blobSize, 4)
		const descPadding = alignedDescSize - blobSize
		if (descPadding > 0) {
			appendFileSync(exePath, Buffer.alloc(descPadding))
		}

		const trailingPad = noteAreaSize - noteTotal
		if (trailingPad > 0) {
			appendFileSync(exePath, Buffer.alloc(trailingPad))
		}

		appendFileSync(exePath, phtBuffer)

		// --- Point the ELF header at the relocated, enlarged PHT ---
		const fd2 = openSync(exePath, 'r+')
		try {
			writeU64(fd2, 32, BigInt(phtOff))
			writeU16(fd2, 56, newEntryCount)

			// Build-time readback: locate the note the SAME way the runtime
			// does (a PT_NOTE inside a PT_LOAD, address-congruent with its
			// file offset) so a passing readback reflects runtime success.
			this.#verifyELFNoteMapping(fd2, phtOff, newEntryCount, phdrEntrySize)
		} finally {
			closeSync(fd2)
		}
	}

	// --- ELF: read all program header entries into memory ---

	#readELFProgramHeaders(
		fd: number,
		phdrOffset: number,
		entrySize: number,
		count: number,
	): readonly ELFProgramHeader[] {
		const headers: ELFProgramHeader[] = []
		for (let i = 0; i < count; i++) {
			const off = phdrOffset + i * entrySize
			headers.push({
				type: readU32(fd, off),
				flags: readU32(fd, off + 4),
				offset: Number(readU64(fd, off + 8)),
				vaddr: Number(readU64(fd, off + 16)),
				paddr: Number(readU64(fd, off + 24)),
				filesz: Number(readU64(fd, off + 32)),
				memsz: Number(readU64(fd, off + 40)),
				align: Number(readU64(fd, off + 48)),
			})
		}
		return headers
	}

	// --- ELF: serialize a single program header entry (56 bytes, ELF64) ---

	#writeELFProgramHeaderEntry(buf: Buffer, pos: number, entry: ELFProgramHeader): void {
		buf.writeUInt32LE(entry.type >>> 0, pos)
		buf.writeUInt32LE(entry.flags >>> 0, pos + 4)
		buf.writeBigUInt64LE(BigInt(entry.offset), pos + 8)
		buf.writeBigUInt64LE(BigInt(entry.vaddr), pos + 16)
		buf.writeBigUInt64LE(BigInt(entry.paddr), pos + 24)
		buf.writeBigUInt64LE(BigInt(entry.filesz), pos + 32)
		buf.writeBigUInt64LE(BigInt(entry.memsz), pos + 40)
		buf.writeBigUInt64LE(BigInt(entry.align), pos + 48)
	}

	// --- ELF: read a note's name at a given file offset (bounds-checked) ---

	#readELFNoteName(fd: number, offset: number, size: number): string | undefined {
		if (size < 12) return undefined
		const namesz = readU32(fd, offset)
		const descsz = readU32(fd, offset + 4)
		if (namesz === 0 || namesz > 256) return undefined
		if (12 + alignTo(namesz, 4) + alignTo(descsz, 4) > size) return undefined

		const nameBuf = Buffer.alloc(namesz)
		readSync(fd, nameBuf, 0, namesz, offset + 12)
		return stripTrailingNulls(nameBuf.toString('utf-8'))
	}

	// --- ELF: build-time readback — confirm the note is runtime-reachable ---

	#verifyELFNoteMapping(
		fd: number,
		phdrOffset: number,
		phdrCount: number,
		phdrEntrySize: number,
	): void {
		const headers = this.#readELFProgramHeaders(fd, phdrOffset, phdrEntrySize, phdrCount)
		const loads = headers.filter((h) => h.type === ELF_PT_LOAD)
		const notes = headers.filter((h) => h.type === ELF_PT_NOTE)

		for (const note of notes) {
			const name = this.#readELFNoteName(fd, note.offset, note.filesz)
			if (name === undefined || !name.startsWith('NODE_SEA')) continue

			const covering = loads.find(
				(load) => note.offset >= load.offset && note.offset < load.offset + load.filesz,
			)
			if (covering === undefined) continue

			const expectedVaddr = covering.vaddr + (note.offset - covering.offset)
			if (expectedVaddr === note.vaddr) return
		}

		throw new SEAError(
			'INJECT',
			'Injected ELF note is not reachable via a mapped PT_LOAD segment at runtime',
			{ executable: this.#options.executable, resource: this.#options.resource },
		)
	}

	// =========================================================================
	// Mach-O Injection
	// =========================================================================
	//
	// Strategy: append an LC_SEGMENT_64 load command with a single section
	// containing the blob data. The segment is placed at the next available
	// file offset and virtual address.
	//
	// Node.js SEA on macOS uses getsectdata(segment, section) to find the
	// blob. The segment defaults to "__POSTJECT" (or custom via options)
	// and the section is "__" + resource.

	#injectMachO(): void {
		const exePath = this.#options.executable
		const fileSize = statSync(exePath).size
		let srcFd: number | undefined = openSync(exePath, 'r')
		let destFd: number | undefined
		let blobFd: number | undefined
		let injTemp: string | undefined

		try {
			// --- Bounded header read: just enough to cover every header/LC parse
			// and mutation below (headerSize + sizeofcmds) — never the whole file. ---
			const headerSize = 32 // Mach-O 64-bit header
			const preHeader = Buffer.alloc(headerSize)
			readSync(srcFd, preHeader, 0, headerSize, 0)
			const preSizeofcmds = preHeader.readUInt32LE(20)
			if (headerSize + preSizeofcmds > fileSize) {
				throw new SEAError('FORMAT', 'Mach-O load command region exceeds file size', {
					executable: exePath,
					headerSize,
					sizeofcmds: preSizeofcmds,
					fileSize,
				})
			}
			const buf = Buffer.alloc(headerSize + preSizeofcmds)
			readSync(srcFd, buf, 0, headerSize + preSizeofcmds, 0)

			// --- Parse Mach-O header ---
			const magic = buf.readUInt32LE(0)
			if (magic !== MACHO_MAGIC_64) {
				throw new SEAError('FORMAT', `Unsupported Mach-O magic: 0x${magic.toString(16)}`, {
					executable: exePath,
					magic,
				})
			}

			const cputype = buf.readUInt32LE(4)
			const ncmds = buf.readUInt32LE(16)
			const sizeofcmds = buf.readUInt32LE(20)

			const segmentName = this.#options.macho?.segment ?? 'NODE_SEA'
			let sectionName = this.#options.resource
			if (!sectionName.startsWith('__')) {
				sectionName = `__${sectionName}`
			}

			// --- Walk load commands once, collecting their bounds ---
			const commands: Array<{ type: number; size: number; offset: number }> = []
			let cmdOffset = headerSize
			for (let i = 0; i < ncmds; i++) {
				if (cmdOffset + 8 > buf.length) {
					throw new SEAError('FORMAT', 'Malformed Mach-O load command table', {
						executable: exePath,
					})
				}
				const cmdType = buf.readUInt32LE(cmdOffset)
				const cmdSize = buf.readUInt32LE(cmdOffset + 4)
				if (cmdSize < 8 || cmdOffset + cmdSize > buf.length) {
					throw new SEAError('FORMAT', 'Malformed Mach-O load command table', {
						executable: exePath,
					})
				}
				commands.push({ type: cmdType, size: cmdSize, offset: cmdOffset })
				cmdOffset += cmdSize
			}

			let linkeditIndex = -1
			const existingSegmentIndices: number[] = []
			for (let i = 0; i < commands.length; i++) {
				const cmd = commands[i]
				if (cmd === undefined || cmd.type !== MACHO_LC_SEGMENT_64) continue
				const segName = stripTrailingNulls(
					buf.subarray(cmd.offset + 8, cmd.offset + 24).toString('ascii'),
				)
				if (segName === '__LINKEDIT') linkeditIndex = i
				if (segName === segmentName) existingSegmentIndices.push(i)
			}

			if (existingSegmentIndices.length > 0 && this.#options.overwrite === false) {
				throw new SEAError('INJECT', `Segment "${segmentName}" already exists`, {
					executable: exePath,
					segmentName,
				})
			}
			const linkeditCmd = linkeditIndex === -1 ? undefined : commands[linkeditIndex]
			if (linkeditCmd === undefined) {
				throw new SEAError('INJECT', 'Mach-O binary has no __LINKEDIT segment', {
					executable: exePath,
				})
			}

			const linkeditOffset = Number(buf.readBigUInt64LE(linkeditCmd.offset + 40))
			const linkeditSize = Number(buf.readBigUInt64LE(linkeditCmd.offset + 48))
			const linkeditAddress = buf.readBigUInt64LE(linkeditCmd.offset + 24)

			const blobSize = statSync(this.#options.blob).size
			// arm64 (0x0100000c) requires 16K pages; every other architecture (x86_64
			// etc.) uses 4K — 0x4000 is a safe superset alignment for either.
			const pageSize = cputype === 0x0100000c ? 0x4000 : 0x1000
			const shift = alignTo(blobSize, pageSize)

			// --- Ceiling check BEFORE mutating anything: the enlarged load-command
			// region (plus 16 bytes reserved for codesign re-adding
			// LC_CODE_SIGNATURE) must not overrun the first real section's bytes.
			// The sentinel starts at the FULL file size (not the bounded `buf`
			// size) — it represents "no section found yet", not a hard ceiling. ---
			let firstSectionOffset = fileSize
			for (const cmd of commands) {
				if (cmd.type !== MACHO_LC_SEGMENT_64) continue
				const nsects = buf.readUInt32LE(cmd.offset + 64)
				for (let s = 0; s < nsects; s++) {
					const sectOff = cmd.offset + 72 + s * 80
					if (sectOff + 80 > buf.length) continue
					const size = Number(buf.readBigUInt64LE(sectOff + 40))
					const offset = buf.readUInt32LE(sectOff + 48)
					if (size > 0 && offset > 0 && offset < firstSectionOffset) {
						firstSectionOffset = offset
					}
				}
			}

			const newCmdSize = 72 + 80
			const removedSize = commands
				.filter((_c, i) => existingSegmentIndices.includes(i))
				.reduce((sum, c) => sum + c.size, 0)
			const newNcmds = commands.length - existingSegmentIndices.length + 1
			const newSizeofcmds = sizeofcmds - removedSize + newCmdSize

			if (headerSize + newSizeofcmds + 16 > firstSectionOffset) {
				throw new SEAError(
					'INJECT',
					`Not enough header space for new Mach-O load command ` +
						`(need offset ${String(headerSize + newSizeofcmds + 16)}, first section at ${String(firstSectionOffset)})`,
					{
						executable: exePath,
						firstSectionOffset,
						requiredOffset: headerSize + newSizeofcmds + 16,
					},
				)
			}

			// --- Mutate in place: shift __LINKEDIT and every linkedit-relative
			// offset field in the surviving commands, using the ORIGINAL
			// linkeditOffset as the "does this offset point into __LINKEDIT"
			// threshold. ---
			for (let i = 0; i < commands.length; i++) {
				const cmd = commands[i]
				if (cmd === undefined || existingSegmentIndices.includes(i)) continue

				if (cmd.type === MACHO_LC_SEGMENT_64) {
					const segName = stripTrailingNulls(
						buf.subarray(cmd.offset + 8, cmd.offset + 24).toString('ascii'),
					)
					if (segName === '__LINKEDIT') {
						const nsects = buf.readUInt32LE(cmd.offset + 64)
						if (nsects > 0) {
							throw new SEAError('INJECT', '__LINKEDIT segment with sections is not supported', {
								executable: exePath,
							})
						}
						buf.writeBigUInt64LE(linkeditAddress + BigInt(shift), cmd.offset + 24) // vmaddr
						buf.writeBigUInt64LE(BigInt(linkeditOffset + shift), cmd.offset + 40) // fileoff
						// filesize/vmsize unchanged — __LINKEDIT keeps its size, only moves.
					}
					continue
				}

				this.#shiftMachOLinkeditOffsets(buf, cmd, linkeditOffset, shift)
			}

			buf.writeUInt32LE(newNcmds, 16)
			buf.writeUInt32LE(newSizeofcmds, 20)

			// --- Build the new NODE_SEA segment command: it takes __LINKEDIT's
			// OLD slot (before __LINKEDIT), inserted before __LINKEDIT so
			// codesign's appended signature at EOF (inside __LINKEDIT) survives. ---
			const cmd = Buffer.alloc(newCmdSize)
			cmd.writeUInt32LE(MACHO_LC_SEGMENT_64, 0)
			cmd.writeUInt32LE(newCmdSize, 4)
			cmd.write(segmentName, 8, 16, 'ascii')
			cmd.writeBigUInt64LE(linkeditAddress, 24) // vmaddr
			cmd.writeBigUInt64LE(BigInt(shift), 32) // vmsize
			cmd.writeBigUInt64LE(BigInt(linkeditOffset), 40) // fileoff
			cmd.writeBigUInt64LE(BigInt(shift), 48) // filesize
			cmd.writeUInt32LE(1, 56) // maxprot: VM_PROT_READ
			cmd.writeUInt32LE(1, 60) // initprot: VM_PROT_READ
			cmd.writeUInt32LE(1, 64) // nsects
			cmd.writeUInt32LE(0, 68) // flags

			const sectOff = 72
			cmd.write(sectionName, sectOff, 16, 'ascii')
			cmd.write(segmentName, sectOff + 16, 16, 'ascii')
			cmd.writeBigUInt64LE(linkeditAddress, sectOff + 32) // addr
			cmd.writeBigUInt64LE(BigInt(blobSize), sectOff + 40) // size
			cmd.writeUInt32LE(linkeditOffset, sectOff + 48) // offset
			cmd.writeUInt32LE(0, sectOff + 52) // align
			cmd.writeUInt32LE(0, sectOff + 56) // reloff
			cmd.writeUInt32LE(0, sectOff + 60) // nreloc
			cmd.writeUInt32LE(0, sectOff + 64) // flags
			cmd.writeUInt32LE(0, sectOff + 68) // reserved1
			cmd.writeUInt32LE(0, sectOff + 72) // reserved2
			cmd.writeUInt32LE(0, sectOff + 76) // reserved3

			const pieces: Buffer[] = []
			for (let i = 0; i < commands.length; i++) {
				if (existingSegmentIndices.includes(i)) continue
				const c = commands[i]
				if (c === undefined) continue
				// Insert the new NODE_SEA segment command immediately before
				// __LINKEDIT so segment commands stay in ascending vmaddr order and
				// __LINKEDIT remains the textually-last segment, as dyld/codesign
				// require.
				if (i === linkeditIndex) {
					pieces.push(cmd)
				}
				pieces.push(Buffer.from(buf.subarray(c.offset, c.offset + c.size)))
			}
			const newLoadCmdsBuf = Buffer.concat(pieces)
			if (newLoadCmdsBuf.length !== newSizeofcmds) {
				throw new SEAError('INJECT', 'Internal Mach-O load command size mismatch', {
					executable: exePath,
				})
			}

			// --- Stream-write to a sibling temp, then atomically rename over
			// exePath: header+LCs, unchanged body up to linkeditOffset (streamed from
			// srcFd), the blob (streamed from its own fd, padded to `shift`),
			// then the relocated __LINKEDIT (streamed from srcFd). The body
			// range starts at the NEW command-region end (not the old
			// sizeofcmds) — the ceiling check above guarantees
			// [headerSize + sizeofcmds, headerSize + newSizeofcmds) lies entirely
			// in inter-command padding, so discarding those bytes absorbs the
			// growth and keeps every recorded section/segment offset (computed
			// assuming no shift) correct. Starting from the OLD sizeofcmds
			// instead would shift the entire __TEXT/__DATA body forward by the
			// growth delta, corrupting every offset already written into the new
			// load commands. ---
			const mode = fstatSync(srcFd).mode
			injTemp = join(dirname(exePath), `.inject-${randomUUID()}.tmp`)
			destFd = openSync(injTemp, 'w', mode)

			writeSync(destFd, buf.subarray(0, headerSize))
			writeSync(destFd, newLoadCmdsBuf)
			copyRange(
				srcFd,
				destFd,
				headerSize + newSizeofcmds,
				linkeditOffset - (headerSize + newSizeofcmds),
			)

			blobFd = openSync(this.#options.blob, 'r')
			copyRange(blobFd, destFd, 0, blobSize)
			closeSync(blobFd)
			blobFd = undefined

			const blobPadding = shift - blobSize
			if (blobPadding > 0) {
				writeSync(destFd, Buffer.alloc(blobPadding))
			}
			copyRange(srcFd, destFd, linkeditOffset, linkeditSize)

			closeSync(destFd)
			destFd = undefined

			// Windows cannot rename a replacement over a file that still has an open
			// handle; release the source read handle before finalizeExecutable renames.
			closeSync(srcFd)
			srcFd = undefined

			// openSync's mode is masked by umask, which can silently drop the
			// exec bit; chmod is not masked, so it reproduces the host binary's
			// permissions exactly before the temp replaces the original.
			chmodSync(injTemp, mode & 0o7777)
			finalizeExecutable(injTemp, exePath)
			injTemp = undefined

			// Build-time readback: verify the section by its section table entry,
			// consistent with what was just written.
			this.#verifyMachOSection(exePath, segmentName, sectionName, linkeditOffset, blobSize)
		} finally {
			// Guard each close so a throw from one does not skip the rest of the
			// cleanup (a leaked fd or a stray temp masking the original error).
			for (const fd of [blobFd, destFd, srcFd]) {
				if (fd !== undefined) {
					try {
						closeSync(fd)
					} catch {
						// fd may already be closed or invalid; cleanup must not throw.
					}
				}
			}
			if (injTemp !== undefined) rmSync(injTemp, { force: true })
		}
	}

	// --- Mach-O: shift every linkedit-relative offset field in a load command
	// that points at or past `threshold` by `shift` bytes ---

	#shiftMachOLinkeditOffsets(
		buf: Buffer,
		cmd: { type: number; offset: number },
		threshold: number,
		shift: number,
	): void {
		let offsets: readonly number[]
		switch (cmd.type) {
			case 0x2: // LC_SYMTAB: symoff@+8, stroff@+16
				offsets = [8, 16]
				break
			case 0xb: // LC_DYSYMTAB: tocoff/modtaboff/extrefsymoff/indirectsymoff/extreloff/locreloff
				offsets = [32, 40, 48, 56, 64, 72]
				break
			case 0x22: // LC_DYLD_INFO
			case 0x80000022: // LC_DYLD_INFO_ONLY
				// rebase_off, bind_off, weak_bind_off, lazy_bind_off, export_off
				offsets = [8, 16, 24, 32, 40]
				break
			case 0x1d: // LC_CODE_SIGNATURE
			case 0x1e: // LC_SEGMENT_SPLIT_INFO
			case 0x26: // LC_FUNCTION_STARTS
			case 0x29: // LC_DATA_IN_CODE
			case 0x80000033: // LC_DYLD_EXPORTS_TRIE
			case 0x80000034: // LC_DYLD_CHAINED_FIXUPS
				offsets = [8] // dataoff (linkedit_data_command)
				break
			default:
				// LC_TWOLEVEL_HINTS (0x16, offset@+8) and LC_ATOM_INFO also
				// point into __LINKEDIT but are intentionally not handled here
				// because they do not appear in Node.js executables.
				return
		}
		for (const offset of offsets) {
			const fieldOffset = cmd.offset + offset
			if (fieldOffset + 4 > buf.length) continue
			const value = buf.readUInt32LE(fieldOffset)
			if (value >= threshold && value > 0) {
				buf.writeUInt32LE(value + shift, fieldOffset)
			}
		}
	}

	// --- Mach-O: build-time readback — confirm the section table entry
	// matches what was written, the same shape the runtime's getsectdata
	// lookup relies on ---

	#verifyMachOSection(
		exePath: string,
		segmentName: string,
		sectionName: string,
		expectedOffset: number,
		expectedSize: number,
	): void {
		const fd = openSync(exePath, 'r')
		try {
			const header = Buffer.alloc(32)
			readSync(fd, header, 0, 32, 0)
			const ncmds = header.readUInt32LE(16)

			let offset = 32
			for (let i = 0; i < ncmds; i++) {
				const cmdHead = Buffer.alloc(8)
				readSync(fd, cmdHead, 0, 8, offset)
				const cmdType = cmdHead.readUInt32LE(0)
				const cmdSize = cmdHead.readUInt32LE(4)

				if (cmdType === MACHO_LC_SEGMENT_64 && cmdSize >= 72) {
					const segBuf = Buffer.alloc(cmdSize)
					readSync(fd, segBuf, 0, cmdSize, offset)
					const segName = stripTrailingNulls(segBuf.subarray(8, 24).toString('ascii'))
					if (segName === segmentName) {
						const nsects = segBuf.readUInt32LE(64)
						for (let s = 0; s < nsects; s++) {
							const sectOff = 72 + s * 80
							if (sectOff + 80 > segBuf.length) continue
							const secName = stripTrailingNulls(
								segBuf.subarray(sectOff, sectOff + 16).toString('ascii'),
							)
							if (secName !== sectionName) continue
							const secSize = Number(segBuf.readBigUInt64LE(sectOff + 40))
							const secOffset = segBuf.readUInt32LE(sectOff + 48)
							if (secOffset === expectedOffset && secSize === expectedSize) return
						}
					}
				}
				offset += cmdSize
			}
		} finally {
			closeSync(fd)
		}

		throw new SEAError('INJECT', 'Injected Mach-O section not found after write', {
			executable: exePath,
			segmentName,
			sectionName,
		})
	}

	// --- PE: validate section/file alignment before any `alignTo` call uses it
	// as a divisor — a malformed 0 value would otherwise silently corrupt
	// output through NaN -> `writeU32` coercion. ---

	#ensureValidPEAlignment(sectionAlignment: number, fileAlignment: number): void {
		if (!isPowerOfTwo(sectionAlignment) || !isPowerOfTwo(fileAlignment)) {
			throw new SEAError('FORMAT', 'PE section/file alignment must be a nonzero power of two', {
				executable: this.#options.executable,
				sectionAlignment,
				fileAlignment,
			})
		}
		if (sectionAlignment < fileAlignment) {
			throw new SEAError('FORMAT', 'PE sectionAlignment must be >= fileAlignment', {
				executable: this.#options.executable,
				sectionAlignment,
				fileAlignment,
			})
		}
	}
}
