import type {
	ELFProgramHeader,
	ExecutableFormat,
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

/** Owns the resources and layout cursors of one executable injection. */
export class Injection {
	#rsrcSectionIndex = 0
	#dirTableSize = 0
	#stringPoolSize = 0
	#dataRegionOffset = 0
	#dirPos = 0
	#stringPos = 0
	#dataEntryPos = 0
	#accDirOffset = 0
	#langSubdirCursor = 0
	#checksumSum = 0
	#checksumOffset = 0
	#srcFd: number | undefined
	#destFd: number | undefined
	#blobFd: number | undefined
	#injTemp: string | undefined
	#cmdOffset = 0
	#linkeditIndex = 0
	#firstSectionOffset = 0
	#verifyOffset = 0
	readonly #options: InjectorOptions
	readonly #format: ExecutableFormat

	constructor(options: InjectorOptions, format: ExecutableFormat) {
		this.#options = options
		this.#format = format
	}

	execute(): void {
		const peOptionalOffset = this.#writeFormat()

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

	#writeFormat(): number | undefined {
		switch (this.#format) {
			case 'pe':
				return this.#injectPE()
			case 'elf':
				this.#injectELF()
				return undefined
			case 'macho':
				this.#injectMachO()
				return undefined
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

			this.#rsrcSectionIndex = -1

			for (const i of Array.prototype.keys.call({ length: numberOfSections })) {
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
					this.#rsrcSectionIndex = i
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
					'ROOM',
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

			if (this.#rsrcSectionIndex !== -1 && existingResourceRVA !== 0) {
				const rsrc = sections[this.#rsrcSectionIndex]
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
			for (const i of Array.prototype.keys.call(filteredLeaves)) {
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
			const highestVaEnd = sections.reduce((highest, s) => {
				const end = s.virtualAddress + Math.max(s.virtualSize, s.rawSize)
				return end > highest ? end : highest
			}, 0)
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
			for (const i of Array.prototype.keys.call(filteredLeaves)) {
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

		for (const i of Array.prototype.keys.call({ length: totalEntries })) {
			const entryOffset = absOffset + PE_RESOURCE_DIR_SIZE + i * PE_RESOURCE_ENTRY_SIZE
			const nameOrId = readU32(fd, entryOffset)
			const offsetOrData = readU32(fd, entryOffset + 4)

			// Resolve name or ID
			const named = (nameOrId & PE_RESOURCE_NAME_FLAG) !== 0
			const entryId = named ? 0 : nameOrId
			const entryName = named
				? this.#readResourceString(fd, sectionFileOffset + (nameOrId & ~PE_RESOURCE_NAME_FLAG))
				: undefined
			const typeId = depth === 0 ? entryId : currentTypeId
			const typeName = depth === 0 ? entryName : currentTypeName
			const nameId = depth === 1 ? entryId : currentNameId
			const nameName = depth === 1 ? entryName : currentNameName

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
		for (const i of Array.prototype.keys.call(existingLeaves)) {
			const leaf = existingLeaves[i]
			if (leaf === undefined) continue
			const typeKey =
				leaf.typeName !== undefined ? `n:${leaf.typeName}` : `i:${String(leaf.typeId)}`
			const nameKey =
				leaf.nameName !== undefined ? `n:${leaf.nameName}` : `i:${String(leaf.nameId)}`

			const typeMap = tree.get(typeKey) ?? new Map()
			tree.set(typeKey, typeMap)
			const langArr = typeMap.get(nameKey) ?? []
			typeMap.set(nameKey, langArr)
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

		const typeMap = tree.get(blobTypeKey) ?? new Map()
		tree.set(blobTypeKey, typeMap)
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

		this.#dirTableSize = 0
		this.#stringPoolSize = 0

		// Root directory
		this.#dirTableSize += PE_RESOURCE_DIR_SIZE + tree.size * PE_RESOURCE_ENTRY_SIZE

		const allStrings: Array<{ key: string; value: string }> = []
		const allLeafEntries: Array<{
			leafIndex: number
			dataSize: number
			codePage: number
		}> = []

		for (const [typeKey, nameMap] of tree) {
			// Type directory
			this.#dirTableSize += PE_RESOURCE_DIR_SIZE + nameMap.size * PE_RESOURCE_ENTRY_SIZE

			// Collect type name string if named
			if (typeKey.startsWith('n:')) {
				const str = typeKey.slice(2)
				allStrings.push({ key: typeKey, value: str })
				this.#stringPoolSize += 2 + str.length * 2 // length (u16) + UTF-16LE chars
				this.#stringPoolSize = alignTo(this.#stringPoolSize, 2) // WORD align strings
			}

			for (const [nameKey, langEntries] of nameMap) {
				// Name directory
				this.#dirTableSize += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE

				// Collect name string if named
				if (nameKey.startsWith('n:')) {
					const str = nameKey.slice(2)
					allStrings.push({ key: nameKey, value: str })
					this.#stringPoolSize += 2 + str.length * 2
					this.#stringPoolSize = alignTo(this.#stringPoolSize, 2)
				}

				for (const entry of langEntries) {
					allLeafEntries.push({
						leafIndex: entry.leafIndex,
						dataSize: entry.dataSize,
						codePage: entry.codePage,
					})
				}
			}
		}

		const dataEntriesSize = allLeafEntries.length * PE_RESOURCE_DATA_ENTRY_SIZE
		const headerSize = this.#dirTableSize + this.#stringPoolSize + dataEntriesSize

		// Phase 2: Calculate data region (existing leaves + blob)
		this.#dataRegionOffset = 0
		const leafFileOffsets = new Map<number, number>() // leafIndex → offset within data region

		for (const i of Array.prototype.keys.call(allLeafEntries)) {
			const entry = allLeafEntries[i]
			if (entry === undefined) continue
			if (entry.leafIndex === -1) continue // blob handled separately

			const data = leafDataMap.get(entry.leafIndex)
			if (data !== undefined) {
				leafFileOffsets.set(entry.leafIndex, this.#dataRegionOffset)
				this.#dataRegionOffset += alignTo(data.length, 4)
			}
		}

		const blobDataOffset = this.#dataRegionOffset
		this.#dataRegionOffset += blobSize
		const dataRegionSize = this.#dataRegionOffset

		// Phase 3: Build the directory buffer with placeholder RVAs
		// RVAs will be fixed up later with the actual section VA
		const buf = Buffer.alloc(headerSize)
		this.#dirPos = 0
		this.#stringPos = this.#dirTableSize
		this.#dataEntryPos = this.#dirTableSize + this.#stringPoolSize

		// String offset lookup: key → offset within directory buffer
		const stringOffsets = new Map<string, number>()
		for (const { key, value } of allStrings) {
			stringOffsets.set(key, this.#stringPos)
			buf.writeUInt16LE(value.length, this.#stringPos)
			buf.write(value, this.#stringPos + 2, value.length * 2, 'utf16le')
			this.#stringPos += 2 + value.length * 2
			this.#stringPos = alignTo(this.#stringPos, 2)
		}

		// Sort tree entries: named entries first (sorted by name), then ID entries (sorted by ID)
		const sortedTypeKeys = this.#sortResourceKeys([...tree.keys()])

		// Helper to track subdirectory offsets for linking
		const nextDirOffset = PE_RESOURCE_DIR_SIZE + tree.size * PE_RESOURCE_ENTRY_SIZE

		// --- Write root directory ---
		const namedTypes = sortedTypeKeys.filter((k) => k.startsWith('n:'))
		const idTypes = sortedTypeKeys.filter((k) => k.startsWith('i:'))

		buf.writeUInt32LE(0, this.#dirPos) // Characteristics
		buf.writeUInt32LE(0, this.#dirPos + 4) // TimeDateStamp
		buf.writeUInt16LE(0, this.#dirPos + 8) // MajorVersion
		buf.writeUInt16LE(0, this.#dirPos + 10) // MinorVersion
		buf.writeUInt16LE(namedTypes.length, this.#dirPos + 12)
		buf.writeUInt16LE(idTypes.length, this.#dirPos + 14)
		this.#dirPos += PE_RESOURCE_DIR_SIZE

		// Pre-calculate all type subdirectory offsets
		const typeDirOffsets = new Map<string, number>()
		this.#accDirOffset = nextDirOffset
		for (const typeKey of sortedTypeKeys) {
			typeDirOffsets.set(typeKey, this.#accDirOffset)
			const nameMap = tree.get(typeKey)
			if (nameMap === undefined) continue
			const typeEntryCount = nameMap.size
			this.#accDirOffset += PE_RESOURCE_DIR_SIZE + typeEntryCount * PE_RESOURCE_ENTRY_SIZE
			for (const [, langEntries] of nameMap) {
				this.#accDirOffset += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE
			}
		}

		// Write root entries
		for (const typeKey of sortedTypeKeys) {
			const isNamed = typeKey.startsWith('n:')
			const nameOrId = isNamed
				? (stringOffsets.get(typeKey) ?? 0) | PE_RESOURCE_NAME_FLAG
				: parseInt(typeKey.slice(2), 10)
			const subdirOffset = (typeDirOffsets.get(typeKey) ?? 0) | PE_RESOURCE_SUBDIR_FLAG

			buf.writeUInt32LE(nameOrId >>> 0, this.#dirPos)
			buf.writeUInt32LE(subdirOffset >>> 0, this.#dirPos + 4)
			this.#dirPos += PE_RESOURCE_ENTRY_SIZE
		}

		// --- Write type subdirectories ---
		for (const typeKey of sortedTypeKeys) {
			const nameMap = tree.get(typeKey)
			if (nameMap === undefined) continue
			const sortedNameKeys = this.#sortResourceKeys([...nameMap.keys()])
			const namedNames = sortedNameKeys.filter((k) => k.startsWith('n:'))
			const idNames = sortedNameKeys.filter((k) => k.startsWith('i:'))

			buf.writeUInt32LE(0, this.#dirPos)
			buf.writeUInt32LE(0, this.#dirPos + 4)
			buf.writeUInt16LE(0, this.#dirPos + 8)
			buf.writeUInt16LE(0, this.#dirPos + 10)
			buf.writeUInt16LE(namedNames.length, this.#dirPos + 12)
			buf.writeUInt16LE(idNames.length, this.#dirPos + 14)
			this.#dirPos += PE_RESOURCE_DIR_SIZE

			// Calculate offset of each name's language subdirectory
			// These come sequentially after the current type directory and its entries
			this.#langSubdirCursor = this.#dirPos + sortedNameKeys.length * PE_RESOURCE_ENTRY_SIZE

			for (const nameKey of sortedNameKeys) {
				const isNamed = nameKey.startsWith('n:')
				const nameOrId = isNamed
					? (stringOffsets.get(nameKey) ?? 0) | PE_RESOURCE_NAME_FLAG
					: parseInt(nameKey.slice(2), 10)

				// The language subdirectory offset is relative to resource section start
				const langSubDirRelOffset = this.#langSubdirCursor | PE_RESOURCE_SUBDIR_FLAG

				buf.writeUInt32LE(nameOrId >>> 0, this.#dirPos)
				buf.writeUInt32LE(langSubDirRelOffset >>> 0, this.#dirPos + 4)
				this.#dirPos += PE_RESOURCE_ENTRY_SIZE

				const langEntries = nameMap.get(nameKey)
				if (langEntries !== undefined) {
					this.#langSubdirCursor +=
						PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE
				}
			}

			// Write language subdirectories for each name
			for (const nameKey of sortedNameKeys) {
				const langEntries = nameMap.get(nameKey)
				if (langEntries === undefined) continue

				buf.writeUInt32LE(0, this.#dirPos)
				buf.writeUInt32LE(0, this.#dirPos + 4)
				buf.writeUInt16LE(0, this.#dirPos + 8)
				buf.writeUInt16LE(0, this.#dirPos + 10)
				buf.writeUInt16LE(0, this.#dirPos + 12) // no named language entries
				buf.writeUInt16LE(langEntries.length, this.#dirPos + 14)
				this.#dirPos += PE_RESOURCE_DIR_SIZE

				for (const entry of langEntries) {
					// Language ID
					buf.writeUInt32LE(entry.language, this.#dirPos)

					// Data entry offset (not a subdirectory — no high bit)
					buf.writeUInt32LE(this.#dataEntryPos, this.#dirPos + 4)
					this.#dirPos += PE_RESOURCE_ENTRY_SIZE

					// Write the data entry
					// DataRVA — placeholder, will be fixed up with actual VA
					const resolvedOffset =
						entry.leafIndex === -1 ? blobDataOffset : leafFileOffsets.get(entry.leafIndex)
					if (resolvedOffset === undefined) {
						throw new SEAError('INJECT', 'unresolvable resource RVA', {
							executable: this.#options.executable,
							leafIndex: entry.leafIndex,
						})
					}
					const dataOffset = headerSize + resolvedOffset

					// Store as relative offset from section start for now;
					// #fixupDataEntries will add the section VA
					buf.writeUInt32LE(dataOffset, this.#dataEntryPos) // DataRVA (placeholder)
					buf.writeUInt32LE(entry.dataSize, this.#dataEntryPos + 4) // Size
					buf.writeUInt32LE(entry.codePage, this.#dataEntryPos + 8) // CodePage
					buf.writeUInt32LE(0, this.#dataEntryPos + 12) // Reserved
					this.#dataEntryPos += PE_RESOURCE_DATA_ENTRY_SIZE
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

		for (const i of Array.prototype.keys.call({ length: totalEntries })) {
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

			this.#checksumSum = 0
			this.#checksumOffset = 0
			while (this.#checksumOffset < fileSize) {
				const toRead = Math.min(chunkSize, fileSize - this.#checksumOffset)
				const bytesRead = readSync(fd, chunk, 0, toRead, this.#checksumOffset)
				if (bytesRead === 0) break

				for (const i of Array.prototype.keys
					.call({ length: Math.ceil(bytesRead / 2) })
					.map((index) => index * 2)) {
					const absolute = this.#checksumOffset + i
					const word =
						absolute === checksumOffset || absolute === checksumOffset + 2
							? 0
							: i + 1 < bytesRead
								? chunk.readUInt16LE(i)
								: chunk.readUInt8(i)
					this.#checksumSum += word
					this.#checksumSum = (this.#checksumSum & 0xffff) + (this.#checksumSum >>> 16)
				}

				this.#checksumOffset += bytesRead
			}

			this.#checksumSum = (this.#checksumSum & 0xffff) + (this.#checksumSum >>> 16)
			const checksum = (this.#checksumSum + fileSize) >>> 0

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
	// Node.js SEA on Linux reads PT_NOTE segments through dl_iterate_phdr,
	// searching for a note whose name matches the resource name.

	#injectELF(): void {
		const exePath = this.#options.executable
		const resource = this.#options.resource
		const overwrite = this.#options.overwrite !== false

		const { phdrEntrySize, headers } = this.#prepareELF(exePath, resource, overwrite)

		// --- Compute the new PT_LOAD/PT_NOTE placement ---
		// The note MUST live inside a PT_LOAD so the runtime's dl_iterate_phdr
		// walk can read it from the mapped virtual address (Node reads
		// NODE_SEA notes from memory, never from the file).
		const maxVaddrEnd = headers.reduce((highest, header) => {
			if (header.type !== ELF_PT_LOAD) return highest
			const end = header.vaddr + header.memsz
			return end > highest ? end : highest
		}, 0)
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
		for (const i of Array.prototype.keys.call(finalHeaders)) {
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

	#prepareELF(exePath: string, resource: string, overwrite: boolean) {
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

			const phdrOffset = Number(readU64(fd, 32)) // e_phoff
			const phdrEntrySize = readU16(fd, 54) // e_phentsize
			const phdrCount = readU16(fd, 56) // e_phnum

			const headers = this.#readELFProgramHeaders(fd, phdrOffset, phdrEntrySize, phdrCount)

			// Collect any stale PT_NOTE with a matching name, refusing the whole
			// injection first when the caller forbade an overwrite.
			const stale = new Set<number>()
			for (const i of Array.prototype.keys.call(headers)) {
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
			return {
				phdrEntrySize,
				headers: headers.map((header, index) =>
					stale.has(index) ? { ...header, type: 0 } : header,
				),
			}
		} finally {
			closeSync(fd)
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
		for (const i of Array.prototype.keys.call({ length: count })) {
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
	// blob. The segment defaults to "__POSTJECT", or to a custom name the
	// options carry, and the section is "__" + resource.

	#injectMachO(): void {
		const exePath = this.#options.executable
		const fileSize = statSync(exePath).size
		this.#srcFd = openSync(exePath, 'r')

		try {
			// --- Bounded header read: only enough to cover every header/LC parse
			// and mutation below (headerSize + sizeofcmds) — never the whole file. ---
			const headerSize = 32 // Mach-O 64-bit header
			const preHeader = Buffer.alloc(headerSize)
			readSync(this.#srcFd, preHeader, 0, headerSize, 0)
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
			readSync(this.#srcFd, buf, 0, headerSize + preSizeofcmds, 0)

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
			const resource = this.#options.resource
			const sectionName = resource.startsWith('__') ? resource : `__${resource}`

			// --- Walk load commands once, collecting their bounds ---
			const commands: Array<{ type: number; size: number; offset: number }> = []
			this.#cmdOffset = headerSize
			for (const _ of Array.prototype.keys.call({ length: ncmds })) {
				if (this.#cmdOffset + 8 > buf.length) {
					throw new SEAError('FORMAT', 'Malformed Mach-O load command table', {
						executable: exePath,
					})
				}
				const cmdType = buf.readUInt32LE(this.#cmdOffset)
				const cmdSize = buf.readUInt32LE(this.#cmdOffset + 4)
				if (cmdSize < 8 || this.#cmdOffset + cmdSize > buf.length) {
					throw new SEAError('FORMAT', 'Malformed Mach-O load command table', {
						executable: exePath,
					})
				}
				commands.push({ type: cmdType, size: cmdSize, offset: this.#cmdOffset })
				this.#cmdOffset += cmdSize
			}

			this.#linkeditIndex = -1
			const existingSegmentIndices: number[] = []
			for (const i of Array.prototype.keys.call(commands)) {
				const cmd = commands[i]
				if (cmd === undefined || cmd.type !== MACHO_LC_SEGMENT_64) continue
				const segName = stripTrailingNulls(
					buf.subarray(cmd.offset + 8, cmd.offset + 24).toString('ascii'),
				)
				if (segName === '__LINKEDIT') this.#linkeditIndex = i
				if (segName === segmentName) existingSegmentIndices.push(i)
			}

			if (existingSegmentIndices.length > 0 && this.#options.overwrite === false) {
				throw new SEAError('INJECT', `Segment "${segmentName}" already exists`, {
					executable: exePath,
					segmentName,
				})
			}
			const linkeditCmd = this.#linkeditIndex === -1 ? undefined : commands[this.#linkeditIndex]
			if (linkeditCmd === undefined) {
				throw new SEAError('ROOM', 'Mach-O binary has no __LINKEDIT segment', {
					executable: exePath,
				})
			}

			const linkeditOffset = Number(buf.readBigUInt64LE(linkeditCmd.offset + 40))
			const linkeditSize = Number(buf.readBigUInt64LE(linkeditCmd.offset + 48))
			const linkeditAddress = buf.readBigUInt64LE(linkeditCmd.offset + 24)

			const blobSize = statSync(this.#options.blob).size
			// arm64 (0x0100000c) requires 16K pages; every other architecture,
			// including x86_64, uses 4K — 0x4000 is a safe superset alignment for either.
			const pageSize = cputype === 0x0100000c ? 0x4000 : 0x1000
			const shift = alignTo(blobSize, pageSize)

			// --- Ceiling check BEFORE mutating anything: the enlarged load-command
			// region (plus 16 bytes reserved for codesign re-adding
			// LC_CODE_SIGNATURE) must not overrun the first real section's bytes.
			// The sentinel starts at the FULL file size (not the bounded `buf`
			// size) — it represents "no section found yet", not a hard ceiling. ---
			this.#firstSectionOffset = fileSize
			for (const cmd of commands) {
				if (cmd.type !== MACHO_LC_SEGMENT_64) continue
				const nsects = buf.readUInt32LE(cmd.offset + 64)
				for (const s of Array.prototype.keys.call({ length: nsects })) {
					const sectOff = cmd.offset + 72 + s * 80
					if (sectOff + 80 > buf.length) continue
					const size = Number(buf.readBigUInt64LE(sectOff + 40))
					const offset = buf.readUInt32LE(sectOff + 48)
					if (size > 0 && offset > 0 && offset < this.#firstSectionOffset) {
						this.#firstSectionOffset = offset
					}
				}
			}

			const newCmdSize = 72 + 80
			const removedSize = commands
				.filter((_c, i) => existingSegmentIndices.includes(i))
				.reduce((sum, c) => sum + c.size, 0)
			const newNcmds = commands.length - existingSegmentIndices.length + 1
			const newSizeofcmds = sizeofcmds - removedSize + newCmdSize

			if (headerSize + newSizeofcmds + 16 > this.#firstSectionOffset) {
				throw new SEAError(
					'ROOM',
					`Not enough header space for new Mach-O load command ` +
						`(need offset ${String(headerSize + newSizeofcmds + 16)}, first section at ${String(this.#firstSectionOffset)})`,
					{
						executable: exePath,
						firstSectionOffset: this.#firstSectionOffset,
						requiredOffset: headerSize + newSizeofcmds + 16,
					},
				)
			}

			// --- Mutate in place: shift __LINKEDIT and every linkedit-relative
			// offset field in the surviving commands, using the ORIGINAL
			// linkeditOffset as the "does this offset point into __LINKEDIT"
			// threshold. ---
			for (const i of Array.prototype.keys.call(commands)) {
				const cmd = commands[i]
				if (cmd === undefined || existingSegmentIndices.includes(i)) continue

				if (cmd.type === MACHO_LC_SEGMENT_64) {
					const segName = stripTrailingNulls(
						buf.subarray(cmd.offset + 8, cmd.offset + 24).toString('ascii'),
					)
					if (segName === '__LINKEDIT') {
						const nsects = buf.readUInt32LE(cmd.offset + 64)
						if (nsects > 0) {
							throw new SEAError('ROOM', '__LINKEDIT segment with sections is not supported', {
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
			for (const i of Array.prototype.keys.call(commands)) {
				if (existingSegmentIndices.includes(i)) continue
				const c = commands[i]
				if (c === undefined) continue
				// Insert the new NODE_SEA segment command immediately before
				// __LINKEDIT so segment commands stay in ascending vmaddr order and
				// __LINKEDIT remains the textually-last segment, as dyld/codesign
				// require.
				if (i === this.#linkeditIndex) {
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
			// the source descriptor), the blob (streamed from its own descriptor, padded to `shift`),
			// then the relocated __LINKEDIT (streamed from the source descriptor). The body
			// range starts at the NEW command-region end (not the old
			// sizeofcmds) — the ceiling check above guarantees
			// [headerSize + sizeofcmds, headerSize + newSizeofcmds) lies entirely
			// in inter-command padding, so discarding those bytes absorbs the
			// growth and keeps every recorded section/segment offset (computed
			// assuming no shift) correct. Starting from the OLD sizeofcmds
			// instead would shift the entire __TEXT/__DATA body forward by the
			// growth delta, corrupting every offset already written into the new
			// load commands. ---
			const mode = fstatSync(this.#srcFd).mode
			this.#injTemp = join(dirname(exePath), `.inject-${randomUUID()}.tmp`)
			this.#destFd = openSync(this.#injTemp, 'w', mode)

			writeSync(this.#destFd, buf.subarray(0, headerSize))
			writeSync(this.#destFd, newLoadCmdsBuf)
			copyRange(
				this.#srcFd,
				this.#destFd,
				headerSize + newSizeofcmds,
				linkeditOffset - (headerSize + newSizeofcmds),
			)

			this.#blobFd = openSync(this.#options.blob, 'r')
			copyRange(this.#blobFd, this.#destFd, 0, blobSize)
			closeSync(this.#blobFd)
			this.#blobFd = undefined

			const blobPadding = shift - blobSize
			if (blobPadding > 0) {
				writeSync(this.#destFd, Buffer.alloc(blobPadding))
			}
			copyRange(this.#srcFd, this.#destFd, linkeditOffset, linkeditSize)

			closeSync(this.#destFd)
			this.#destFd = undefined

			// Windows cannot rename a replacement over a file that still has an open
			// handle; release the source read handle before finalizeExecutable renames.
			closeSync(this.#srcFd)
			this.#srcFd = undefined

			// openSync's mode is masked by umask, which can silently drop the
			// exec bit; chmod is not masked, so it reproduces the host binary's
			// permissions exactly before the temp replaces the original.
			chmodSync(this.#injTemp, mode & 0o7777)
			finalizeExecutable(this.#injTemp, exePath)
			this.#injTemp = undefined

			// Build-time readback: verify the section by its section table entry,
			// consistent with what was written.
			this.#verifyMachOSection(exePath, segmentName, sectionName, linkeditOffset, blobSize)
		} finally {
			// Guard each close so a throw from one does not skip the rest of the
			// cleanup (a leaked fd or a stray temp masking the original error).
			for (const fd of [this.#blobFd, this.#destFd, this.#srcFd]) {
				if (fd !== undefined) {
					try {
						closeSync(fd)
					} catch {
						// fd may already be closed or invalid; cleanup must not throw.
					}
				}
			}
			if (this.#injTemp !== undefined) rmSync(this.#injTemp, { force: true })
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
		const offsets =
			cmd.type === 0x2
				? [8, 16]
				: cmd.type === 0xb
					? [32, 40, 48, 56, 64, 72]
					: cmd.type === 0x22 || cmd.type === 0x80000022
						? [8, 16, 24, 32, 40]
						: [0x1d, 0x1e, 0x26, 0x29, 0x80000033, 0x80000034].includes(cmd.type)
							? [8]
							: []
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

			this.#verifyOffset = 32
			for (const _ of Array.prototype.keys.call({ length: ncmds })) {
				const cmdHead = Buffer.alloc(8)
				readSync(fd, cmdHead, 0, 8, this.#verifyOffset)
				const cmdType = cmdHead.readUInt32LE(0)
				const cmdSize = cmdHead.readUInt32LE(4)

				if (cmdType === MACHO_LC_SEGMENT_64 && cmdSize >= 72) {
					const segBuf = Buffer.alloc(cmdSize)
					readSync(fd, segBuf, 0, cmdSize, this.#verifyOffset)
					const segName = stripTrailingNulls(segBuf.subarray(8, 24).toString('ascii'))
					if (segName === segmentName) {
						const nsects = segBuf.readUInt32LE(64)
						for (const s of Array.prototype.keys.call({ length: nsects })) {
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
				this.#verifyOffset += cmdSize
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
