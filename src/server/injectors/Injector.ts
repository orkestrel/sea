/**
 * Injector
 *
 * Cross-platform binary resource injector for PE, ELF, and Mach-O executables.
 * Pure TypeScript file I/O — no WASM, no external tools, no size ceiling.
 *
 * PE  — adds an RT_RCDATA resource via resource directory rebuild.
 * ELF — appends a PT_NOTE segment with the blob as note data.
 * Mach-O — appends an LC_SEGMENT_64 load command with a section.
 */

import type { ExecutableFormat, InjectorInterface, InjectorOptions } from '../../types.js'
import {
	openSync,
	readSync,
	writeSync,
	closeSync,
	statSync,
	appendFileSync,
	readFileSync,
	writeFileSync,
} from 'node:fs'
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
	MACHO_MAGIC_64,
	MACHO_LC_SEGMENT_64,
} from '../../constants.js'
import { patchSentinelFuse } from '../../helpers.js'

// === Injector

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
		switch (this.#format) {
			case 'pe':
				this.#injectPe()
				break
			case 'elf':
				this.#injectElf()
				break
			case 'macho':
				this.#injectMacho()
				break
		}

		if (this.#options.fuse !== undefined) {
			patchSentinelFuse(this.#options.executable, this.#options.fuse)
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

			throw new Error(
				`Unknown executable format (magic: 0x${magic32.toString(16).padStart(8, '0')})`,
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

	#injectPe(): void {
		const fd = openSync(this.#options.executable, 'r+')
		try {
			// --- Parse PE headers ---
			const peOffset = this.#readU32(fd, 0x3c)
			const sig = this.#readU32(fd, peOffset)
			if (sig !== PE_SIGNATURE) {
				throw new Error('Invalid PE signature')
			}

			const coffOffset = peOffset + 4
			const numberOfSections = this.#readU16(fd, coffOffset + 2)
			const optionalHeaderSize = this.#readU16(fd, coffOffset + 16)
			const optionalOffset = coffOffset + 20

			const optMagic = this.#readU16(fd, optionalOffset)
			const is64 = optMagic === PE32_PLUS_MAGIC
			if (optMagic !== PE32_MAGIC && optMagic !== PE32_PLUS_MAGIC) {
				throw new Error(`Unsupported PE optional header magic: 0x${optMagic.toString(16)}`)
			}

			const sectionAlignment = this.#readU32(fd, optionalOffset + 32)
			const fileAlignment = this.#readU32(fd, optionalOffset + 36)

			// SizeOfImage offset: same in PE32 and PE32+
			const sizeOfImageOffset = optionalOffset + 56

			// Data directory starts after the fixed optional header fields
			// PE32: 96 bytes fixed + data dirs; PE32+: 112 bytes fixed + data dirs
			const dataDirOffset = optionalOffset + (is64 ? 112 : 96)

			// Resource table is data directory entry index 2
			const resourceDirRvaOffset = dataDirOffset + 2 * 8
			const resourceDirSizeOffset = resourceDirRvaOffset + 4
			const existingResourceRva = this.#readU32(fd, resourceDirRvaOffset)

			// --- Parse section table ---
			const sectionTableOffset = optionalOffset + optionalHeaderSize

			// Collect all sections and find the resource section
			const sections: Array<{
				name: string
				virtualSize: number
				virtualAddress: number
				rawSize: number
				rawOffset: number
				characteristics: number
				headerOffset: number
			}> = []

			let rsrcSectionIndex = -1

			for (let i = 0; i < numberOfSections; i++) {
				const off = sectionTableOffset + i * PE_SECTION_HEADER_SIZE
				const nameBuf = Buffer.alloc(8)
				readSync(fd, nameBuf, 0, 8, off)
				const name = this.#stripTrailingNulls(nameBuf.toString('ascii'))
				const virtualSize = this.#readU32(fd, off + 8)
				const virtualAddress = this.#readU32(fd, off + 12)
				const rawSize = this.#readU32(fd, off + 16)
				const rawOffset = this.#readU32(fd, off + 20)
				const characteristics = this.#readU32(fd, off + 36)

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
					existingResourceRva >= virtualAddress &&
					existingResourceRva < virtualAddress + Math.max(virtualSize, rawSize)
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
				throw new Error(
					'No room in PE header for a new section entry ' +
						`(${String(availableHeaderSpace)} bytes available, need ${String(PE_SECTION_HEADER_SIZE)})`,
				)
			}

			// --- Gather existing resource leaves ---
			const existingLeaves: Array<{
				typeId: number
				typeName: string | undefined
				nameId: number
				nameName: string | undefined
				language: number
				codePage: number
				dataRva: number
				dataSize: number
			}> = []

			if (rsrcSectionIndex !== -1 && existingResourceRva !== 0) {
				const rsrc = sections[rsrcSectionIndex]
				if (rsrc !== undefined) {
					this.#parseResourceDirectory(
						fd,
						rsrc.rawOffset,
						existingResourceRva,
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
				const fileOffset = this.#rvaToFileOffset(leaf.dataRva, sections)
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
			const alignedRawSize = this.#align(totalRawSize, fileAlignment)

			// --- Determine new section placement ---
			// Virtual address: highest VA end of all sections, aligned
			let highestVaEnd = 0
			for (const s of sections) {
				const end = s.virtualAddress + Math.max(s.virtualSize, s.rawSize)
				if (end > highestVaEnd) highestVaEnd = end
			}
			const newVa = this.#align(highestVaEnd, sectionAlignment)
			const newVirtualSize = totalRawSize

			// File offset: end of file, aligned
			const fileSize = statSync(this.#options.executable).size
			const newRawOffset = this.#align(fileSize, fileAlignment)

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
			this.#writeU16(fd, coffOffset + 2, numberOfSections + 1)

			// Resource data directory → point to new section
			this.#writeU32(fd, resourceDirRvaOffset, newVa)
			this.#writeU32(fd, resourceDirSizeOffset, directoryBuffer.length)

			// SizeOfImage — must cover the new section
			const newSizeOfImage = this.#align(
				newVa + Math.max(newVirtualSize, alignedRawSize),
				sectionAlignment,
			)
			this.#writeU32(fd, sizeOfImageOffset, newSizeOfImage)

			closeSync(fd)

			// --- Write new section data to file ---
			// Pad file to aligned offset
			const currentFileSize = statSync(this.#options.executable).size
			if (newRawOffset > currentFileSize) {
				const padding = Buffer.alloc(newRawOffset - currentFileSize)
				appendFileSync(this.#options.executable, padding)
			}

			// Fixup RVAs in the directory buffer: add newVa as base
			this.#fixupDirectoryRvas(directoryBuffer, newVa)

			// Write the directory buffer
			appendFileSync(this.#options.executable, directoryBuffer)

			// Write existing resource data
			for (let i = 0; i < filteredLeaves.length; i++) {
				const data = leafDataMap.get(i)
				if (data !== undefined) {
					appendFileSync(this.#options.executable, data)
					// Pad to DWORD alignment
					const padLen = this.#align(data.length, 4) - data.length
					if (padLen > 0) {
						appendFileSync(this.#options.executable, Buffer.alloc(padLen))
					}
				}
			}

			// Stream the blob from disk
			this.#appendFile(this.#options.executable, this.#options.blob)

			// Pad the section to aligned raw size
			const writtenSize = statSync(this.#options.executable).size - newRawOffset
			if (writtenSize < alignedRawSize) {
				appendFileSync(this.#options.executable, Buffer.alloc(alignedRawSize - writtenSize))
			}
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
		leaves: Array<{
			typeId: number
			typeName: string | undefined
			nameId: number
			nameName: string | undefined
			language: number
			codePage: number
			dataRva: number
			dataSize: number
		}>,
		depth: number,
		currentTypeId: number,
		currentTypeName: string | undefined,
		currentNameId: number,
		currentNameName: string | undefined,
	): void {
		const absOffset = sectionFileOffset + dirOffset

		// IMAGE_RESOURCE_DIRECTORY: 16 bytes
		const numNamedEntries = this.#readU16(fd, absOffset + 12)
		const numIdEntries = this.#readU16(fd, absOffset + 14)
		const totalEntries = numNamedEntries + numIdEntries

		for (let i = 0; i < totalEntries; i++) {
			const entryOffset = absOffset + PE_RESOURCE_DIR_SIZE + i * PE_RESOURCE_ENTRY_SIZE
			const nameOrId = this.#readU32(fd, entryOffset)
			const offsetOrData = this.#readU32(fd, entryOffset + 4)

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
				const dataRva = this.#readU32(fd, dataEntryFileOffset)
				const dataSize = this.#readU32(fd, dataEntryFileOffset + 4)
				const codePage = this.#readU32(fd, dataEntryFileOffset + 8)

				const language = depth === 2 ? entryId : 0

				leaves.push({
					typeId,
					typeName,
					nameId,
					nameName,
					language,
					codePage,
					dataRva,
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

	#rvaToFileOffset(
		rva: number,
		sections: ReadonlyArray<{
			readonly virtualAddress: number
			readonly virtualSize: number
			readonly rawSize: number
			readonly rawOffset: number
		}>,
	): number {
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
		existingLeaves: ReadonlyArray<{
			readonly typeId: number
			readonly typeName: string | undefined
			readonly nameId: number
			readonly nameName: string | undefined
			readonly language: number
			readonly codePage: number
			readonly dataRva: number
			readonly dataSize: number
		}>,
		blobName: string,
		blobSize: number,
	): Map<
		string,
		Map<
			string,
			Array<{
				language: number
				codePage: number
				leafIndex: number
				dataSize: number
			}>
		>
	> {
		// Tree: typeKey → nameKey → language entries
		// typeKey/nameKey encode both named and integer IDs
		const tree = new Map<
			string,
			Map<
				string,
				Array<{
					language: number
					codePage: number
					leafIndex: number
					dataSize: number
				}>
			>
		>()

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
		tree: Map<
			string,
			Map<
				string,
				Array<{
					language: number
					codePage: number
					leafIndex: number
					dataSize: number
				}>
			>
		>,
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
				stringPoolSize = this.#align(stringPoolSize, 2) // WORD align strings
			}

			for (const [nameKey, langEntries] of nameMap) {
				// Name directory
				dirTableSize += PE_RESOURCE_DIR_SIZE + langEntries.length * PE_RESOURCE_ENTRY_SIZE

				// Collect name string if named
				if (nameKey.startsWith('n:')) {
					const str = nameKey.slice(2)
					allStrings.push({ key: nameKey, value: str })
					stringPoolSize += 2 + str.length * 2
					stringPoolSize = this.#align(stringPoolSize, 2)
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
				dataRegionOffset += this.#align(data.length, 4)
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
			stringPos = this.#align(stringPos, 2)
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
						dataOffset = headerSize + (leafFileOffsets.get(entry.leafIndex) ?? 0)
					}

					// Store as relative offset from section start for now;
					// #fixupDirectoryRvas will add the section VA
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

	#fixupDirectoryRvas(directoryBuffer: Buffer, sectionVa: number): void {
		// Data entries are at the end of the directory buffer.
		// Each is 16 bytes: DataRVA(4), Size(4), CodePage(4), Reserved(4)
		// We need to find them and add sectionVa to the DataRVA field.
		//
		// Data entries are pointed to by level-2 directory entries.
		// Rather than re-walking the tree, we know that data entries are
		// contiguous at the end of the buffer (before strings, which we
		// placed between directories and data entries — wait, actually
		// strings come before data entries in our layout).
		//
		// Our layout: [directories] [strings] [data entries]
		// The data entries all need their first DWORD (DataRVA) adjusted.
		//
		// We can find them by scanning for references from directory entries.
		// But a simpler approach: we marked data entry positions during
		// serialization. Let's just scan the buffer for data entry blocks.
		//
		// Actually the simplest: re-walk the level-2 directory entries to
		// find the data entry offsets, then fix them up.

		this.#fixupDataEntries(directoryBuffer, 0, 0, sectionVa)
	}

	#fixupDataEntries(buf: Buffer, dirOffset: number, depth: number, sectionVa: number): void {
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
				this.#fixupDataEntries(buf, subOffset, depth + 1, sectionVa)
			} else {
				// Data entry — fix up the RVA
				if (offsetOrData + 4 <= buf.length) {
					const currentRva = buf.readUInt32LE(offsetOrData)
					buf.writeUInt32LE((currentRva + sectionVa) >>> 0, offsetOrData)
				}
			}
		}
	}

	// --- PE: sort resource keys (named first alphabetically, then IDs numerically) ---

	#sortResourceKeys(keys: readonly string[]): readonly string[] {
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

	#injectElf(): void {
		const exePath = this.#options.executable
		const fd = openSync(exePath, 'r+')

		try {
			// --- Parse ELF header ---
			const identBuf = Buffer.alloc(16)
			readSync(fd, identBuf, 0, 16, 0)

			const elfClass = identBuf.readUInt8(4)
			const elfData = identBuf.readUInt8(5)

			if (elfClass !== ELF_CLASS_64) {
				throw new Error('Only 64-bit ELF executables are supported')
			}
			if (elfData !== ELF_DATA_LSB) {
				throw new Error('Only little-endian ELF executables are supported')
			}

			// ELF64 header fields
			const phdrOffset = this.#readU64(fd, 32) // e_phoff
			const phdrEntrySize = this.#readU16(fd, 54) // e_phentsize
			const phdrCount = this.#readU16(fd, 56) // e_phnum

			// --- Find an existing PT_NOTE or free slot ---
			// We look for an existing PT_NOTE whose note name matches (for overwrite)
			// or we use a NULL (type 0) entry as a free slot for a new PT_NOTE.
			let targetPhdrOffset = -1

			for (let i = 0; i < phdrCount; i++) {
				const off = Number(phdrOffset) + i * phdrEntrySize
				const pType = this.#readU32(fd, off)

				if (pType === ELF_PT_NOTE) {
					// Check if this note matches our resource name
					const noteOffset = Number(this.#readU64(fd, off + 8)) // p_offset
					const noteSize = Number(this.#readU64(fd, off + 32)) // p_filesz
					if (this.#elfNoteContains(fd, noteOffset, noteSize, this.#options.resource)) {
						if (this.#options.overwrite !== false) {
							targetPhdrOffset = off
							break
						}
						throw new Error(`Note with name "${this.#options.resource}" already exists`)
					}
				}

				// Use a PT_NULL (type 0) entry as a free slot
				if (pType === 0 && targetPhdrOffset === -1) {
					targetPhdrOffset = off
				}
			}

			if (targetPhdrOffset === -1) {
				throw new Error(
					'No free program header entry (PT_NULL) available for a new PT_NOTE segment',
				)
			}

			// --- Build the note ---
			const nameBytes = Buffer.from(this.#options.resource + '\0', 'utf-8')
			const nameSize = nameBytes.length
			const alignedNameSize = this.#align(nameSize, 4)

			const blobSize = statSync(this.#options.blob).size
			const alignedDescSize = this.#align(blobSize, 4)

			// Note header: namesz (4) + descsz (4) + type (4) = 12
			const noteHeaderSize = 12
			const noteHeader = Buffer.alloc(noteHeaderSize + alignedNameSize)
			noteHeader.writeUInt32LE(nameSize, 0)
			noteHeader.writeUInt32LE(blobSize, 4)
			noteHeader.writeUInt32LE(0, 8) // type: 0 (generic)
			nameBytes.copy(noteHeader, noteHeaderSize)

			// --- Append to file ---
			closeSync(fd)

			const fileSize = statSync(exePath).size
			const noteFileOffset = this.#align(fileSize, 8)

			// Pad to alignment
			if (noteFileOffset > fileSize) {
				appendFileSync(exePath, Buffer.alloc(noteFileOffset - fileSize))
			}

			// Write note header + name
			appendFileSync(exePath, noteHeader)

			// Stream blob data
			this.#appendFile(exePath, this.#options.blob)

			// Pad desc to alignment
			const descPadding = alignedDescSize - blobSize
			if (descPadding > 0) {
				appendFileSync(exePath, Buffer.alloc(descPadding))
			}

			const totalNoteSize = noteHeader.length + alignedDescSize

			// --- Update program header entry ---
			const fd2 = openSync(exePath, 'r+')
			try {
				// p_type = PT_NOTE (4)
				this.#writeU32(fd2, targetPhdrOffset, ELF_PT_NOTE)
				// p_flags (4) = PF_R (0x4)
				this.#writeU32(fd2, targetPhdrOffset + 4, 0x4)
				// p_offset (8) = file offset of the note
				this.#writeU64(fd2, targetPhdrOffset + 8, BigInt(noteFileOffset))
				// p_vaddr (8) = 0 (not loaded into a specific VA)
				this.#writeU64(fd2, targetPhdrOffset + 16, 0n)
				// p_paddr (8) = 0
				this.#writeU64(fd2, targetPhdrOffset + 24, 0n)
				// p_filesz (8) = total note size
				this.#writeU64(fd2, targetPhdrOffset + 32, BigInt(totalNoteSize))
				// p_memsz (8) = same
				this.#writeU64(fd2, targetPhdrOffset + 40, BigInt(totalNoteSize))
				// p_align (8) = 4
				this.#writeU64(fd2, targetPhdrOffset + 48, 4n)
			} finally {
				closeSync(fd2)
			}
		} catch (error: unknown) {
			try {
				closeSync(fd)
			} catch {
				/* already closed */
			}
			throw error
		}
	}

	// --- ELF: check if a note segment contains a note with the given name ---

	#elfNoteContains(fd: number, offset: number, size: number, name: string): boolean {
		let pos = 0
		while (pos + 12 <= size) {
			const namesz = this.#readU32(fd, offset + pos)
			const descsz = this.#readU32(fd, offset + pos + 4)

			if (namesz > 0 && namesz <= 256) {
				const nameBuf = Buffer.alloc(namesz)
				readSync(fd, nameBuf, 0, namesz, offset + pos + 12)
				const noteName = this.#stripTrailingNulls(nameBuf.toString('utf-8'))
				if (noteName === name) return true
			}

			pos += 12 + this.#align(namesz, 4) + this.#align(descsz, 4)
		}
		return false
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

	#injectMacho(): void {
		const exePath = this.#options.executable
		const buf = readFileSync(exePath)

		// --- Parse Mach-O header ---
		const magic = buf.readUInt32LE(0)
		if (magic !== MACHO_MAGIC_64) {
			throw new Error(`Unsupported Mach-O magic: 0x${magic.toString(16)}`)
		}

		const ncmds = buf.readUInt32LE(16)
		const sizeofcmds = buf.readUInt32LE(20)
		const headerSize = 32 // Mach-O 64-bit header

		// --- Find highest segment end and check for existing section ---
		const segmentName = this.#options.macho?.segment ?? 'NODE_SEA'
		let sectionName = this.#options.resource
		if (!sectionName.startsWith('__')) {
			sectionName = `__${sectionName}`
		}

		let highestFileEnd = 0
		let highestVmEnd = BigInt(0)
		let cmdOffset = headerSize

		for (let i = 0; i < ncmds; i++) {
			const cmdType = buf.readUInt32LE(cmdOffset)
			const cmdSize = buf.readUInt32LE(cmdOffset + 4)

			if (cmdType === MACHO_LC_SEGMENT_64) {
				const segName = this.#stripTrailingNulls(
					buf.subarray(cmdOffset + 8, cmdOffset + 24).toString('ascii'),
				)
				const vmaddr = buf.readBigUInt64LE(cmdOffset + 24)
				const vmsize = buf.readBigUInt64LE(cmdOffset + 32)
				const fileoff = buf.readBigUInt64LE(cmdOffset + 40)
				const filesize = buf.readBigUInt64LE(cmdOffset + 48)

				const segFileEnd = Number(fileoff) + Number(filesize)
				if (segFileEnd > highestFileEnd) highestFileEnd = segFileEnd

				const segVmEnd = vmaddr + vmsize
				if (segVmEnd > highestVmEnd) highestVmEnd = segVmEnd

				// Check for existing segment with same name
				if (segName === segmentName) {
					if (this.#options.overwrite === false) {
						throw new Error(`Segment "${segmentName}" already exists`)
					}
					// For overwrite, we'll just add a new one at the end
					// (the old one becomes dead space — macOS will load the last one)
				}
			}

			cmdOffset += cmdSize
		}

		// --- Check header space for new load command ---
		// LC_SEGMENT_64 with one section = 72 (segment) + 80 (section) = 152 bytes
		const newCmdSize = 72 + 80
		const usedHeaderSpace = headerSize + sizeofcmds

		// Find the actual first segment file offset
		let firstSegOff = buf.length
		cmdOffset = headerSize
		for (let i = 0; i < ncmds; i++) {
			const cmdType = buf.readUInt32LE(cmdOffset)
			const cmdSize = buf.readUInt32LE(cmdOffset + 4)
			if (cmdType === MACHO_LC_SEGMENT_64) {
				const fileoff = Number(buf.readBigUInt64LE(cmdOffset + 40))
				const filesize = Number(buf.readBigUInt64LE(cmdOffset + 48))
				if (fileoff > 0 && filesize > 0 && fileoff < firstSegOff) {
					firstSegOff = fileoff
				}
			}
			cmdOffset += cmdSize
		}

		const availableSpace = firstSegOff - usedHeaderSpace
		if (availableSpace < newCmdSize) {
			throw new Error(
				`Not enough header space for new Mach-O load command ` +
					`(${String(availableSpace)} bytes available, need ${String(newCmdSize)})`,
			)
		}

		// --- Build new LC_SEGMENT_64 command ---
		const blobSize = statSync(this.#options.blob).size
		const pageSize = 16384 // macOS uses 16K pages on ARM64
		const dataFileOffset = this.#align(Math.max(highestFileEnd, buf.length), pageSize)
		const alignedBlobSize = this.#align(blobSize, pageSize)
		const dataVmAddr = this.#alignBig(highestVmEnd, BigInt(pageSize))

		const cmd = Buffer.alloc(newCmdSize)

		// LC_SEGMENT_64 header (72 bytes)
		cmd.writeUInt32LE(MACHO_LC_SEGMENT_64, 0) // cmd
		cmd.writeUInt32LE(newCmdSize, 4) // cmdsize
		cmd.write(segmentName, 8, 16, 'ascii') // segname[16]
		cmd.writeBigUInt64LE(dataVmAddr, 24) // vmaddr
		cmd.writeBigUInt64LE(BigInt(alignedBlobSize), 32) // vmsize
		cmd.writeBigUInt64LE(BigInt(dataFileOffset), 40) // fileoff
		cmd.writeBigUInt64LE(BigInt(alignedBlobSize), 48) // filesize
		cmd.writeUInt32LE(1, 56) // maxprot: VM_PROT_READ
		cmd.writeUInt32LE(1, 60) // initprot: VM_PROT_READ
		cmd.writeUInt32LE(1, 64) // nsects
		cmd.writeUInt32LE(0, 68) // flags

		// Section header (80 bytes at offset 72)
		const sectOff = 72
		cmd.write(sectionName, sectOff, 16, 'ascii') // sectname[16]
		cmd.write(segmentName, sectOff + 16, 16, 'ascii') // segname[16]
		cmd.writeBigUInt64LE(dataVmAddr, sectOff + 32) // addr
		cmd.writeBigUInt64LE(BigInt(blobSize), sectOff + 40) // size
		cmd.writeUInt32LE(dataFileOffset, sectOff + 48) // offset
		cmd.writeUInt32LE(0, sectOff + 52) // align (2^0 = 1)
		cmd.writeUInt32LE(0, sectOff + 56) // reloff
		cmd.writeUInt32LE(0, sectOff + 60) // nreloc
		cmd.writeUInt32LE(0, sectOff + 64) // flags
		cmd.writeUInt32LE(0, sectOff + 68) // reserved1
		cmd.writeUInt32LE(0, sectOff + 72) // reserved2
		cmd.writeUInt32LE(0, sectOff + 76) // reserved3

		// --- Write load command into header space ---
		const newCmdOffset = headerSize + sizeofcmds
		cmd.copy(buf, newCmdOffset)

		// Update Mach-O header
		buf.writeUInt32LE(ncmds + 1, 16) // ncmds
		buf.writeUInt32LE(sizeofcmds + newCmdSize, 20) // sizeofcmds

		// Write modified header region back
		writeFileSync(exePath, buf)

		// --- Append blob data at the aligned offset ---
		const currentSize = statSync(exePath).size
		if (dataFileOffset > currentSize) {
			appendFileSync(exePath, Buffer.alloc(dataFileOffset - currentSize))
		}

		this.#appendFile(exePath, this.#options.blob)

		// Pad to page alignment
		const totalWritten = statSync(exePath).size
		const targetEnd = dataFileOffset + alignedBlobSize
		if (totalWritten < targetEnd) {
			appendFileSync(exePath, Buffer.alloc(targetEnd - totalWritten))
		}
	}

	// =========================================================================
	// Binary I/O Helpers
	// =========================================================================

	#readU16(fd: number, offset: number): number {
		const b = Buffer.alloc(2)
		readSync(fd, b, 0, 2, offset)
		return b.readUInt16LE(0)
	}

	#readU32(fd: number, offset: number): number {
		const b = Buffer.alloc(4)
		readSync(fd, b, 0, 4, offset)
		return b.readUInt32LE(0)
	}

	#readU64(fd: number, offset: number): bigint {
		const b = Buffer.alloc(8)
		readSync(fd, b, 0, 8, offset)
		return b.readBigUInt64LE(0)
	}

	#writeU16(fd: number, offset: number, value: number): void {
		const b = Buffer.alloc(2)
		b.writeUInt16LE(value, 0)
		writeSync(fd, b, 0, 2, offset)
	}

	#writeU32(fd: number, offset: number, value: number): void {
		const b = Buffer.alloc(4)
		b.writeUInt32LE(value >>> 0, 0)
		writeSync(fd, b, 0, 4, offset)
	}

	#writeU64(fd: number, offset: number, value: bigint): void {
		const b = Buffer.alloc(8)
		b.writeBigUInt64LE(value, 0)
		writeSync(fd, b, 0, 8, offset)
	}

	#align(value: number, alignment: number): number {
		const remainder = value % alignment
		return remainder === 0 ? value : value + (alignment - remainder)
	}

	#alignBig(value: bigint, alignment: bigint): bigint {
		const remainder = value % alignment
		return remainder === 0n ? value : value + (alignment - remainder)
	}

	/** Append sourceFile to targetFile by streaming in 4 MB chunks */
	#appendFile(targetPath: string, sourcePath: string): void {
		const chunkSize = 4 * 1024 * 1024
		const srcFd = openSync(sourcePath, 'r')
		try {
			const srcSize = statSync(sourcePath).size
			const chunk = Buffer.alloc(Math.min(chunkSize, srcSize))
			let offset = 0
			while (offset < srcSize) {
				const toRead = Math.min(chunkSize, srcSize - offset)
				const bytesRead = readSync(srcFd, chunk, 0, toRead, offset)
				if (bytesRead === 0) break
				appendFileSync(targetPath, chunk.subarray(0, bytesRead))
				offset += bytesRead
			}
		} finally {
			closeSync(srcFd)
		}
	}

	// Strip trailing null characters from a string (used for binary name fields)
	#stripTrailingNulls(value: string): string {
		const idx = value.indexOf(String.fromCharCode(0))
		return idx === -1 ? value : value.slice(0, idx)
	}
}
