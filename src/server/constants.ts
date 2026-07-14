import type { SEACompressionMode, SEAEntryFormat, SEAPlatform } from './types.js'

/** SEA sentinel fuse value embedded in the Node.js binary */
export const SEA_SENTINEL_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'

/** Resource name for the SEA blob in the executable */
export const SEA_BLOB_RESOURCE = 'NODE_SEA_BLOB'

/** Default Brotli compression quality level (maximum) */
export const DEFAULT_SEA_COMPRESSION_QUALITY = 11

/** Windows PE subsystem value: GUI application (no terminal window) */
export const WINDOWS_SUBSYSTEM_GUI = 2

/** Windows PE subsystem value: console application */
export const WINDOWS_SUBSYSTEM_CONSOLE = 3

/** File extension indicating Brotli compression */
export const BROTLI_EXTENSION = '.br'

/** File extensions that should NOT be Brotli-compressed */
export const SKIP_EXTENSIONS = new Set([
	'.br',
	'.gz',
	'.zst',
	'.png',
	'.jpg',
	'.jpeg',
	'.gif',
	'.webp',
	'.avif',
	'.ico',
	'.woff',
	'.woff2',
	'.ttf',
	'.otf',
	'.eot',
	'.mp3',
	'.mp4',
	'.webm',
	'.ogg',
	'.zip',
	'.tar',
])

/** Default SEA entry point module format when none is specified */
export const DEFAULT_ENTRY_FORMAT: SEAEntryFormat = 'cjs'

/** Asset key for the raw (uncompressed) client HTML entry */
export const CLIENT_ASSET_KEY_RAW = 'client.html'

/** Asset key for the Brotli-compressed client HTML entry */
export const CLIENT_ASSET_KEY_BR = 'client.html.br'

// === Binary Format Magic

/** DOS MZ header magic (first 2 bytes of a PE file) */
export const PE_MAGIC = 0x5a4d

/** PE signature: "PE\0\0" as a 32-bit value */
export const PE_SIGNATURE = 0x00004550

/** PE32 optional header magic */
export const PE32_MAGIC = 0x10b

/** PE32+ (64-bit) optional header magic */
export const PE32_PLUS_MAGIC = 0x20b

/** ELF magic: 0x7F 'E' 'L' 'F' as a 32-bit big-endian value */
export const ELF_MAGIC = 0x7f454c46

/** ELF 64-bit class identifier */
export const ELF_CLASS_64 = 2

/** ELF little-endian data encoding */
export const ELF_DATA_LSB = 1

/** ELF program header type: note segment */
export const ELF_PT_NOTE = 4

/** Mach-O 64-bit magic (little-endian) */
export const MACHO_MAGIC_64 = 0xfeedfacf

/** Mach-O LC_SEGMENT_64 load command */
export const MACHO_LC_SEGMENT_64 = 0x19

// === PE Resource Directory

/** PE resource type: RT_RCDATA (raw data) */
export const PE_RT_RCDATA = 10

/** Size of IMAGE_RESOURCE_DIRECTORY in bytes */
export const PE_RESOURCE_DIR_SIZE = 16

/** Size of IMAGE_RESOURCE_DIRECTORY_ENTRY in bytes */
export const PE_RESOURCE_ENTRY_SIZE = 8

/** Size of IMAGE_RESOURCE_DATA_ENTRY in bytes */
export const PE_RESOURCE_DATA_ENTRY_SIZE = 16

/** PE section header size in bytes */
export const PE_SECTION_HEADER_SIZE = 40

/** High bit mask for resource directory entry offset (indicates subdirectory) */
export const PE_RESOURCE_SUBDIR_FLAG = 0x80000000

/** High bit mask for resource name entry (indicates named vs integer ID) */
export const PE_RESOURCE_NAME_FLAG = 0x80000000

// === PE Section Characteristics

/** Section contains initialized data */
export const PE_SCN_INITIALIZED_DATA = 0x00000040

/** Section is readable */
export const PE_SCN_MEM_READ = 0x40000000

// === Platform

/** Platform-specific SEA build configurations */
export const SEA_PLATFORMS: Readonly<Record<string, SEAPlatform>> = Object.freeze({
	win32: Object.freeze({
		executable: 'node.exe',
		remove: undefined,
		sign: undefined,
		verify: undefined,
	}),
	darwin: Object.freeze({
		executable: 'node',
		remove: Object.freeze(['codesign', '--remove-signature']),
		sign: Object.freeze(['codesign', '--sign', '-']),
		verify: Object.freeze(['codesign', '--verify', '--strict']),
	}),
	linux: Object.freeze({
		executable: 'node',
		remove: undefined,
		sign: undefined,
		verify: undefined,
	}),
})

// === Compression

/** Maps a {@link SEACompressionMode} to its numeric Brotli mode value */
export const SEA_COMPRESSION_MODE_VALUES: Readonly<Record<SEACompressionMode, number>> =
	Object.freeze({
		generic: 0,
		text: 1,
		font: 2,
	})
