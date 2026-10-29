import type { ExecutableFormat, InjectorInterface, InjectorOptions } from '../types.js'
import { openSync, readSync, closeSync } from 'node:fs'
import { PE_MAGIC, ELF_MAGIC, MACHO_MAGIC_64 } from '../constants.js'
import { SEAError } from '../errors.js'
import { Injection } from './Injection.js'

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
	readonly #options: InjectorOptions
	readonly #format: ExecutableFormat

	constructor(options: InjectorOptions) {
		this.#options = options
		this.#format = this.#detect()
	}

	get format(): ExecutableFormat {
		return this.#format
	}

	inject(): void {
		new Injection(this.#options, this.#format).execute()
	}

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
}
