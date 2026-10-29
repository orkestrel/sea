import { openSync, readSync, writeSync, closeSync } from 'node:fs'
import { SEAError } from './errors.js'

/** Owns the cursor of one patchSentinelFuse operation. */
export class FusePatcher {
	#offset = 0

	execute(executable: string, fuse: string): void {
		const fd = openSync(executable, 'r+')
		try {
			const needle = Buffer.from(fuse, 'utf-8')
			const chunkSize = 64 * 1024 * 1024 // 64 MB
			const readSize = chunkSize + needle.length
			const buffer = Buffer.alloc(readSize)

			this.#offset = 0
			while (true) {
				const bytesRead = readSync(fd, buffer, 0, readSize, this.#offset)
				if (bytesRead === 0) break

				const chunk = buffer.subarray(0, bytesRead)
				const idx = chunk.indexOf(needle)

				if (idx !== -1) {
					const fuseEnd = this.#offset + idx + needle.length
					const valueBuf = Buffer.alloc(2)
					const valueRead = readSync(fd, valueBuf, 0, 2, fuseEnd)

					if (valueRead < 2) {
						throw new SEAError('FUSE', 'Could not read sentinel fuse value', { executable, fuse })
					}

					const value = valueBuf.toString('utf-8')

					if (value === ':0') {
						writeSync(fd, Buffer.from('1', 'utf-8'), 0, 1, fuseEnd + 1)
						return
					}

					if (value === ':1') {
						return // Already patched
					}

					throw new SEAError('FUSE', `Unexpected sentinel fuse value: ${value}`, {
						executable,
						fuse,
					})
				}

				this.#offset += chunkSize
			}

			throw new SEAError('FUSE', `Sentinel fuse not found in executable: ${fuse}`, {
				executable,
				fuse,
			})
		} finally {
			closeSync(fd)
		}
	}
}
