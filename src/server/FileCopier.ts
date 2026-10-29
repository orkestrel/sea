import { readSync, writeSync } from 'node:fs'
import { SEAError } from './errors.js'

/** Owns the cursor of one copyRange operation. */
export class FileCopier {
	#position = 0
	#remaining = 0

	execute(
		source: number,
		target: number,
		start: number,
		length: number,
		chunk = 4 * 1024 * 1024,
	): void {
		if (length <= 0) return

		const bufferSize = Math.min(chunk, length)
		const buffer = Buffer.alloc(bufferSize)
		this.#position = start
		this.#remaining = length

		while (this.#remaining > 0) {
			const toRead = Math.min(chunk, this.#remaining)
			const bytesRead = readSync(source, buffer, 0, toRead, this.#position)
			if (bytesRead === 0) {
				throw new SEAError('OUTPUT', 'Unexpected end of file while copying byte range', {
					start,
					length,
					position: this.#position,
					remaining: this.#remaining,
				})
			}
			writeSync(target, buffer, 0, bytesRead, null)
			this.#position += bytesRead
			this.#remaining -= bytesRead
		}
	}
}
