import { appendFileSync, openSync, readSync, statSync, closeSync } from 'node:fs'

/** Owns the cursor of one appendFile operation. */
export class FileAppender {
	#offset = 0

	execute(target: string, source: string, chunk = 4 * 1024 * 1024): void {
		const fd = openSync(source, 'r')
		try {
			const size = statSync(source).size
			const buffer = Buffer.alloc(Math.min(chunk, size))
			this.#offset = 0
			while (this.#offset < size) {
				const toRead = Math.min(chunk, size - this.#offset)
				const bytesRead = readSync(fd, buffer, 0, toRead, this.#offset)
				if (bytesRead === 0) break
				appendFileSync(target, buffer.subarray(0, bytesRead))
				this.#offset += bytesRead
			}
		} finally {
			closeSync(fd)
		}
	}
}
