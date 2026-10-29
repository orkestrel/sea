import type { Emitter } from '@orkestrel/emitter'
import type { SEACompressionManifest, SEAEventMap, SEAOptions } from '../types.js'
import { chmodSync, copyFileSync, existsSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { isError } from '@orkestrel/contract'
import {
	SEA_BLOB_RESOURCE,
	SEA_SENTINEL_FUSE,
	WINDOWS_SUBSYSTEM_CONSOLE,
	WINDOWS_SUBSYSTEM_GUI,
} from '../constants.js'
import {
	buildSignCommand,
	compressDirectory,
	ensureContained,
	executeShell,
	finalizeExecutable,
	isCompressible,
	isPEExecutable,
	patchPESubsystem,
	resolvePlatform,
	stripPESignature,
	walkDirectory,
} from '../helpers.js'
import { SEAError } from '../errors.js'
import { Injector } from '../injectors/Injector.js'

/** Owns the progress and assembly state of one SEA build. */
export class SEAConstruction {
	readonly #options: SEAOptions
	readonly #emitter: Emitter<SEAEventMap>
	readonly #check: () => void
	#total = 0
	#original = 0
	#compressed = 0
	#current = 0
	#signed = false
	#stripped = false
	#terminal: boolean | undefined

	constructor(options: SEAOptions, emitter: Emitter<SEAEventMap>, check: () => void) {
		this.#options = options
		this.#emitter = emitter
		this.#check = check
	}

	compress(root: string): SEACompressionManifest | undefined {
		const compression = this.#options.compression
		if (compression === undefined || compression.paths.length === 0) {
			this.#emitter.emit('compress', undefined)
			return undefined
		}

		const directories: string[] = []
		for (const path of compression.paths) {
			const candidate = resolve(root, path)
			if (!existsSync(candidate)) continue
			this.#check()
			const directory = ensureContained(root, path)
			directories.push(directory)
			this.#total += walkDirectory(directory).filter(isCompressible).length
		}

		const assets: Array<SEACompressionManifest['assets'][number]> = []

		for (const directory of directories) {
			this.#check()
			const manifest = compressDirectory(directory, compression, (result) => {
				this.#current += 1
				this.#emitter.emit('progress', {
					path: result.input,
					current: this.#current,
					total: this.#total,
				})
			})
			assets.push(...manifest.assets)
			this.#original += manifest.total.original
			this.#compressed += manifest.total.compressed
		}

		const manifest: SEACompressionManifest = {
			assets,
			total: {
				original: this.#original,
				compressed: this.#compressed,
				ratio: this.#original > 0 ? this.#compressed / this.#original : 0,
			},
		}

		this.#emitter.emit('compress', manifest)
		return manifest
	}

	// Assembles through strip, inject, sign, and verify in a sibling temporary file.
	// A failure removes that temporary file and preserves the prior output.
	assemble(
		root: string,
		blob: string,
	): { executable: string; signed: boolean; stripped: boolean; terminal?: boolean } {
		const platform = resolvePlatform()
		if (platform === undefined) {
			throw new SEAError('PLATFORM', `Unsupported platform: ${process.platform}`, {
				platform: process.platform,
			})
		}

		const output = resolve(root, this.#options.output)
		const ext = process.platform === 'win32' ? '.exe' : ''
		const name = process.platform === 'win32' ? `${this.#options.name}.exe` : this.#options.name
		const finalOutput = join(output, name)
		const temp = join(output, `.${this.#options.name}-${randomUUID()}.tmp${ext}`)
		const shell = {
			...(this.#options.signal === undefined ? {} : { signal: this.#options.signal }),
			...(this.#options.timeout === undefined ? {} : { timeout: this.#options.timeout }),
		}

		try {
			if (process.platform === 'darwin') {
				this.#check()
				copyFileSync(process.execPath, temp)
				chmodSync(temp, 0o755)

				if (platform.remove !== undefined) {
					this.#check()
					try {
						executeShell([...platform.remove, temp], shell)
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to strip existing signature', {
							cause: isError(thrown) ? thrown.message : String(thrown),
						})
					}
					this.#stripped = true
				}

				this.#check()
				const injector = new Injector({
					executable: temp,
					resource: SEA_BLOB_RESOURCE,
					blob,
					fuse: SEA_SENTINEL_FUSE,
					macho: { segment: 'NODE_SEA' },
				})
				injector.inject()

				if (platform.sign !== undefined) {
					this.#check()
					try {
						executeShell([...platform.sign, temp], shell)
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to sign executable', {
							cause: isError(thrown) ? thrown.message : String(thrown),
						})
					}

					if (platform.verify !== undefined) {
						this.#check()
						try {
							executeShell([...platform.verify, temp], shell)
						} catch (thrown: unknown) {
							throw new SEAError('SIGN', 'Signature verification failed', {
								cause: isError(thrown) ? thrown.message : String(thrown),
							})
						}
					}

					this.#signed = true
				}
			} else if (process.platform === 'win32') {
				this.#check()
				copyFileSync(process.execPath, temp)

				stripPESignature(temp)
				this.#stripped = true

				if (isPEExecutable(temp)) {
					this.#terminal = this.#options.windows?.terminal !== false
					const value = this.#terminal ? WINDOWS_SUBSYSTEM_CONSOLE : WINDOWS_SUBSYSTEM_GUI
					patchPESubsystem(temp, value)
				}

				this.#check()
				const injector = new Injector({
					executable: temp,
					resource: SEA_BLOB_RESOURCE,
					blob,
					fuse: SEA_SENTINEL_FUSE,
				})
				injector.inject()

				const sign = this.#options.windows?.sign
				if (sign !== undefined) {
					this.#check()
					// Resolve the certificate file against the SAME base #validate
					// checked existence against — buildSignCommand's argv is passed
					// through executeShell without a cwd, so a relative sign.file would
					// otherwise resolve against process.cwd(), a different file.
					const signInput =
						sign.file !== undefined ? { ...sign, file: resolve(root, sign.file) } : sign
					const signArgs = buildSignCommand(signInput, temp)
					try {
						executeShell(signArgs, shell)
					} catch {
						throw new SEAError('SIGN', 'Windows signing failed', { executable: temp })
					}
					this.#signed = true

					if (platform.verify !== undefined) {
						this.#check()
						try {
							executeShell([...platform.verify, temp], shell)
						} catch {
							throw new SEAError('SIGN', 'Signature verification failed', { executable: temp })
						}
					}
				}
			} else {
				this.#check()
				copyFileSync(process.execPath, temp)
				chmodSync(temp, 0o755)

				this.#check()
				const injector = new Injector({
					executable: temp,
					resource: SEA_BLOB_RESOURCE,
					blob,
					fuse: SEA_SENTINEL_FUSE,
				})
				injector.inject()
			}

			finalizeExecutable(temp, finalOutput)
		} catch (thrown: unknown) {
			rmSync(temp, { force: true })
			throw thrown
		}

		this.#emitter.emit('assemble', finalOutput)
		return {
			executable: finalOutput,
			signed: this.#signed,
			stripped: this.#stripped,
			...(this.#terminal === undefined ? {} : { terminal: this.#terminal }),
		}
	}
}
