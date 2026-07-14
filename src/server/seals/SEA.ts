/**
 * SEA
 *
 * Build orchestrator for Node.js Single Executable Applications.
 * Compresses assets, generates the SEA blob, copies the Node binary,
 * injects the blob, and handles platform-specific signing.
 */

import type {
	SEACompressionManifest,
	SEAEventMap,
	SEAInterface,
	SEAOptions,
	SEAResult,
	SEAStatus,
	WindowsSubsystem,
} from '../types.js'
import type { EmitterInterface } from '@orkestrel/emitter'
import {
	chmodSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { Emitter } from '@orkestrel/emitter'
import {
	SEA_BLOB_RESOURCE,
	SEA_SENTINEL_FUSE,
	WINDOWS_SUBSYSTEM_CONSOLE,
	WINDOWS_SUBSYSTEM_GUI,
} from '../constants.js'
import {
	compressDirectory,
	createBlobConfig,
	ensureContained,
	ensureExists,
	ensureSafeKey,
	ensureSafeName,
	finalizeExecutable,
	isPEExecutable,
	isPlatformSupported,
	patchPESubsystem,
	platformConfig,
	runShell,
	stripPESignature,
} from '../helpers.js'
import { SEAError } from '../errors.js'
import { Injector } from '../injectors/Injector.js'

// === SEA

export class SEA implements SEAInterface {
	#status: SEAStatus = 'idle'
	#destroyed = false
	readonly #options: SEAOptions
	readonly #emitter: Emitter<SEAEventMap>

	constructor(options: SEAOptions) {
		this.#options = options
		this.#emitter = new Emitter({ on: options.on, error: options.error })
	}

	get emitter(): EmitterInterface<SEAEventMap> {
		return this.#emitter
	}

	get status(): SEAStatus {
		return this.#status
	}

	async execute(): Promise<SEAResult> {
		if (this.#destroyed) {
			throw new SEAError('STATE', 'SEA is destroyed')
		}
		if (this.#status === 'active') {
			throw new SEAError('STATE', 'SEA build already in progress')
		}

		const platform = platformConfig()
		if (platform === undefined || !isPlatformSupported()) {
			const error = new SEAError('PLATFORM', `Unsupported platform: ${process.platform}`, {
				platform: process.platform,
			})
			this.#status = 'error'
			this.#emitter.emit('error', error)
			throw error
		}

		this.#status = 'active'
		const start = Date.now()
		const root = this.#options.root ?? process.cwd()

		try {
			this.#check()
			this.#validate(root)

			this.#check()
			const compression = this.#compress(root)

			this.#check()
			const blob = this.#blob(root)

			this.#check()
			const assembled = this.#assemble(root, blob)
			const size = statSync(assembled.executable).size
			const duration = Date.now() - start

			const result: SEAResult = {
				executable: assembled.executable,
				platform: process.platform,
				size,
				duration,
				compression,
				signed: assembled.signed,
				stripped: assembled.stripped,
				subsystem: assembled.subsystem,
			}

			this.#status = 'done'
			this.#emitter.emit('complete', result)
			return result
		} catch (thrown: unknown) {
			this.#status = 'error'
			this.#emitter.emit('error', thrown)
			throw thrown
		}
	}

	destroy(): void {
		if (this.#destroyed) return
		this.#destroyed = true
		this.#emitter.destroy()
	}

	// Throws SEAError('ABORT', ...) when the caller's signal has fired.
	#check(): void {
		if (this.#options.signal?.aborted === true) {
			throw new SEAError('ABORT', 'SEA build aborted')
		}
	}

	// Validates every asset key/path and compression path before any work runs.
	#validate(root: string): void {
		const base = resolve(root)

		ensureSafeName(this.#options.name)

		for (const [key, path] of Object.entries(this.#options.assets ?? {})) {
			ensureSafeKey(key)
			ensureSafeKey(path)
			ensureContained(base, path)
		}

		for (const path of this.#options.compression?.paths ?? []) {
			ensureSafeKey(path)
			ensureContained(base, path)
		}
	}

	#compress(root: string): SEACompressionManifest | undefined {
		const compression = this.#options.compression
		if (compression === undefined || compression.paths.length === 0) {
			this.#emitter.emit('compress', undefined)
			return undefined
		}

		const assets: SEACompressionManifest['assets'][number][] = []
		let original = 0
		let compressed = 0

		for (const path of compression.paths) {
			this.#check()
			const directory = resolve(root, path)
			if (!existsSync(directory)) {
				continue
			}

			const manifest = compressDirectory(directory, compression)
			assets.push(...manifest.assets)
			original += manifest.total.original
			compressed += manifest.total.compressed
		}

		const manifest: SEACompressionManifest = {
			timestamp: new Date().toISOString(),
			assets,
			total: {
				original,
				compressed,
				ratio: original > 0 ? compressed / original : 0,
			},
		}

		this.#emitter.emit('compress', manifest)
		return manifest
	}

	#blob(root: string): string {
		const entry = resolve(root, this.#options.entry.path)
		ensureExists(entry, `Entry not found: ${this.#options.entry.path}`, 'ENTRY')

		const output = resolve(root, this.#options.output)
		mkdirSync(output, { recursive: true })

		const configPath = join(output, 'sea-config.json')
		const blob = join(output, 'sea-prep.blob')
		const config = createBlobConfig(
			{ path: entry, format: this.#options.entry.format },
			blob,
			this.#assets(root),
			this.#options.blob,
		)

		writeFileSync(configPath, JSON.stringify(config, null, 2))
		runShell([process.execPath, '--experimental-sea-config', configPath], {
			cwd: output,
			signal: this.#options.signal,
		})

		if (!existsSync(blob)) {
			throw new SEAError('BLOB', 'SEA blob generation failed — blob not found', { blob })
		}

		this.#emitter.emit('blob', blob)
		return blob
	}

	// Assembles the final executable in a same-directory temp file, mutating it
	// through strip -> inject -> sign -> verify, then atomically finalizing it
	// into place. Any failure removes the temp file and leaves the prior output
	// (if any) untouched.
	#assemble(
		root: string,
		blob: string,
	): { executable: string; signed: boolean; stripped: boolean; subsystem?: WindowsSubsystem } {
		const platform = platformConfig()
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

		let signed = false
		let stripped = false
		let subsystem: WindowsSubsystem | undefined

		try {
			if (process.platform === 'darwin') {
				this.#check()
				copyFileSync(process.execPath, temp)
				chmodSync(temp, 0o755)

				if (platform.remove !== undefined) {
					this.#check()
					try {
						runShell([...platform.remove, temp], { signal: this.#options.signal })
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to strip existing signature', {
							cause: thrown instanceof Error ? thrown.message : String(thrown),
						})
					}
					stripped = true
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
						runShell([...platform.sign, temp], { signal: this.#options.signal })
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to sign executable', {
							cause: thrown instanceof Error ? thrown.message : String(thrown),
						})
					}

					if (platform.verify !== undefined) {
						this.#check()
						try {
							runShell([...platform.verify, temp], { signal: this.#options.signal })
						} catch (thrown: unknown) {
							throw new SEAError('SIGN', 'Signature verification failed', {
								cause: thrown instanceof Error ? thrown.message : String(thrown),
							})
						}
					}

					signed = true
				}
			} else if (process.platform === 'win32') {
				this.#check()
				copyFileSync(process.execPath, temp)

				stripPESignature(temp)
				stripped = true

				if (isPEExecutable(temp)) {
					subsystem = this.#options.windows?.subsystem === 'gui' ? 'gui' : 'console'
					const value = subsystem === 'gui' ? WINDOWS_SUBSYSTEM_GUI : WINDOWS_SUBSYSTEM_CONSOLE
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

				if (platform.sign !== undefined) {
					this.#check()
					try {
						runShell([...platform.sign, temp], { signal: this.#options.signal })
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to sign executable', {
							cause: thrown instanceof Error ? thrown.message : String(thrown),
						})
					}
					signed = true

					if (platform.verify !== undefined) {
						this.#check()
						try {
							runShell([...platform.verify, temp], { signal: this.#options.signal })
						} catch (thrown: unknown) {
							throw new SEAError('SIGN', 'Signature verification failed', {
								cause: thrown instanceof Error ? thrown.message : String(thrown),
							})
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
		return { executable: finalOutput, signed, stripped, subsystem }
	}

	#assets(root: string): Readonly<Record<string, string>> {
		const assets: Record<string, string> = {}
		for (const [name, path] of Object.entries(this.#options.assets ?? {})) {
			assets[name] = resolve(root, path)
		}
		return assets
	}
}
