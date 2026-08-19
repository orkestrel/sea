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
	createSignCommand,
	ensureContained,
	ensureExists,
	ensureSafeKey,
	ensureSafeName,
	finalizeExecutable,
	isCompressible,
	isPEExecutable,
	isPlatformSupported,
	patchPESubsystem,
	platformConfig,
	runShell,
	stripPESignature,
	walkDirectory,
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
		this.#emitter = new Emitter({
			...(options.on === undefined ? {} : { on: options.on }),
			...(options.error === undefined ? {} : { error: options.error }),
		})
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
			const blob = this.#blob(root, compression)

			this.#check()
			const assembled = this.#assemble(root, blob)
			const size = statSync(assembled.executable).size
			const duration = Date.now() - start

			const result: SEAResult = {
				executable: assembled.executable,
				platform: process.platform,
				size,
				duration,
				signed: assembled.signed,
				stripped: assembled.stripped,
				...(compression === undefined ? {} : { compression }),
				...(assembled.terminal === undefined ? {} : { terminal: assembled.terminal }),
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
			// A compression path that does not exist yet is skipped by #compress
			// (existsSync gate below), so validation only enforces containment
			// for paths that actually exist — keep the two stages in agreement.
			if (existsSync(resolve(base, path))) {
				ensureContained(base, path)
			}
		}

		const sign = this.#options.windows?.sign
		if (sign !== undefined) {
			// Trigger the file-XOR-thumbprint and timestamp-scheme validation
			// fail-fast, before any build work runs. The placeholder target is
			// never executed here — createSignCommand is a pure argv builder.
			createSignCommand(sign, 'placeholder')

			if (sign.file !== undefined) {
				ensureExists(resolve(base, sign.file), 'Certificate file not found', 'SIGN')
			}
		}
	}

	#compress(root: string): SEACompressionManifest | undefined {
		const compression = this.#options.compression
		if (compression === undefined || compression.paths.length === 0) {
			this.#emitter.emit('compress', undefined)
			return undefined
		}

		const directories: string[] = []
		let total = 0
		for (const path of compression.paths) {
			const candidate = resolve(root, path)
			if (!existsSync(candidate)) continue
			this.#check()
			const directory = ensureContained(root, path)
			directories.push(directory)
			total += walkDirectory(directory).filter(isCompressible).length
		}

		const assets: Array<SEACompressionManifest['assets'][number]> = []
		let original = 0
		let compressed = 0
		let current = 0

		for (const directory of directories) {
			this.#check()
			const manifest = compressDirectory(directory, compression, (result) => {
				current += 1
				this.#emitter.emit('progress', { path: result.input, current, total })
			})
			assets.push(...manifest.assets)
			original += manifest.total.original
			compressed += manifest.total.compressed
		}

		const manifest: SEACompressionManifest = {
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

	#blob(root: string, compression: SEACompressionManifest | undefined): string {
		const entry = resolve(root, this.#options.entry.path)
		ensureExists(entry, `Entry not found: ${this.#options.entry.path}`, 'ENTRY')

		const output = resolve(root, this.#options.output)
		mkdirSync(output, { recursive: true })

		const configPath = join(output, 'sea-config.json')
		const blob = join(output, 'sea-prep.blob')
		const config = createBlobConfig(
			{
				path: entry,
				...(this.#options.entry.format === undefined ? {} : { format: this.#options.entry.format }),
			},
			blob,
			this.#assets(root, compression),
			this.#options.blob,
		)

		writeFileSync(configPath, JSON.stringify(config, null, 2))
		runShell([process.execPath, '--experimental-sea-config', configPath], {
			cwd: output,
			...(this.#options.signal === undefined ? {} : { signal: this.#options.signal }),
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
	): { executable: string; signed: boolean; stripped: boolean; terminal?: boolean } {
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
		const shell = this.#options.signal === undefined ? {} : { signal: this.#options.signal }

		let signed = false
		let stripped = false
		let terminal: boolean | undefined

		try {
			if (process.platform === 'darwin') {
				this.#check()
				copyFileSync(process.execPath, temp)
				chmodSync(temp, 0o755)

				if (platform.remove !== undefined) {
					this.#check()
					try {
						runShell([...platform.remove, temp], shell)
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
						runShell([...platform.sign, temp], shell)
					} catch (thrown: unknown) {
						throw new SEAError('SIGN', 'Failed to sign executable', {
							cause: thrown instanceof Error ? thrown.message : String(thrown),
						})
					}

					if (platform.verify !== undefined) {
						this.#check()
						try {
							runShell([...platform.verify, temp], shell)
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
					terminal = this.#options.windows?.terminal !== false
					const value = terminal ? WINDOWS_SUBSYSTEM_CONSOLE : WINDOWS_SUBSYSTEM_GUI
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
					// checked existence against — createSignCommand's argv is passed
					// through runShell without a cwd, so a relative sign.file would
					// otherwise resolve against process.cwd(), a different file.
					const signInput =
						sign.file !== undefined ? { ...sign, file: resolve(root, sign.file) } : sign
					const signArgs = createSignCommand(signInput, temp)
					try {
						runShell(signArgs, shell)
					} catch {
						throw new SEAError('SIGN', 'Windows signing failed', { executable: temp })
					}
					signed = true

					if (platform.verify !== undefined) {
						this.#check()
						try {
							runShell([...platform.verify, temp], shell)
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
			signed,
			stripped,
			...(terminal === undefined ? {} : { terminal }),
		}
	}

	#assets(
		root: string,
		compression: SEACompressionManifest | undefined,
	): Readonly<Record<string, string>> {
		const outputs = new Map<string, string>()
		for (const result of compression?.assets ?? []) {
			outputs.set(result.input, result.output)
		}

		const assets: Record<string, string> = {}
		for (const [name, path] of Object.entries(this.#options.assets ?? {})) {
			const input = ensureContained(root, path)
			assets[name] = outputs.get(input) ?? input
		}
		return assets
	}
}
