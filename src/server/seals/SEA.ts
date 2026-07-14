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
import { chmodSync, copyFileSync, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { Emitter } from '@orkestrel/emitter'
import {
	SEA_BLOB_RESOURCE,
	SEA_SENTINEL_FUSE,
	WINDOWS_SUBSYSTEM_CONSOLE,
	WINDOWS_SUBSYSTEM_GUI,
} from '../constants.js'
import {
	compressDirectory,
	ensureExists,
	isPEExecutable,
	isPlatformSupported,
	patchPESubsystem,
	platformConfig,
	runShell,
	stripPESignature,
} from '../helpers.js'
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
			throw new Error('SEA is destroyed')
		}
		if (this.#status === 'active') {
			throw new Error('SEA build already in progress')
		}

		const platform = platformConfig()
		if (platform === undefined || !isPlatformSupported()) {
			const error = new Error(`Unsupported platform: ${process.platform}`)
			this.#status = 'error'
			this.#emitter.emit('error', error)
			throw error
		}

		this.#status = 'active'
		const start = Date.now()
		const root = this.#options.root ?? process.cwd()

		try {
			const compression = this.#compress(root)
			const blob = this.#blob(root)
			const executable = this.#assemble(root, blob)
			const size = statSync(executable).size
			const duration = Date.now() - start

			const result: SEAResult = {
				executable,
				platform: process.platform,
				size,
				duration,
				compression,
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
		const entry = resolve(root, this.#options.entry)
		ensureExists(entry, `Entry not found: ${this.#options.entry}`)

		const output = resolve(root, this.#options.output)
		mkdirSync(output, { recursive: true })

		const configPath = join(output, 'sea-config.json')
		const blob = join(output, 'sea-prep.blob')
		const config = {
			main: entry,
			output: blob,
			disableExperimentalSEAWarning: true,
			useSnapshot: false,
			useCodeCache: true,
			...(this.#options.assets !== undefined ? { assets: this.#assets(root) } : {}),
		}

		writeFileSync(configPath, JSON.stringify(config, null, 2))
		runShell([process.execPath, '--experimental-sea-config', configPath], { cwd: output })

		if (!existsSync(blob)) {
			throw new Error('SEA blob generation failed — blob not found')
		}

		this.#emitter.emit('blob', blob)
		return blob
	}

	#assemble(root: string, blob: string): string {
		const platform = platformConfig()
		if (platform === undefined) {
			throw new Error(`Unsupported platform: ${process.platform}`)
		}

		const output = resolve(root, this.#options.output)
		const name = process.platform === 'win32' ? `${this.#options.name}.exe` : this.#options.name
		const executable = join(output, name)

		copyFileSync(process.execPath, executable)
		if (process.platform !== 'win32') {
			chmodSync(executable, 0o755)
		}

		if (platform.remove !== undefined) {
			try {
				if (process.platform === 'win32') {
					stripPESignature(executable)
				} else {
					runShell([...platform.remove, executable])
				}
			} catch {}
		}

		const injector = new Injector({
			executable,
			resource: SEA_BLOB_RESOURCE,
			blob,
			fuse: SEA_SENTINEL_FUSE,
			macho: { segment: 'NODE_SEA' },
		})
		injector.inject()

		if (platform.sign !== undefined) {
			try {
				runShell([...platform.sign, executable])
			} catch {}
		}

		if (process.platform === 'win32' && isPEExecutable(executable)) {
			const subsystem =
				this.#options.windows?.subsystem === 'gui'
					? WINDOWS_SUBSYSTEM_GUI
					: WINDOWS_SUBSYSTEM_CONSOLE
			patchPESubsystem(executable, subsystem)
		}

		this.#emitter.emit('assemble', executable)
		return executable
	}

	#assets(root: string): Readonly<Record<string, string>> {
		const assets: Record<string, string> = {}
		for (const [name, path] of Object.entries(this.#options.assets ?? {})) {
			assets[name] = resolve(root, path)
		}
		return assets
	}
}
