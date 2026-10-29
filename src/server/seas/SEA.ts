import type {
	SEACompressionManifest,
	SEAEventMap,
	SEAInterface,
	SEAOptions,
	SEAResult,
	SEAStatus,
} from '../types.js'
import type { EmitterInterface } from '@orkestrel/emitter'
import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { Emitter } from '@orkestrel/emitter'
import {
	buildBlobConfig,
	buildSignCommand,
	ensureContained,
	ensureExists,
	ensureSafeKey,
	ensureSafeName,
	executeShell,
	resolvePlatform,
} from '../helpers.js'
import { SEAError } from '../errors.js'
import { SEAConstruction } from './SEAConstruction.js'

/**
 * Runs a Node.js single executable application build to completion.
 *
 * @remarks
 * `execute` compresses the configured directories, generates the SEA blob, copies
 * the host Node binary, injects the blob with an {@link Injector}, signs the
 * result where the platform supports it, and moves the finished executable into
 * place atomically. Each stage reports on `emitter`, and every failure throws a
 * coded `SEAError` after an `error` event carrying it.
 *
 * @param options - SEA build options: the output name, the entry point, the output
 * directory, and the optional assets, compression, Windows, and blob settings
 *
 * @example
 * ```ts
 * const sea = new SEA({
 *     name: 'myapp',
 *     entry: { path: 'dist/server/serve.cjs' },
 *     output: 'dist/sea',
 * })
 * const result = await sea.execute()
 * sea.destroy()
 * ```
 */
export class SEA implements SEAInterface {
	#status: SEAStatus = 'idle'
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
		if (this.#emitter.destroyed) {
			throw new SEAError('STATE', 'SEA is destroyed')
		}
		if (this.#status === 'active') {
			throw new SEAError('STATE', 'SEA build already in progress')
		}

		const platform = resolvePlatform()
		if (platform === undefined) {
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
			const construction = new SEAConstruction(this.#options, this.#emitter, () => this.#check())
			const compression = construction.compress(root)

			this.#check()
			const blob = this.#buildBlob(root, compression)

			this.#check()
			const assembled = construction.assemble(root, blob)
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
			ensureContained(base, path)
		}

		for (const path of this.#options.compression?.paths ?? []) {
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
			// never executed here — buildSignCommand is a pure argv builder.
			buildSignCommand(sign, 'placeholder')

			if (sign.file !== undefined) {
				ensureExists(resolve(base, sign.file), 'Certificate file not found', 'SIGN')
			}
		}
	}

	#buildBlob(root: string, compression: SEACompressionManifest | undefined): string {
		const entry = resolve(root, this.#options.entry.path)
		ensureExists(entry, `Entry not found: ${this.#options.entry.path}`, 'ENTRY')

		const output = resolve(root, this.#options.output)
		mkdirSync(output, { recursive: true })

		const configPath = join(output, 'sea-config.json')
		const blob = join(output, 'sea-prep.blob')
		const config = buildBlobConfig(
			{
				path: entry,
				...(this.#options.entry.format === undefined ? {} : { format: this.#options.entry.format }),
			},
			blob,
			this.#resolveAssets(root, compression),
			this.#options.blob,
		)

		writeFileSync(configPath, JSON.stringify(config, null, 2))
		executeShell([process.execPath, '--experimental-sea-config', configPath], {
			cwd: output,
			...(this.#options.signal === undefined ? {} : { signal: this.#options.signal }),
			...(this.#options.timeout === undefined ? {} : { timeout: this.#options.timeout }),
		})

		if (!existsSync(blob)) {
			throw new SEAError('BLOB', 'SEA blob generation failed — blob not found', { blob })
		}

		this.#emitter.emit('blob', blob)
		return blob
	}

	#resolveAssets(
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
