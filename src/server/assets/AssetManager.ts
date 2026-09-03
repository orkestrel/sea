import type {
	AssetInput,
	AssetInterface,
	AssetManagerEventMap,
	AssetManagerInterface,
	AssetManagerOptions,
} from '../types.js'
import type { EmitterInterface } from '@orkestrel/emitter'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { getAssetKeys, getRawAsset, isSea } from 'node:sea'
import { Emitter } from '@orkestrel/emitter'
import { isArrayBuffer } from '@orkestrel/contract'
import { Asset } from './Asset.js'

/**
 * Collects named assets from a SEA blob or from disk and serves them by key.
 *
 * @remarks
 * Construction registers every asset embedded in the running SEA blob, so an
 * executable built by this package reaches its assets without touching the
 * filesystem. Outside SEA mode that step registers nothing, and `load()` reads
 * the paths `options.assets` configures instead.
 *
 * @param options - Asset manager options: the project root, the key→path mapping
 * `load()` reads, and the event hooks
 *
 * @example
 * ```ts
 * const manager = new AssetManager({
 *     root: process.cwd(),
 *     assets: { 'client.html.br': 'dist/client/client.html.br' },
 * })
 * manager.load()
 * manager.asset('client.html.br')
 * manager.destroy()
 * ```
 */
export class AssetManager implements AssetManagerInterface {
	readonly #emitter: Emitter<AssetManagerEventMap>
	#assets = new Map<string, AssetInterface>()
	readonly #root: string
	readonly #paths: Readonly<Record<string, string>>

	constructor(options?: AssetManagerOptions) {
		this.#root = options?.root ?? process.cwd()
		this.#paths = options?.assets ?? {}
		this.#emitter = new Emitter({
			...(options?.on === undefined ? {} : { on: options.on }),
			...(options?.error === undefined ? {} : { error: options.error }),
		})
		this.#loadSEA()
	}

	get emitter(): EmitterInterface<AssetManagerEventMap> {
		return this.#emitter
	}

	get count(): number {
		return this.#assets.size
	}

	asset(key: string): AssetInterface | undefined {
		return this.#assets.get(key)
	}

	assets(): readonly AssetInterface[] {
		return [...this.#assets.values()]
	}

	keys(): readonly string[] {
		return [...this.#assets.keys()]
	}

	register(input: AssetInput | readonly AssetInput[]): void {
		const items = Array.isArray(input) ? input : [input]
		for (const item of items) {
			const asset: AssetInterface = new Asset(item)
			this.#add(asset)
			this.#emitter.emit('register', asset)
		}
	}

	load(): void {
		if (isSea()) return

		const registered: string[] = []
		for (const [key, path] of Object.entries(this.#paths)) {
			const resolved = resolve(this.#root, path)
			if (!existsSync(resolved)) {
				this.#emitter.emit('error', new Error(`Asset not found: ${path}`))
				continue
			}
			try {
				const buffer = readFileSync(resolved)
				const bufferData = buffer.buffer
				if (!isArrayBuffer(bufferData)) {
					throw new Error(`Failed to read asset: ${path}`)
				}
				const content = bufferData.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
				this.register({ key, content })
				registered.push(key)
			} catch (thrown: unknown) {
				this.#emitter.emit('error', thrown)
			}
		}

		if (registered.length > 0) {
			this.#emitter.emit('load', registered)
		}
	}

	clear(): void {
		this.#assets.clear()
		this.#emitter.emit('clear')
	}

	destroy(): void {
		this.clear()
		this.#emitter.destroy()
	}

	// === Private

	#add(asset: AssetInterface): void {
		this.#assets.set(asset.key, asset)
	}

	#loadSEA(): void {
		if (isSea()) {
			const assetKeys: readonly string[] = getAssetKeys()
			const registered: string[] = []
			for (const key of assetKeys) {
				const content: ArrayBuffer = getRawAsset(key)
				this.#add(new Asset({ key, content }))
				registered.push(key)
			}
			if (registered.length > 0) {
				this.#emitter.emit('load', registered)
			}
		}
	}
}
