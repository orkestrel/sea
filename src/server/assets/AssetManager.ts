/**
 * AssetManager
 *
 * Named asset collection with SEA and disk loading.
 * In SEA mode, embedded assets are loaded automatically at construction.
 * In development, `load()` reads client assets from disk.
 */

import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { getAssetKeys, getRawAsset, isSea } from 'node:sea'
import type {
	AssetInput,
	AssetInterface,
	AssetManagerEventMap,
	AssetManagerInterface,
	AssetManagerOptions,
} from '../types.js'
import type { EmitterInterface } from '@orkestrel/emitter'
import { Emitter } from '@orkestrel/emitter'
import { isArrayBuffer } from '@orkestrel/contract'
import { CLIENT_ASSET_KEY_BR, CLIENT_ASSET_KEY_RAW } from '../constants.js'
import { Asset } from './Asset.js'

// === AssetManager

export class AssetManager implements AssetManagerInterface {
	readonly #emitter: Emitter<AssetManagerEventMap>
	#assets = new Map<string, AssetInterface>()
	#keys: string[] = []
	readonly #root: string

	constructor(options?: AssetManagerOptions) {
		this.#root = options?.root ?? process.cwd()
		this.#emitter = new Emitter({
			...(options?.on === undefined ? {} : { on: options.on }),
			...(options?.error === undefined ? {} : { error: options.error }),
		})
		this.#loadSea()
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
		return [...this.#keys]
	}

	register(input: AssetInput | AssetInput[]): void {
		const items = Array.isArray(input) ? input : [input]
		for (const item of items) {
			const asset: AssetInterface = new Asset(item)
			this.#add(asset)
			this.#emitter.emit('register', asset)
		}
	}

	load(): void {
		if (isSea()) return

		const devPath = resolve(this.#root, 'client', CLIENT_ASSET_KEY_RAW)
		const builtBrPath = resolve(this.#root, 'dist', 'client', CLIENT_ASSET_KEY_BR)

		if (existsSync(devPath)) {
			try {
				const raw = readFileSync(devPath, 'utf-8')
				const encoder = new TextEncoder()
				const bytes = encoder.encode(raw)
				const content = bytes.buffer
				if (!isArrayBuffer(content)) {
					throw new Error('Failed to encode client asset')
				}
				this.register({ key: CLIENT_ASSET_KEY_RAW, content, compressed: false })
				this.#emitter.emit('load', [CLIENT_ASSET_KEY_RAW])
			} catch (thrown: unknown) {
				this.#emitter.emit('error', thrown)
			}
			return
		}

		if (existsSync(builtBrPath)) {
			try {
				const buffer = readFileSync(builtBrPath)
				const bufferData = buffer.buffer
				if (!isArrayBuffer(bufferData)) {
					throw new Error('Failed to read client asset')
				}
				const content = bufferData.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
				this.register({ key: CLIENT_ASSET_KEY_BR, content, compressed: true })
				this.#emitter.emit('load', [CLIENT_ASSET_KEY_BR])
			} catch (thrown: unknown) {
				this.#emitter.emit('error', thrown)
			}
			return
		}

		this.#emitter.emit('error', new Error('Client assets not found'))
	}

	clear(): void {
		this.#assets.clear()
		this.#keys = []
		this.#emitter.emit('clear')
	}

	destroy(): void {
		this.clear()
		this.#emitter.destroy()
	}

	// === Private

	#add(asset: AssetInterface): void {
		this.#assets.set(asset.key, asset)
		if (!this.#keys.includes(asset.key)) {
			this.#keys.push(asset.key)
		}
	}

	#loadSea(): void {
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
