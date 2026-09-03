import type {
	AssetInput,
	AssetInterface,
	AssetManagerInterface,
	AssetManagerOptions,
	InjectorInterface,
	InjectorOptions,
	SEAInterface,
	SEAOptions,
} from './types.js'
import { SEA } from './seas/SEA.js'
import { Injector } from './injectors/Injector.js'
import { Asset } from './assets/Asset.js'
import { AssetManager } from './assets/AssetManager.js'

/**
 * Creates a new SEA build orchestrator.
 *
 * @param options - SEA build options
 * @returns a new `SEAInterface`
 *
 * @example
 * ```ts
 * const sea = createSEA({
 *     name: 'orkestrel',
 *     entry: { path: 'dist/bin/serve.cjs' },
 *     output: 'dist/sea',
 *     assets: { 'index.html.br': 'dist/client/index.html.br' },
 *     compression: { paths: ['dist/client'] },
 * })
 * const result = await sea.execute()
 * ```
 */
export function createSEA(options: SEAOptions): SEAInterface {
	return new SEA(options)
}

/**
 * Creates a cross-platform binary resource injector.
 *
 * Detects the executable format (PE, ELF, Mach-O) from the file header
 * and injects the blob using pure TypeScript file I/O — no WASM, no
 * external tools.
 *
 * @param options - Injector options
 * @returns a new `InjectorInterface`
 *
 * @example
 * ```ts
 * const injector = createInjector({
 *     executable: 'dist/bin/myapp.exe',
 *     resource: 'NODE_SEA_BLOB',
 *     blob: 'dist/bin/sea-prep.blob',
 *     fuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
 * })
 * injector.inject()
 * ```
 */
export function createInjector(options: InjectorOptions): InjectorInterface {
	return new Injector(options)
}

/**
 * Creates a single named asset.
 *
 * @param input - Asset key, content, and optional compression flag
 * @returns a new `AssetInterface`
 *
 * @example
 * ```ts
 * const asset = createAsset({ key: 'client.html.br', content: compressedBuffer })
 * ```
 */
export function createAsset(input: AssetInput): AssetInterface {
	return new Asset(input)
}

/**
 * Creates an asset manager for SEA-embedded or disk-loaded assets.
 *
 * @param options - Asset manager options (root, event hooks)
 * @returns a new `AssetManagerInterface`
 *
 * @example
 * ```ts
 * const manager = createAssetManager({ root: process.cwd() })
 * manager.load()
 * ```
 */
export function createAssetManager(options?: AssetManagerOptions): AssetManagerInterface {
	return new AssetManager(options)
}
