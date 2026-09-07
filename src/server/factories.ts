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
 * Creates a SEA build orchestrator over the given options and returns it as a
 * `SEAInterface`, the published contract a caller holds instead of the `SEA` class.
 *
 * @param options - SEA build options
 * @returns a new `SEAInterface`
 *
 * @example Build a single executable
 * ```ts
 * import { createSEA, formatSize } from '@orkestrel/sea'
 *
 * const sea = createSEA({
 * 	name: 'myapp',
 * 	entry: { path: 'dist/server/serve.cjs' },
 * 	output: 'dist/sea',
 * 	assets: { 'model.gguf': 'models/model.gguf' },
 * 	compression: { paths: ['dist/app/browser'], mode: 'text' },
 * 	windows: { terminal: false },
 * 	timeout: 30_000,
 * })
 *
 * const result = await sea.execute()
 * process.stdout.write(
 * 	`${result.executable} ${formatSize(result.size)} ${String(result.duration)}ms\n`,
 * )
 * ```
 */
export function createSEA(options: SEAOptions): SEAInterface {
	return new SEA(options)
}

/**
 * Creates a resource injector bound to one target executable and returns it as an
 * `InjectorInterface`, with the executable's format already detected from its header.
 *
 * @remarks
 * The format detected at construction — PE, ELF, or Mach-O — selects the strategy
 * `inject` takes. Every write runs through pure TypeScript file I/O, so the injector
 * needs no WASM and no external tool.
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
 * Creates one named asset from a key and a content buffer and returns it as an
 * `AssetInterface`, with `compressed` inferred from the key where the input leaves
 * it unset.
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
 * Creates an asset collection and returns it as an `AssetManagerInterface`, already
 * carrying whatever assets the running SEA blob embeds.
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
