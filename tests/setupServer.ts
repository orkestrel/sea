// Server-test setup — node-only helpers, loaded after `setup.ts` for the node
// `src:server` (and `guides`) projects. `node:fs` / `node:path` imports belong
// here, never in `setup.ts`. Anchor every path to `WORKSPACE_ROOT` so the
// runner's cwd never matters (AGENTS §16.1).

import type { InjectorOptions, SEAOptions } from '@src/server'
import * as fs from 'node:fs'
import * as nodePath from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

export const WORKSPACE_ROOT = fileURLToPath(new URL('..', import.meta.url))

// === Temp directories

/** A temporary directory created for one test, cleaned up via {@link withTestDir}. */
export interface TestDir {
	readonly root: string
}

/**
 * Create a fresh temporary directory pre-populated with `files`, under the OS
 * tmp root — NOT anchored under `WORKSPACE_ROOT`, since a seal build writes a
 * real executable that must never land in source control (AGENTS §16.1).
 *
 * @param files - Record of relative path to file content, written before returning
 * @returns A {@link TestDir} wrapping the created directory's absolute path
 */
export function createTestDir(files: Record<string, string> = {}): TestDir {
	const root = fs.mkdtempSync(nodePath.join(tmpdir(), 'sea-test-'))
	for (const [relativePath, content] of Object.entries(files)) {
		const target = nodePath.join(root, relativePath)
		fs.mkdirSync(nodePath.dirname(target), { recursive: true })
		fs.writeFileSync(target, content, 'utf8')
	}
	return { root }
}

/** Remove a {@link TestDir} and everything inside it. */
export function destroyTestDir(dir: TestDir): void {
	fs.rmSync(dir.root, { recursive: true, force: true })
}

/**
 * Run `fn` with a fresh {@link TestDir} pre-populated with `files`, then clean
 * it up unconditionally — the shared create/use/destroy wrapper every
 * seal/injector test repeats (AGENTS §16.1).
 *
 * @param files - Record of relative path to file content
 * @param fn - Callback receiving the created {@link TestDir}
 * @returns The callback's return value
 */
export async function withTestDir<T>(
	files: Record<string, string>,
	fn: (dir: TestDir) => Promise<T> | T,
): Promise<T> {
	const dir = createTestDir(files)
	try {
		return await fn(dir)
	} finally {
		destroyTestDir(dir)
	}
}

/** Read a file's UTF-8 content relative to `root`. */
export function readFromDisk(root: string, relativePath: string): string {
	return fs.readFileSync(nodePath.join(root, relativePath), 'utf-8')
}

/** Check whether a path relative to `root` exists on disk. */
export function existsOnDisk(root: string, relativePath: string): boolean {
	return fs.existsSync(nodePath.join(root, relativePath))
}

// === Option builders

/**
 * Build valid {@link SEAOptions} for a test — `name`, `entry`, and `output`
 * default to a minimal working scenario; override any field to exercise a
 * specific case.
 */
export function createSEAOptions(overrides?: Partial<SEAOptions>): SEAOptions {
	return {
		name: 'seal-test',
		entry: 'entry.cjs',
		output: 'dist',
		...overrides,
	}
}

/**
 * Build valid {@link InjectorOptions} for a test — `resource` defaults to the
 * standard SEA blob resource name.
 */
export function createInjectorOptions(options: {
	readonly executable: string
	readonly blob: string
	readonly resource?: string
	readonly fuse?: string
	readonly overwrite?: boolean
	readonly macho?: InjectorOptions['macho']
}): InjectorOptions {
	return {
		executable: options.executable,
		resource: options.resource ?? 'NODE_SEA_BLOB',
		blob: options.blob,
		fuse: options.fuse,
		overwrite: options.overwrite,
		macho: options.macho,
	}
}
