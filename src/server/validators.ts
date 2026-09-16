import type { ExecutableFormat } from './types.js'
import { literalOf } from '@orkestrel/contract'

// === Type Guards

/**
 * Checks whether a value is a valid {@link ExecutableFormat}.
 *
 * @param value - Value to check
 * @returns True if value is `'pe'`, `'elf'`, or `'macho'`; false otherwise
 *
 * @example
 * ```ts
 * isExecutableFormat('elf') // true
 * isExecutableFormat('coff') // false
 * ```
 */
export function isExecutableFormat(value: unknown): value is ExecutableFormat {
	return literalOf('pe', 'elf', 'macho')(value)
}
