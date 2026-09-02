import type { ExecutableFormat } from './types.js'

// === Type Guards

/**
 * Checks if a value is a valid {@link ExecutableFormat}.
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
	return value === 'pe' || value === 'elf' || value === 'macho'
}
