import type { ExecutableFormat } from './types.js'

// === Type Guards

/**
 * Check if a value is a valid {@link ExecutableFormat}.
 *
 * @param value - Value to check
 * @returns True when value is `'pe'`, `'elf'`, or `'macho'`
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
