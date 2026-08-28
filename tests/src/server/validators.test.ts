import { describe, expect, it } from 'vitest'
import { isExecutableFormat } from '@src/server'

describe('validators', () => {
	describe('isExecutableFormat', () => {
		it.each([
			['pe', true],
			['elf', true],
			['macho', true],
			['coff', false],
			['PE', false],
			['', false],
		])('classifies %j as %s', (value, expected) => {
			expect(isExecutableFormat(value)).toBe(expected)
		})

		it('rejects every non-string value', () => {
			for (const value of [undefined, null, 0, {}, ['pe']]) {
				expect(isExecutableFormat(value)).toBe(false)
			}
		})
	})
})
