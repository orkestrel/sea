import { describe, expect, it } from 'vitest'
import { isSEAError, isShellError, SEAError, ShellError } from '@src/server'
import { createCallableSEAContext, SEAContextFixture } from '../../setup.js'

describe('sea error context types', () => {
	it('accepts a class-instance context', () => {
		const error = new SEAError('STATE', 'failure')
		Object.defineProperty(error, 'context', { value: new SEAContextFixture() })
		expect(isSEAError(error)).toBe(true)
		const shell = new ShellError('failure', Buffer.alloc(0), Buffer.alloc(0))
		Object.defineProperty(shell, 'context', { value: new SEAContextFixture() })
		expect(isShellError(shell)).toBe(true)
	})

	it('accepts a callable context', () => {
		const error = new SEAError('STATE', 'failure')
		Object.defineProperty(error, 'context', { value: createCallableSEAContext() })
		expect(isSEAError(error)).toBe(true)
		const shell = new ShellError('failure', Buffer.alloc(0), Buffer.alloc(0))
		Object.defineProperty(shell, 'context', { value: createCallableSEAContext() })
		expect(isShellError(shell)).toBe(true)
	})
})
