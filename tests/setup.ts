import type {
	ToolCall,
	ToolInterface,
	QueueEntryState,
	QueueEntryOptions,
	QueueEntryStatus,
	QueueEntrySchedule,
	Result,
	QuantitativeDefinition,
	LogicalDefinition,
	SymbolicDefinition,
	InferentialDefinition,
	QuantitativeResult,
	LogicalResult,
	SymbolicResult,
	InferentialResult,
	ReasonResult,
	ReasonerInterface,
	EvaluatorInterface,
	TransformerInterface,
	AggregatorInterface,
	AbortInterface,
	AgentProviderInterface,
	AgentStreamOptions,
	DatabaseInterface,
	DatabaseSchema,
	Factor,
	FactorGroup,
	Rule,
	Aggregation,
	ChainingStrategy,
	Equation,
	Fact,
	Inference,
	MessageInterface,
	MessageRole,
	ProviderResult,
	Subject,
	Condition,
	Bounds,
	InterpretTemplate,
	RelationManagerInterface,
	TableDefinition,
	ToolDefinition,
	PromptTemplate,
	AgentManagerInterface,
} from '@scsr/core'
import {
	generateId,
	createDatabase,
	createQuantitativeReasoner,
	createLogicalReasoner,
	createSymbolicReasoner,
	createInferentialReasoner,
	createEvaluator,
	createTransformer,
	createAggregator,
	createMemoryDriver,
	createRelationManager,
	createAgentManager,
	OllamaProvider,
} from '@scsr/core'
export { delay } from '@scsr/core'
import { afterEach, expect, vi } from 'vitest'

// === Constants

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const OLLAMA_TIMEOUT_MS = 5_000
// === Environment

function env(key: string, fallback: string): string {
	const meta: unknown = import.meta.env?.[key]
	if (typeof meta === 'string' && meta.length > 0) return meta

	const proc: unknown = typeof process !== 'undefined' ? process.env[key] : undefined
	if (typeof proc === 'string' && proc.length > 0) return proc

	return fallback
}

export const OLLAMA_CONFIG = {
	host: env('OLLAMA_HOST', 'http://localhost:11434'),
	model: env('OLLAMA_MODEL', 'qwen3.5:2b-q4_K_M'),
	defaultSystem: 'Reply briefly and directly.',
}

export const DRIVER_TABLE_DEF: TableDefinition = {
	columns: [
		{ name: 'id', type: 'TEXT', primary: true },
		{ name: 'name', type: 'TEXT', nullable: false },
		{ name: 'age', type: 'INTEGER' },
	],
}

export const DRIVER_ALICE = { id: 'u1', name: 'Alice', age: 30 }
export const DRIVER_BOB = { id: 'u2', name: 'Bob', age: 25 }
export const DRIVER_CAROL = { id: 'u3', name: 'Carol', age: 35 }

type AgentTestSchema = {
	readonly agents: {
		readonly id: string
		readonly content: string
	}
}

const AGENT_TEST_TABLE_DEF: TableDefinition = {
	columns: [
		{ name: 'id', type: 'TEXT', primary: true },
		{ name: 'content', type: 'TEXT', nullable: false },
	],
}

// === Ollama Availability

export async function isOllamaAvailable(): Promise<boolean> {
	const controller = new AbortController()
	const timeoutId = setTimeout(() => controller.abort(), OLLAMA_TIMEOUT_MS)
	try {
		const response = await fetch(`${OLLAMA_CONFIG.host}/api/tags`, {
			signal: controller.signal,
		})
		return response.ok
	} catch {
		return false
	} finally {
		clearTimeout(timeoutId)
	}
}

// === Global Teardown

afterEach(() => {
	vi.restoreAllMocks()
})

// === Agent Test Helpers

export function createTestAgentProvider(options?: {
	readonly id?: string
	readonly name?: string
	readonly generate?: (
		messages: readonly MessageInterface[],
		abort: AbortInterface,
		tools?: readonly ToolDefinition[],
	) => Promise<ProviderResult>
	readonly stream?: (
		messages: readonly MessageInterface[],
		abort: AbortInterface,
		tools?: readonly ToolDefinition[],
		options?: AgentStreamOptions,
	) => AsyncGenerator<string, ProviderResult>
}): AgentProviderInterface {
	return {
		id: options?.id ?? 'test-provider',
		name: options?.name ?? 'Test Provider',
		generate:
			options?.generate ??
			(() =>
				Promise.resolve({
					content: 'response',
					usage: { prompt: 5, completion: 3, total: 8 },
				})),
		stream:
			options?.stream ??
			async function* (): AsyncGenerator<string, ProviderResult> {
				yield 'token'
				return { content: 'token' }
			},
	}
}

export function createTestAgentDatabase(
	name = `agent-test-${generateId()}`,
): DatabaseInterface<AgentTestSchema> {
	return createDatabase<AgentTestSchema>({
		name,
		driver: createMemoryDriver({ name }),
		tables: {
			agents: AGENT_TEST_TABLE_DEF,
		},
	})
}

export function createTestAgentRelations(
	database: DatabaseInterface<DatabaseSchema> = createTestAgentDatabase(),
): RelationManagerInterface {
	return createRelationManager({ database })
}

export function createTestAgentDependencies(): {
	readonly database: DatabaseInterface<AgentTestSchema>
	readonly relations: RelationManagerInterface
} {
	const database = createTestAgentDatabase()
	const relations = createTestAgentRelations(database)
	return { database, relations }
}

// === Tool Factory

/**
 * Create a test tool that echoes back its arguments.
 */
export function createEchoTool(name = 'echo'): ToolInterface {
	return {
		name,
		summary: 'Echoes back the input',
		description: 'A simple tool that returns whatever you pass to it.',
		parameters: {
			type: 'object',
			properties: {
				message: { type: 'string', description: 'Message to echo' },
			},
			required: ['message'],
		},
		execute: (args) => args,
	}
}

/**
 * Create a minimal Tool with an optional fixed return value.
 * Defaults to returning `undefined` from the handler.
 */
export function makeTool(name: string, returnValue?: unknown): ToolInterface {
	return {
		name,
		summary: name,
		description: name,
		parameters: { type: 'object' },
		execute: () => returnValue,
	}
}

/**
 * Create a minimal ToolCall for testing.
 */
export function makeCall(name: string, args: Record<string, unknown> = {}): ToolCall {
	return {
		id: generateId(),
		name,
		arguments: args,
	}
}

// === Queue Test Helpers

/**
 * Assert the result is a Success and return the value.
 * Throws a test assertion error if the result is a Failure.
 *
 * @param result - Result to assert
 * @returns The success value
 */
export function expectSuccess<T>(result: Result<T>): T {
	expect(result.success).toBe(true)
	if (!result.success) throw new Error('Expected success')
	return result.value
}

/**
 * Assert the result is a Failure and return the error.
 * Throws a test assertion error if the result is a Success.
 *
 * @param result - Result to assert
 * @returns The failure error
 */
export function expectFailure<T, E = Error>(result: Result<T, E>): E {
	expect(result.success).toBe(false)
	if (result.success) throw new Error('Expected failure')
	return result.error
}

/**
 * Build a QueueEntryState with scheduling fields defaulted.
 * Keeps test literals short while satisfying the full interface.
 */
export function entryState<TContext>(fields: {
	id: string
	context: TContext
	status: QueueEntryStatus
	attempts: number
	options: QueueEntryOptions | undefined
	schedule?: QueueEntrySchedule | undefined
	timestamp?: number
}): QueueEntryState<TContext> {
	return {
		id: fields.id,
		context: fields.context,
		status: fields.status,
		attempts: fields.attempts,
		options: fields.options,
		schedule: fields.schedule !== undefined ? fields.schedule : undefined,
		timestamp: fields.timestamp !== undefined ? fields.timestamp : 0,
	}
}

// === Reason Test Helpers

/**
 * Empty subject constant for tests that don't need subject data.
 */
export const emptySubject: Subject = {}

/**
 * A typical subject with common fields used across multiple test suites.
 */
export const basicSubject: Subject = {
	id: 'test-1',
	age: 30,
	name: 'Alice',
	score: 85,
	state: 'CA',
	employed: true,
}

/**
 * A subject with nested object fields.
 */
export const nestedSubject: Subject = {
	id: 'nested-1',
	address: { city: 'NY', zip: '10001' },
	scores: { math: 90, english: 80 },
}

/**
 * A subject shaped for insurance/driver scenarios.
 */
export const driverSubject: Subject = {
	driverAge: 22,
	violationCount: 0,
	vehicleYear: 2020,
}

// === Shared Conditions

/** Condition: age >= 18 */
export const ageGte18: Condition = { field: 'age', operator: 'greaterThanOrEqual', value: 18 }
/** Condition: score > 50 */
export const scoreGt50: Condition = { field: 'score', operator: 'greaterThan', value: 50 }
/** Condition: name === 'Alice' */
export const nameEqualsAlice: Condition = { field: 'name', operator: 'equals', value: 'Alice' }

/**
 * Pre-created evaluator instance for direct use in tests.
 */
export const evaluator: EvaluatorInterface = createEvaluator()

/**
 * Pre-created transformer instance for direct use in tests.
 */
export const transformer: TransformerInterface = createTransformer()

/**
 * Pre-created aggregator instance for direct use in tests.
 */
export const aggregator: AggregatorInterface = createAggregator()

/**
 * Pre-created reasoner instances for direct use in tests.
 */
export const quantitativeReasoner: ReasonerInterface = createQuantitativeReasoner()
export const logicalReasoner: ReasonerInterface = createLogicalReasoner()
export const symbolicReasoner: ReasonerInterface = createSymbolicReasoner()
export const inferentialReasoner: ReasonerInterface = createInferentialReasoner()

// === Reason Definition Factories

/**
 * Create a QuantitativeDefinition from groups with optional overrides.
 */
export function quantitativeDef(
	groups: FactorGroup[],
	overrides?: {
		readonly id?: string
		readonly name?: string
		readonly description?: string
		readonly aggregation?: Aggregation
		readonly base?: number
		readonly bounds?: Bounds
		readonly precision?: number
	},
): QuantitativeDefinition {
	return {
		type: 'quantitative',
		id: overrides?.id ?? `quant-${generateId()}`,
		name: overrides?.name ?? 'Test Quantitative',
		description: overrides?.description,
		groups,
		aggregation: overrides?.aggregation ?? 'sum',
		base: overrides?.base,
		bounds: overrides?.bounds,
		precision: overrides?.precision ?? 15,
	}
}

/**
 * Create a LogicalDefinition from rules with optional overrides.
 */
export function logicalDef(
	rules: Rule[],
	overrides?: {
		readonly id?: string
		readonly name?: string
		readonly description?: string
		readonly strategy?: ChainingStrategy
		readonly depth?: number
	},
): LogicalDefinition {
	return {
		type: 'logical',
		id: overrides?.id ?? `logical-${generateId()}`,
		name: overrides?.name ?? 'Test Logical',
		description: overrides?.description,
		rules,
		strategy: overrides?.strategy ?? 'forward',
		depth: overrides?.depth,
	}
}

/**
 * Create a SymbolicDefinition from a config object.
 */
export function symbolicDef(config: {
	readonly id?: string
	readonly name?: string
	readonly description?: string
	readonly equations?: Equation[]
	readonly variables?: Readonly<Record<string, number>>
	readonly precision?: number
}): SymbolicDefinition {
	return {
		type: 'symbolic',
		id: config.id ?? `symbolic-${generateId()}`,
		name: config.name ?? 'Test Symbolic',
		description: config.description,
		equations: config.equations ?? [],
		variables: config.variables ?? {},
		precision: config.precision,
	}
}

/**
 * Create an InferentialDefinition from a config object.
 */
export function inferentialDef(config: {
	readonly id?: string
	readonly name?: string
	readonly description?: string
	readonly inferences?: Inference[]
	readonly facts?: Fact[]
	readonly strategy?: ChainingStrategy
	readonly depth?: number
}): InferentialDefinition {
	return {
		type: 'inferential',
		id: config.id ?? `inferential-${generateId()}`,
		name: config.name ?? 'Test Inferential',
		description: config.description,
		inferences: config.inferences ?? [],
		facts: config.facts ?? [],
		strategy: config.strategy ?? 'forward',
		depth: config.depth,
	}
}

// === Factor and Group Factories

/**
 * Create a Factor with a static value source.
 */
export function staticFactor(
	id: string,
	value: number,
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly fallback?: number
		readonly conditions?: Condition[]
		readonly transforms?: Factor['transforms']
		readonly bounds?: Bounds
		readonly weight?: number
		readonly priority?: number
		readonly enabled?: boolean
		readonly required?: boolean
	},
): Factor {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		source: { kind: 'static', value },
		fallback: overrides?.fallback,
		conditions: overrides?.conditions,
		transforms: overrides?.transforms,
		bounds: overrides?.bounds,
		weight: overrides?.weight,
		priority: overrides?.priority,
		enabled: overrides?.enabled,
		required: overrides?.required,
	}
}

/**
 * Create a Factor with a field value source.
 */
export function fieldFactor(
	id: string,
	field: string,
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly fallback?: number
		readonly conditions?: Condition[]
		readonly transforms?: Factor['transforms']
		readonly bounds?: Bounds
		readonly weight?: number
		readonly priority?: number
		readonly enabled?: boolean
		readonly required?: boolean
	},
): Factor {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		source: { kind: 'field', field },
		fallback: overrides?.fallback,
		conditions: overrides?.conditions,
		transforms: overrides?.transforms,
		bounds: overrides?.bounds,
		weight: overrides?.weight,
		priority: overrides?.priority,
		enabled: overrides?.enabled,
		required: overrides?.required,
	}
}

/**
 * Create a FactorGroup with any aggregation type.
 */
export function group(
	id: string,
	aggregation: Aggregation,
	factors: Factor[],
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly base?: number
		readonly bounds?: Bounds
		readonly enabled?: boolean
		readonly strict?: boolean
	},
): FactorGroup {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		factors,
		aggregation,
		base: overrides?.base,
		bounds: overrides?.bounds,
		enabled: overrides?.enabled,
		strict: overrides?.strict,
	}
}

/**
 * Create a FactorGroup with 'sum' aggregation.
 */
export function sumGroup(
	id: string,
	factors: Factor[],
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly base?: number
		readonly bounds?: Bounds
		readonly enabled?: boolean
		readonly strict?: boolean
	},
): FactorGroup {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		factors,
		aggregation: 'sum',
		base: overrides?.base,
		bounds: overrides?.bounds,
		enabled: overrides?.enabled,
		strict: overrides?.strict,
	}
}

/**
 * Create a FactorGroup with 'product' aggregation.
 */
export function productGroup(
	id: string,
	factors: Factor[],
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly base?: number
		readonly bounds?: Bounds
		readonly enabled?: boolean
		readonly strict?: boolean
	},
): FactorGroup {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		factors,
		aggregation: 'product',
		base: overrides?.base,
		bounds: overrides?.bounds,
		enabled: overrides?.enabled,
		strict: overrides?.strict,
	}
}

// === Rule Factory

/**
 * Create a simple logical rule: if `fromField` equals `fromValue`, conclude `toField` equals `toValue`.
 */
export function simpleRule(
	id: string,
	fromField: string,
	fromValue: unknown,
	toField: string,
	toValue: unknown,
	overrides?: {
		readonly label?: string
		readonly description?: string
		readonly confidence?: number
		readonly priority?: number
		readonly enabled?: boolean
	},
): Rule {
	return {
		id,
		label: overrides?.label ?? id,
		description: overrides?.description,
		premises: [
			{
				type: 'atom',
				condition: { field: fromField, operator: 'equals', value: fromValue },
			},
		],
		conclusion: {
			type: 'atom',
			condition: { field: toField, operator: 'equals', value: toValue },
		},
		confidence: overrides?.confidence,
		priority: overrides?.priority,
		enabled: overrides?.enabled,
	}
}

// === Result Type Assertion Helpers

function isSingleResult(result: unknown): result is ReasonResult {
	return typeof result === 'object' && result !== null && 'type' in result && !Array.isArray(result)
}

/**
 * Assert a ReasonResult is QuantitativeResult and return it.
 * Throws if the result type does not match.
 */
export function expectQuantitative(result: unknown): QuantitativeResult {
	if (!isSingleResult(result)) {
		throw new Error('Expected single result, got batch array')
	}
	if (result.type !== 'quantitative') {
		throw new Error(`Expected quantitative result but got ${result.type}`)
	}
	return result
}

/**
 * Assert a ReasonResult is LogicalResult and return it.
 * Throws if the result type does not match.
 */
export function expectLogical(result: unknown): LogicalResult {
	if (!isSingleResult(result)) {
		throw new Error('Expected single result, got batch array')
	}
	if (result.type !== 'logical') {
		throw new Error(`Expected logical result but got ${result.type}`)
	}
	return result
}

/**
 * Assert a ReasonResult is SymbolicResult and return it.
 * Throws if the result type does not match.
 */
export function expectSymbolic(result: unknown): SymbolicResult {
	if (!isSingleResult(result)) {
		throw new Error('Expected single result, got batch array')
	}
	if (result.type !== 'symbolic') {
		throw new Error(`Expected symbolic result but got ${result.type}`)
	}
	return result
}

/**
 * Assert a ReasonResult is InferentialResult and return it.
 * Throws if the result type does not match.
 */
export function expectInferential(result: unknown): InferentialResult {
	if (!isSingleResult(result)) {
		throw new Error('Expected single result, got batch array')
	}
	if (result.type !== 'inferential') {
		throw new Error(`Expected inferential result but got ${result.type}`)
	}
	return result
}

// === Simple Pre-Built Definitions

/**
 * A simple quantitative definition that produces value 42 with an empty subject.
 */
export const simpleQuantDef: QuantitativeDefinition = {
	type: 'quantitative',
	id: 'simple-quant',
	name: 'Simple Quantitative',
	groups: [
		{
			id: 'g1',
			label: 'Group 1',
			aggregation: 'sum',
			factors: [
				{
					id: 'f1',
					label: 'Factor 1',
					source: { kind: 'static', value: 42 },
				},
			],
		},
	],
	aggregation: 'sum',
	precision: 15,
}

// === Interpret Test Helpers

/**
 * Creates a minimal test template for the interpret pipeline.
 *
 * @param overrides - Override any template field
 * @returns A valid InterpretTemplate for testing
 */
export function testTemplate(overrides?: Partial<InterpretTemplate>): InterpretTemplate {
	return {
		id: 'test-template',
		name: 'Test Template',
		domain: 'test',
		subDomains: ['sub'],
		intents: ['calculate'],
		mappings: [
			{ entity: 'age', aliases: ['years old', 'year old'], field: 'age', required: true },
			{ entity: 'amount', aliases: ['dollars', 'price', 'cost'], field: 'amount' },
		],
		defaults: [{ field: 'amount', value: 100, source: 'template' }],
		inferences: [],
		definition: {
			type: 'quantitative',
			id: overrides?.id ?? 'test-template',
			name: overrides?.name ?? 'Test Template',
			groups: [],
			aggregation: 'sum' as const,
		},
		...overrides,
	}
}

// === Batch Result Narrowing

/**
 * Assert that a result is a batch array.
 */
export function expectBatch(result: unknown): readonly ReasonResult[] {
	if (!Array.isArray(result)) {
		throw new Error('Expected batch array, got single result')
	}
	return result
}

// === MCP Tool Test Helpers

/** Narrows unknown to a record for test assertions */
export function toRecord(value: unknown): Record<string, unknown> {
	if (typeof value === 'object' && value !== null) {
		const result: Record<string, unknown> = {}
		for (const [k, v] of Object.entries(value)) {
			result[k] = v
		}
		return result
	}
	return {}
}

/** Narrows unknown to unknown[] — returns empty array if not an array */
export function toArray(value: unknown): unknown[] {
	return Array.isArray(value) ? value : []
}

/** Extracts the parsed JSON content from a successful MCP tool call response */
export function parseToolContent(result: unknown): Record<string, unknown> {
	const r = toRecord(result)
	const content = toArray(r['content'])
	if (content.length === 0) return {}
	const text = toRecord(content[0])['text']
	return toRecord(JSON.parse(String(text)))
}

/**
 * Recursively validates a JSON Schema object.
 *
 * Returns an array of error strings. An empty array means the schema is valid.
 */
export function validateSchema(schema: unknown, path: string = '$'): string[] {
	if (typeof schema !== 'object' || schema === null) return []
	const errors: string[] = []
	const record = schema as Record<string, unknown>

	if (record['type'] === 'array' && record['items'] === undefined) {
		errors.push(`${path}: type "array" is missing "items"`)
	}

	const oneOf = record['oneOf']
	if (oneOf !== undefined) {
		if (!Array.isArray(oneOf) || oneOf.length === 0) {
			errors.push(`${path}: "oneOf" must be a non-empty array`)
		} else {
			for (let i = 0; i < oneOf.length; i++) {
				errors.push(...validateSchema(oneOf[i], `${path}.oneOf[${i}]`))
			}
		}
	}

	const properties = record['properties']
	if (typeof properties === 'object' && properties !== null) {
		for (const [key, value] of Object.entries(properties as Record<string, unknown>)) {
			errors.push(...validateSchema(value, `${path}.properties.${key}`))
		}
	}

	const items = record['items']
	if (typeof items === 'object' && items !== null) {
		errors.push(...validateSchema(items, `${path}.items`))
	}

	return errors
}

// === Agent Manager Test Helpers

const activeManagers = new Set<AgentManagerInterface>()

afterEach(() => {
	for (const manager of activeManagers) {
		manager.destroy()
	}
	activeManagers.clear()
})

export function createTestManager(model = OLLAMA_CONFIG.model): AgentManagerInterface {
	const manager = createAgentManager(
		new OllamaProvider({
			model,
			url: OLLAMA_CONFIG.host,
			think: false,
			timeout: 60_000,
		}),
	)
	activeManagers.add(manager)
	return manager
}

export function msg(role: MessageRole, content: string, partial = false): MessageInterface {
	return { id: generateId(), role, content, partial }
}

// === Template Factories for MCP Tools

/** Standard greeting template for tests */
export function greetingTemplate(): PromptTemplate {
	return {
		id: 'greeting',
		name: 'Greeting',
		content: 'Hello, {{name}}! Welcome to {{place}}.',
		placeholders: [
			{ name: 'name', required: true },
			{ name: 'place', value: 'the system' },
		],
	}
}

/** Template with all optional fields populated */
export function fullTemplate(): PromptTemplate {
	return {
		id: 'full',
		name: 'Full Template',
		content: 'Dear {{recipient}},\n\n{{body}}\n\nBest,\n{{sender}}',
		placeholders: [
			{ name: 'recipient', required: true, description: 'Person to address' },
			{ name: 'body', required: true, description: 'Main content' },
			{ name: 'sender', value: 'The Team', description: 'Sender name' },
		],
		summary: 'A full email template',
		description: 'Template with all optional fields filled in',
		category: 'communication',
		tags: ['email', 'formal'],
	}
}
