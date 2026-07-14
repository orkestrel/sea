import type { IncomingMessage, ServerResponse } from 'node:http'
import { IncomingMessage as HttpIncomingMessage } from 'node:http'
import type {
	DatabaseEventMap,
	DatabaseInterface,
	EmitterHooks,
	JsonRpcMessage,
	JsonRpcResponse,
	QuantitativeDefinition,
	RelationManagerInterface,
	TableDefinitions,
} from '@scsr/core'
import {
	createDatabase,
	compileTable,
	createRelationManager,
	parseJsonRpcMessage,
	stripAnsi,
} from '@scsr/core'
import type {
	InjectorOptions,
	MCPServerInterface,
	NodeWebSocketInterface,
	RouteHandlerContext,
	SandboxInterface,
	SealOptions,
	ServerInterface,
	TerminalFormInterface,
	WebSocketUpgradeOptions,
} from '@scsr/server'
import {
	seedAccount as createSeededAccount,
	seedLocation as createSeededLocation,
	seedPolicy as createSeededPolicy,
	seedQuote as createSeededQuote,
	seedRepresentative as createSeededRepresentative,
	seedSubmission as createSeededSubmission,
} from '@app/core'
import { type AppContext, createAppContext } from '@app/server'
import {
	createBrowser,
	createWebSocketUpgradeHandler,
	createSandbox,
	MCPStoreManager,
	Server,
	Session,
	SessionStore,
	SqliteDriver,
	Terminal,
	UploadedFile,
} from '@scsr/server'
import type { BrowserInterface, BrowserContextInterface } from '@scsr/server'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as nodePath from 'node:path'
import type { Duplex } from 'node:stream'
import { PassThrough, Writable } from 'node:stream'
import { Socket } from 'node:net'
import { isFunction, isObject, isRecord } from '@scsr/core'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { rm } from 'node:fs/promises'
import { DRIVER_TABLE_DEF } from './setup.js'
import { createServer as createHttpServer, request } from 'node:http'
import type { Server as HttpServer } from 'node:http'

// === Test Schema

export type TestSchema = {
	users: { id: string; name: string; email: string; age: number }
	posts: { id: string; title: string; authorId: string; published: number }
}

export const TEST_TABLES: TableDefinitions<TestSchema> = {
	users: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'name', type: 'TEXT', nullable: false },
			{ name: 'email', type: 'TEXT', unique: true },
			{ name: 'age', type: 'INTEGER' },
		],
		indexes: [{ name: 'idx_users_email', columns: ['email'], unique: true }],
	},
	posts: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'title', type: 'TEXT', nullable: false },
			{ name: 'authorId', type: 'TEXT', nullable: false },
			{ name: 'published', type: 'INTEGER' },
		],
		foreignKeys: [
			{
				columns: ['authorId'],
				references: { table: 'users', columns: ['id'] },
				delete: 'CASCADE',
			},
		],
	},
}

export const ALICE = { id: 'u1', name: 'Alice', email: 'alice@test.com', age: 30 }
export const BOB = { id: 'u2', name: 'Bob', email: 'bob@test.com', age: 25 }
export const CAROL = { id: 'u3', name: 'Carol', email: 'carol@test.com', age: 35 }

const POST_A = { id: 'p1', title: 'Hello World', authorId: 'u1', published: 1 }
const POST_B = { id: 'p2', title: 'Second Post', authorId: 'u1', published: 0 }
const POST_C = { id: 'p3', title: 'Bobs Post', authorId: 'u2', published: 1 }

/** Create an in-memory test database with the standard test schema. */
export function createTestDatabase(options?: {
	readonly on?: EmitterHooks<DatabaseEventMap>
}): DatabaseInterface<TestSchema> {
	return createDatabase<TestSchema>({
		driver: new SqliteDriver({ path: ':memory:' }),
		name: 'test',
		version: 1,
		tables: TEST_TABLES,
		on: options?.on,
	})
}

/** Seed the database with standard test data. */
export async function seed(db: DatabaseInterface<TestSchema>): Promise<void> {
	await db.table('users').set([ALICE, BOB, CAROL])
	await db.table('posts').set([POST_A, POST_B, POST_C])
}

// === SQLite Driver Test Helpers

/**
 * Create a connected in-memory SQLite driver with a 'users' table.
 * Uses the minimal driver test schema (id, name, age).
 */
export async function createTestSqliteDriver(): Promise<SqliteDriver> {
	const driver = new SqliteDriver({ path: ':memory:' })
	await driver.connect()
	await driver.execute(compileTable('users', DRIVER_TABLE_DEF))
	return driver
}
// === Test Port Allocation

let nextPort = 19000
let tempPathCounter = 0

/**
 * Allocate a unique port number for test servers.
 * Each call returns the next available port in a high range to avoid conflicts.
 */
export function allocatePort(): number {
	return nextPort++
}

export function createTempPath(prefix = 'server-test', extension = '.json'): string {
	tempPathCounter += 1
	return join(tmpdir(), `${prefix}-${Date.now()}-${tempPathCounter}${extension}`)
}

export function createTempTreePath(prefix = 'server-test', fileName = 'data.json'): string {
	tempPathCounter += 1
	return join(tmpdir(), `${prefix}-${Date.now()}-${tempPathCounter}`, 'nested', fileName)
}

export async function destroyPath(path: string): Promise<void> {
	try {
		await rm(path, { recursive: true, force: true })
	} catch {
		// Ignore cleanup failures for temporary test paths.
	}
}

// === IncomingMessage Factory

/**
 * Create a minimal IncomingMessage for unit tests.
 * Uses a real IncomingMessage backed by an unconnected Socket.
 */
export function createIncomingMessage(
	overrides?: Partial<Pick<IncomingMessage, 'url' | 'method' | 'headers'>>,
): IncomingMessage {
	const socket = new Socket()
	const req = new HttpIncomingMessage(socket)
	req.method = overrides?.method ?? 'GET'
	req.url = overrides?.url ?? '/'
	req.headers = overrides?.headers ?? {}
	// Destroy the socket immediately — we only need the IncomingMessage shell
	socket.destroy()
	return req
}

// === ServerResponse Factory

interface TestResponse extends ServerResponse {
	readonly _statusCode: number
	readonly _headers: Record<string, string>
	readonly _body: string
}

function isTestResponse(value: unknown): value is TestResponse {
	if (!isObject(value)) return false
	return '_body' in value && '_statusCode' in value && '_headers' in value
}

/**
 * Create a minimal ServerResponse backed by a Writable stream.
 * Captures status, headers, and body for assertion.
 */
export function createServerResponse(): TestResponse {
	const chunks: Buffer[] = []
	const headers: Record<string, string> = {}
	let statusCode = 200

	const stream = new Writable({
		write(chunk, _encoding, callback) {
			chunks.push(Buffer.from(chunk))
			callback()
		},
	})

	Object.assign(stream, {
		statusCode,
		headersSent: false,
		_statusCode: statusCode,
		_headers: headers,
		_body: '',
		hasHeader: (name: string): boolean => {
			return name.toLowerCase() in headers
		},
		removeHeader: (name: string): void => {
			const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase())
			if (key !== undefined) delete headers[key]
		},
		writeHead: (status: number, resHeaders?: Record<string, string | number>) => {
			statusCode = status
			Object.assign(stream, { statusCode: status, _statusCode: status })
			if (resHeaders !== undefined) {
				for (const [key, val] of Object.entries(resHeaders)) {
					headers[key] = String(val)
				}
				Object.assign(stream, { _headers: headers })
			}
			return stream
		},
		setHeader: (name: string, value: string | number | readonly string[]) => {
			headers[name] = Array.isArray(value) ? value.join(', ') : String(value)
			Object.assign(stream, { _headers: headers })
			return stream
		},
		end: (data?: string | Buffer | (() => void)) => {
			if (!isFunction(data) && data !== undefined) chunks.push(Buffer.from(data))
			const body = Buffer.concat(chunks).toString()
			Object.assign(stream, { _body: body })
		},
	})

	return stream as unknown as TestResponse
}

/**
 * Read the captured body from a test response.
 */
export function responseBody(response: ServerResponse): string {
	if (isTestResponse(response)) return response._body
	return ''
}

/**
 * Read the captured status code from a test response.
 */
export function responseStatus(response: ServerResponse): number {
	if (isTestResponse(response)) return response._statusCode
	return 200
}

function responseJson(response: ServerResponse): unknown {
	return JSON.parse(responseBody(response))
}

function responseData(response: ServerResponse): unknown {
	const body = responseJson(response)
	if (!isRecord(body)) {
		throw new Error('Expected JSON envelope record')
	}
	if (!('data' in body)) {
		throw new Error('Expected response data payload')
	}
	return body['data']
}

export function responseRecord(response: ServerResponse): Record<string, unknown> {
	const data = responseData(response)
	if (!isRecord(data)) {
		throw new Error('Expected response record payload')
	}
	return data
}

export function responseList(response: ServerResponse): {
	readonly items: readonly unknown[]
	readonly total: number
} {
	const data = responseData(response)
	if (!isRecord(data)) {
		throw new Error('Expected response list payload')
	}
	const items = data['items']
	const total = data['total']
	if (!Array.isArray(items) || typeof total !== 'number') {
		throw new Error('Expected response list shape')
	}
	return { items, total }
}

/**
 * Read the captured response headers from a test response.
 */
export function responseHeaders(response: ServerResponse): Record<string, string> {
	if (isTestResponse(response)) return response._headers
	return {}
}

// === Server Factory

/**
 * Create a real Server instance for testing.
 * Returns an idle Server with all managers wired up.
 */
export function createTestServer(): ServerInterface {
	return new Server({ port: 0, timeout: 1000 })
}

// === RouteHandlerContext Factory

/**
 * Create a minimal RouteHandlerContext for testing route handlers and middleware.
 * Uses `createIncomingMessage` and `createServerResponse` for request/response.
 */
export function createHandlerContext(
	method = 'GET',
	url = '/',
	overrides?: Partial<RouteHandlerContext>,
): RouteHandlerContext {
	return {
		request: createIncomingMessage({ method, url }),
		response: createServerResponse(),
		server: createTestServer(),
		params: {},
		query: {},
		body: undefined,
		state: {},
		...overrides,
	}
}

export function createAppRouteContext(
	app: AppContext,
	options?: {
		readonly body?: unknown
		readonly method?: string
		readonly params?: Record<string, string>
		readonly query?: Record<string, string>
		readonly url?: string
	},
): RouteHandlerContext {
	return createHandlerContext(options?.method ?? 'GET', options?.url ?? '/', {
		body: options?.body,
		params: options?.params ?? {},
		query: options?.query ?? {},
		state: { app },
	})
}

export async function withAppContext<T>(
	execute: (app: AppContext) => Promise<T>,
	prefix = 'app-handler',
): Promise<T> {
	const path = createTempPath(prefix, '.db')
	const app = await createAppContext({ database: { path } })

	try {
		return await execute(app)
	} finally {
		app.database.destroy()
		await destroyPath(path)
	}
}

export async function seedAccount(
	app: AppContext,
	options?: {
		readonly id?: string
		readonly name?: string
	},
) {
	const row = createSeededAccount({
		input: {
			name: options?.name ?? 'Account',
			account_type: 'commercial',
		},
		record: options?.id === undefined ? undefined : { id: options.id },
	})
	await app.database.table('accounts').set(row)
	return row
}

export async function seedLocation(app: AppContext, accountId: string) {
	const row = createSeededLocation({ input: { account_id: accountId, city: 'Miami', state: 'FL' } })
	await app.database.table('locations').set(row)
	return row
}

export async function seedPolicy(
	app: AppContext,
	accountId: string,
	options?: {
		readonly policyNumber?: string
	},
) {
	const row = createSeededPolicy({
		input: {
			account_id: accountId,
			policy_number: options?.policyNumber,
			status: 'active',
		},
	})
	await app.database.table('policies').set(row)
	return row
}

export async function seedSubmission(app: AppContext, accountId: string) {
	const row = createSeededSubmission({ input: { account_id: accountId, status: 'new' } })
	await app.database.table('submissions').set(row)
	return row
}

export async function seedQuote(app: AppContext, accountId: string) {
	const row = createSeededQuote({ input: { account_id: accountId, quote_number: 'QT-1' } })
	await app.database.table('quotes').set(row)
	return row
}

export async function seedRepresentative(app: AppContext) {
	const row = createSeededRepresentative({
		input: {
			first_name: 'Jamie',
			last_name: 'Agent',
			email: 'jamie@test.com',
		},
	})
	await app.database.table('representatives').set(row)
	return row
}

// === Session Factory

/**
 * Create a Session and its backing SessionStore for testing.
 */
export function createTestSession(
	data: Record<string, unknown> = {},
	id = 'test-id',
	ttl = 3600,
): { session: Session; store: SessionStore } {
	const store = new SessionStore()
	const session = new Session(id, data, store, ttl)
	return { session, store }
}

// === UploadedFile Factory

/**
 * Create an UploadedFile for testing with sensible defaults.
 */
export function createTestFile(
	content = 'file-content',
	errors: string[] = [],
	field = 'avatar',
	name = 'photo.png',
	mime = 'image/png',
): UploadedFile {
	const buffer = Buffer.from(content)
	const tempPath = join(tmpdir(), `test-upload-${Date.now()}`)
	return new UploadedFile(field, name, mime, buffer, tempPath, true, errors)
}

// === Relation Test Schema

export type RelationSchema = {
	accounts: { id: string; name: string; classificationId: string }
	contacts: { id: string; name: string; accountId: string }
	classifications: { id: string; label: string }
	submissions: { id: string; title: string; accountId: string }
	policies: { id: string; number: string; submissionId: string }
	notes: { id: string; content: string; entityId: string; entityType: string }
	account_reps: { id: string; accountId: string; repId: string }
	reps: { id: string; name: string }
}

const RELATION_TABLES: TableDefinitions<RelationSchema> = {
	accounts: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'name', type: 'TEXT', nullable: false },
			{ name: 'classificationId', type: 'TEXT' },
		],
	},
	contacts: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'name', type: 'TEXT', nullable: false },
			{ name: 'accountId', type: 'TEXT', nullable: false },
		],
	},
	classifications: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'label', type: 'TEXT', nullable: false },
		],
	},
	submissions: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'title', type: 'TEXT', nullable: false },
			{ name: 'accountId', type: 'TEXT', nullable: false },
		],
	},
	policies: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'number', type: 'TEXT', nullable: false },
			{ name: 'submissionId', type: 'TEXT', nullable: false },
		],
	},
	notes: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'content', type: 'TEXT', nullable: false },
			{ name: 'entityId', type: 'TEXT', nullable: false },
			{ name: 'entityType', type: 'TEXT', nullable: false },
		],
	},
	account_reps: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'accountId', type: 'TEXT', nullable: false },
			{ name: 'repId', type: 'TEXT', nullable: false },
		],
	},
	reps: {
		columns: [
			{ name: 'id', type: 'TEXT', primary: true },
			{ name: 'name', type: 'TEXT', nullable: false },
		],
	},
}

// Relation seed data

const CLASSIFICATION_COMMERCIAL = { id: 'cls1', label: 'Commercial' }
const CLASSIFICATION_PERSONAL = { id: 'cls2', label: 'Personal' }

export const ACCOUNT_ACME = { id: 'acc1', name: 'Acme Corp', classificationId: 'cls1' }
export const ACCOUNT_GLOBEX = { id: 'acc2', name: 'Globex Inc', classificationId: 'cls2' }

export const CONTACT_JOHN = { id: 'con1', name: 'John', accountId: 'acc1' }
const CONTACT_JANE = { id: 'con2', name: 'Jane', accountId: 'acc1' }
export const CONTACT_MIKE = { id: 'con3', name: 'Mike', accountId: 'acc2' }

export const SUBMISSION_ONE = { id: 'sub1', title: 'Renewal 2025', accountId: 'acc1' }
export const SUBMISSION_TWO = { id: 'sub2', title: 'New Business', accountId: 'acc2' }

const POLICY_ALPHA = { id: 'pol1', number: 'POL-001', submissionId: 'sub1' }

const NOTE_ACC = {
	id: 'n1',
	content: 'Account note',
	entityId: 'acc1',
	entityType: 'account',
}
const NOTE_CON = {
	id: 'n2',
	content: 'Contact note',
	entityId: 'con1',
	entityType: 'contact',
}
const NOTE_ACC2 = {
	id: 'n3',
	content: 'Second account note',
	entityId: 'acc1',
	entityType: 'account',
}

const REP_ALICE = { id: 'rep1', name: 'Alice' }
const REP_BOB = { id: 'rep2', name: 'Bob' }

const JUNCTION_1 = { id: 'ar1', accountId: 'acc1', repId: 'rep1' }
const JUNCTION_2 = { id: 'ar2', accountId: 'acc1', repId: 'rep2' }
const JUNCTION_3 = { id: 'ar3', accountId: 'acc2', repId: 'rep1' }

/** Create an in-memory test database with the relation test schema. */
export function createRelationDatabase(): DatabaseInterface<RelationSchema> {
	return createDatabase<RelationSchema>({
		driver: new SqliteDriver({ path: ':memory:' }),
		name: 'relation-test',
		version: 1,
		tables: RELATION_TABLES,
	})
}

/** Seed the relation test database with standard data. */
export async function seedRelations(db: DatabaseInterface<RelationSchema>): Promise<void> {
	await db.table('classifications').set([CLASSIFICATION_COMMERCIAL, CLASSIFICATION_PERSONAL])
	await db.table('accounts').set([ACCOUNT_ACME, ACCOUNT_GLOBEX])
	await db.table('contacts').set([CONTACT_JOHN, CONTACT_JANE, CONTACT_MIKE])
	await db.table('submissions').set([SUBMISSION_ONE, SUBMISSION_TWO])
	await db.table('policies').set([POLICY_ALPHA])
	await db.table('notes').set([NOTE_ACC, NOTE_CON, NOTE_ACC2])
	await db.table('reps').set([REP_ALICE, REP_BOB])
	await db.table('account_reps').set([JUNCTION_1, JUNCTION_2, JUNCTION_3])
}

/** Create a seeded relation manager with standard model definitions. */
export async function createRelationTestManager(): Promise<{
	readonly database: DatabaseInterface<RelationSchema>
	readonly manager: RelationManagerInterface
}> {
	const database = createRelationDatabase()
	await seedRelations(database)

	const manager = createRelationManager({
		database: database as unknown as DatabaseInterface<
			Record<string, Record<string, string | number | boolean | null | Uint8Array>>
		>,
	})

	manager.define<RelationSchema['accounts']>('accounts', {
		classification: { column: 'classificationId', model: 'classifications' },
		contacts: ['accountId'],
		submissions: ['accountId'],
		notes: { key: 'entityId', tag: 'entityType', label: 'account', model: 'notes' },
		reps: { through: 'account_reps', source: 'accountId', target: 'repId', model: 'reps' },
	})

	manager.define<RelationSchema['contacts']>('contacts', {
		account: { column: 'accountId', model: 'accounts' },
		notes: { key: 'entityId', tag: 'entityType', label: 'contact', model: 'notes' },
	})

	manager.define<RelationSchema['classifications']>('classifications', {
		accounts: ['classificationId'],
	})

	manager.define<RelationSchema['submissions']>('submissions', {
		account: { column: 'accountId', model: 'accounts' },
		policy: { key: 'submissionId', model: 'policies' },
	})

	manager.define<RelationSchema['policies']>('policies', {
		submission: { column: 'submissionId', model: 'submissions' },
	})

	manager.define<RelationSchema['notes']>('notes', {})

	manager.define<RelationSchema['reps']>('reps', {
		accounts: { through: 'account_reps', source: 'repId', target: 'accountId', model: 'accounts' },
	})

	return { database, manager }
}

// === Browser Test Helpers

/**
 * Launch a headless Chromium browser for unit tests via CDP.
 *
 * Use in `beforeAll` / `afterAll` pairs.
 *
 * @returns Connected BrowserInterface instance
 */
export async function launchTestBrowser(): Promise<BrowserInterface> {
	const browser = createBrowser({
		headless: true,
		args: ['--no-sandbox'],
		executable: process.env['CHROME_EXECUTABLE_PATH'],
	})
	await browser.connect()
	return browser
}

/**
 * Create a new isolated browser context within an existing test browser.
 *
 * @param browser - BrowserInterface to create the context in
 * @returns The first BrowserContextInterface
 */
export async function createTestContext(
	browser: BrowserInterface,
): Promise<BrowserContextInterface> {
	const ctx = browser.context()
	if (ctx !== undefined) return ctx

	// Create a page to ensure a context exists
	await browser.create()
	const created = browser.context()
	if (created === undefined) {
		throw new Error('Failed to create test browser context')
	}
	return created
}

// === MCP Test Helpers

/** Builds a JSON-RPC request string */
export function jsonRpcRequest(
	method: string,
	id: number | string,
	params?: Record<string, unknown>,
): string {
	return JSON.stringify({
		jsonrpc: '2.0',
		method,
		id,
		...(params !== undefined ? { params } : {}),
	})
}

/** Builds a JSON-RPC notification string (no id) */
export function jsonRpcNotification(method: string): string {
	return JSON.stringify({
		jsonrpc: '2.0',
		method,
	})
}

// === Filesystem Helpers

/** Result of creating a sandbox-backed test directory */
export interface TestDir {
	readonly root: string
	readonly sandbox: SandboxInterface
}

/**
 * Creates a sandbox-backed temporary directory pre-populated with files.
 *
 * @param files - Record of relative path to content
 * @returns A TestDir with the root path and sandbox reference
 */
export async function createTestDir(files: Record<string, string> = {}): Promise<TestDir> {
	const sb = await createSandbox({ symlinkNodeModules: false })
	for (const [relativePath, content] of Object.entries(files)) {
		await sb.write(relativePath, content)
	}
	return { root: sb.root, sandbox: sb }
}

/** Cleans up a test directory created by createTestDir */
export async function destroyTestDir(dir: TestDir): Promise<void> {
	await dir.sandbox.destroy()
}

/**
 * Runs a callback with a sandbox-backed temporary directory, then cleans up.
 *
 * @param files - Record of relative path to content
 * @param fn - Callback receiving the root path and sandbox
 * @returns The callback's return value
 */
export async function withTestDir<T>(
	files: Record<string, string>,
	fn: (dir: TestDir) => Promise<T> | T,
): Promise<T> {
	const dir = await createTestDir(files)
	try {
		return await fn(dir)
	} finally {
		await destroyTestDir(dir)
	}
}

/** Create standard seal options for tests with a silent reporter. */
export function createSealOptions(overrides?: Partial<SealOptions>): SealOptions {
	return {
		name: 'seal-test',
		entry: 'entry.cjs',
		output: 'dist',
		...overrides,
	}
}

/** Create standard injector options for tests. */
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

/** Reads a file from a directory, returns its content */
export function readFromDisk(dir: string, relativePath: string): string {
	return fs.readFileSync(nodePath.join(dir, relativePath), 'utf-8')
}

/** Checks whether a path exists on disk */
export function existsOnDisk(dir: string, relativePath: string): boolean {
	return fs.existsSync(nodePath.join(dir, relativePath))
}

/** Builds a minimal quantitative definition for testing */
export function testDef(id: string, value: number): QuantitativeDefinition {
	return {
		type: 'quantitative',
		id,
		name: `Test ${id}`,
		groups: [
			{
				id: 'g1',
				label: 'g1',
				aggregation: 'sum',
				factors: [{ id: 'f1', label: 'f1', source: { kind: 'static', value } }],
			},
		],
		aggregation: 'sum',
	}
}

/** Builds an MCPStoreEntry from an id and value */
export function testEntry(
	id: string,
	value: number,
): { id: string; data: Record<string, unknown> } {
	const def = testDef(id, value)
	const data: Record<string, unknown> = {}
	for (const [k, v] of Object.entries(def)) {
		data[k] = v
	}
	return { id, data }
}

/** Writes a JSON file to a directory */
export function writeJson(dir: string, filename: string, content: unknown): void {
	fs.writeFileSync(nodePath.join(dir, filename), JSON.stringify(content), 'utf8')
}

/** Creates an MCPStoreManager with stores for the given directories */
export function storesFor(...dirs: { path: string; writable?: boolean }[]): MCPStoreManager {
	const manager = new MCPStoreManager()
	for (const dir of dirs) {
		manager.create(dir)
	}
	return manager
}

/** Extracts value from a quantitative result — throws if wrong type */
export function quantitativeValue(result: unknown): number {
	const record = result as Record<string, unknown>
	if (record['type'] !== 'quantitative' || typeof record['value'] !== 'number') {
		throw new Error('Expected a quantitative result with a numeric value')
	}
	return record['value']
}

// === JS/TS Definition File Helpers

/** Writes a JS definition file using static export default */
export function writeJsDef(dir: string, filename: string, id: string, value: number): void {
	const content = `export default {
  type: "quantitative",
  id: "${id}",
  name: "Test ${id}",
  groups: [{
    id: "g1",
    label: "g1",
    aggregation: "sum",
    factors: [{ id: "f1", label: "f1", source: { kind: "static", value: ${value} } }],
  }],
  aggregation: "sum",
};
`
	fs.writeFileSync(nodePath.join(dir, filename), content, 'utf8')
}

/** Writes a JS definition file using a provider function */
export function writeJsProviderDef(dir: string, filename: string, id: string, value: number): void {
	const content = `export default function() {
  return {
    type: "quantitative",
    id: "${id}",
    name: "Provider ${id}",
    groups: [{
      id: "g1",
      label: "g1",
      aggregation: "sum",
      factors: [{ id: "f1", label: "f1", source: { kind: "static", value: ${value} } }],
    }],
    aggregation: "sum",
  };
}
`
	fs.writeFileSync(nodePath.join(dir, filename), content, 'utf8')
}

/** Writes a JS file with invalid default export */
export function writeInvalidJsDef(dir: string, filename: string): void {
	const content = `export default { foo: "bar" };\n`
	fs.writeFileSync(nodePath.join(dir, filename), content, 'utf8')
}

/** Writes a JS file with no default export */
export function writeNoDefaultJs(dir: string, filename: string): void {
	const content = `export const x = 42;\n`
	fs.writeFileSync(nodePath.join(dir, filename), content, 'utf8')
}

/** Writes a JS file with a syntax error */
export function writeBrokenJs(dir: string, filename: string): void {
	const content = `export default {{{invalid\n`
	fs.writeFileSync(nodePath.join(dir, filename), content, 'utf8')
}

// === MCP Client ↔ Server Bridge

/** Parses a JSON-RPC body from a fetch RequestInit */
export function parseJsonRpcBody(init: RequestInit | undefined): unknown {
	const bodyText = typeof init?.body === 'string' ? init.body : ''
	return JSON.parse(bodyText)
}

/** Extracts headers as a plain record from a fetch RequestInit */
export function extractHeaders(init: RequestInit | undefined): Record<string, string> {
	const headers = init?.headers
	if (typeof headers === 'object' && headers !== null && !Array.isArray(headers)) {
		const result: Record<string, string> = {}
		for (const [k, v] of Object.entries(headers)) {
			if (typeof v === 'string') result[k] = v
		}
		return result
	}
	return {}
}

/**
 * Creates a `fetch` implementation backed by a real MCPServer.
 */
export function createServerFetch(server: MCPServerInterface): {
	fetch: typeof globalThis.fetch
	sessionId: string
	calls: { method: string; url: string; headers: Record<string, string> }[]
} {
	const sessionId = 'session-' + Math.random().toString(36).slice(2)
	const calls: { method: string; url: string; headers: Record<string, string> }[] = []

	const mockFetch: typeof globalThis.fetch = async (
		input: string | URL | Request,
		init?: RequestInit,
	): Promise<Response> => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
		const method = init?.method ?? 'GET'
		const headers = extractHeaders(init)
		calls.push({ method, url, headers })

		if (method === 'DELETE') {
			return new Response(null, { status: 200 })
		}

		let parsed: unknown
		try {
			parsed = parseJsonRpcBody(init)
		} catch {
			return new Response(
				JSON.stringify({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } }),
				{ status: 400, headers: { 'Content-Type': 'application/json' } },
			)
		}

		if (typeof parsed !== 'object' || parsed === null) {
			return new Response(
				JSON.stringify({ jsonrpc: '2.0', error: { code: -32600, message: 'Invalid request' } }),
				{ status: 400, headers: { 'Content-Type': 'application/json' } },
			)
		}

		// Handle batch arrays: process each request individually
		if (Array.isArray(parsed)) {
			const responses = []
			for (const item of parsed) {
				const response = await server.handle(JSON.stringify(item))
				if (response !== undefined) {
					responses.push(response)
				}
			}
			return new Response(JSON.stringify(responses), {
				status: 200,
				headers: {
					'Content-Type': 'application/json',
					'MCP-Session-Id': sessionId,
				},
			})
		}

		const body = parsed as Record<string, unknown>
		const messageMethod = body.method

		if (body.id === undefined && typeof messageMethod === 'string') {
			return new Response(null, {
				status: 202,
				headers: { 'MCP-Session-Id': sessionId },
			})
		}

		const message = typeof init?.body === 'string' ? init.body : JSON.stringify(parsed)
		const response = await server.handle(message)

		if (response === undefined) {
			return new Response(null, {
				status: 202,
				headers: { 'MCP-Session-Id': sessionId },
			})
		}

		return new Response(JSON.stringify(response), {
			status: 200,
			headers: {
				'Content-Type': 'application/json',
				'MCP-Session-Id': sessionId,
			},
		})
	}

	return { fetch: mockFetch, sessionId, calls }
}

// === Stream Helpers

/** Reads all buffered content from a PassThrough stream and returns it as a string */
export function readOutput(output: PassThrough): string {
	const chunks: Buffer[] = []
	let chunk = output.read()
	while (chunk !== null) {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
		chunk = output.read()
	}
	return stripAnsi(Buffer.concat(chunks).toString('utf8'))
}

/** Creates a Terminal with injectable PassThrough streams for testing */
export function createTestTerminal(): {
	terminal: TerminalFormInterface
	input: PassThrough
	output: PassThrough
} {
	const input = new PassThrough()
	const output = new PassThrough()
	const terminal = new Terminal({ input, output })
	return { terminal, input, output }
}

// === Server Test Helpers

/** Standard HTTP response shape returned by all request helpers */
interface HttpResponse {
	readonly status: number
	readonly headers: Record<string, string>
	readonly body: string
}

/** A real HTTP test server with convenience methods */
interface TestHttpServer {
	readonly http: HttpServer
	readonly port: number
	readonly captured: readonly { readonly req: IncomingMessage; readonly res: ServerResponse }[]
	get(path: string, headers?: Record<string, string>): Promise<HttpResponse>
	post(path: string, payload: unknown): Promise<HttpResponse>
	raw(
		method: string,
		path: string,
		body: string,
		headers?: Record<string, string>,
	): Promise<HttpResponse>
	sse(path: string): Promise<HttpResponse>
	sseUntil(path: string, target: string, timeout?: number): Promise<HttpResponse>
	cleanup(): Promise<void>
}

/**
 * Start a real HTTP test server.
 *
 * @param handler - Request handler. When omitted, responds 200 OK.
 * @returns TestHttpServer with request helpers
 */
async function createTestHttpServer(
	handler?: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<TestHttpServer> {
	const captured: { readonly req: IncomingMessage; readonly res: ServerResponse }[] = []

	const http = createHttpServer((req, res) => {
		captured.push({ req, res })
		if (handler !== undefined) {
			handler(req, res)
		} else {
			res.writeHead(200)
			res.end('OK')
		}
	})

	const port = await new Promise<number>((resolve) => {
		http.listen(0, '127.0.0.1', () => {
			const addr = http.address()
			resolve(typeof addr === 'object' && addr !== null ? addr.port : 0)
		})
	})

	function makeRequest(
		method: string,
		path: string,
		headers: Record<string, string>,
		body?: string,
	): Promise<HttpResponse> {
		return new Promise((resolve, reject) => {
			const req = request({ hostname: '127.0.0.1', port, method, path, headers }, (res) => {
				let data = ''
				res.on('data', (chunk: Buffer) => {
					data += chunk.toString()
				})
				res.on('end', () => {
					const headerMap: Record<string, string> = {}
					for (const [key, value] of Object.entries(res.headers)) {
						if (typeof value === 'string') {
							headerMap[key] = value
						}
					}
					resolve({ status: res.statusCode ?? 0, headers: headerMap, body: data })
				})
			})
			req.on('error', reject)
			if (body !== undefined) {
				req.write(body)
			}
			req.end()
		})
	}

	function readSse(path: string): Promise<HttpResponse> {
		return new Promise((resolve) => {
			const req = request(
				{ hostname: '127.0.0.1', port, method: 'GET', path },
				(res: IncomingMessage) => {
					const headerMap: Record<string, string> = {}
					for (const [key, value] of Object.entries(res.headers)) {
						if (typeof value === 'string') {
							headerMap[key] = value
						}
					}
					let data = ''
					let resolved = false
					const finish = () => {
						if (resolved) return
						resolved = true
						req.destroy()
						resolve({ status: res.statusCode ?? 0, headers: headerMap, body: data })
					}
					res.on('data', (chunk: Buffer) => {
						data += chunk.toString()
						finish()
					})
					res.on('end', finish)
					setTimeout(finish, 200)
				},
			)
			req.on('error', () => {
				/* ignore ECONNRESET from destroy */
			})
			req.end()
		})
	}

	function readSseUntil(path: string, target: string, timeout = 2000): Promise<HttpResponse> {
		return new Promise((resolve) => {
			let data = ''
			let resolved = false
			const headerMap: Record<string, string> = {}

			const finish = () => {
				if (resolved) return
				resolved = true
				clearTimeout(timer)
				req.destroy()
				resolve({ status: 200, headers: headerMap, body: data })
			}

			const req = request(
				{ hostname: '127.0.0.1', port, method: 'GET', path },
				(res: IncomingMessage) => {
					for (const [key, value] of Object.entries(res.headers)) {
						if (typeof value === 'string') {
							headerMap[key] = value
						}
					}
					res.on('data', (chunk: Buffer) => {
						data += chunk.toString()
						if (data.includes(target)) {
							finish()
						}
					})
					res.on('end', finish)
				},
			)
			req.on('error', () => {})
			req.end()

			const timer = setTimeout(finish, timeout)
		})
	}

	return {
		http,
		port,
		captured,
		async get(path, headers = {}) {
			return makeRequest('GET', path, headers)
		},
		async post(path, payload) {
			return makeRequest(
				'POST',
				path,
				{ 'Content-Type': 'application/json' },
				JSON.stringify(payload),
			)
		},
		async raw(method, path, body, headers = {}) {
			return makeRequest(method, path, headers, body)
		},
		async sse(path) {
			return readSse(path)
		},
		async sseUntil(path, target, timeout) {
			return readSseUntil(path, target, timeout)
		},
		async cleanup() {
			await new Promise<void>((resolve) => {
				http.close(() => resolve())
			})
		},
	}
}

// === Transport Test Helpers

/** Builds a JSON-RPC response object */
export function jsonRpcResponse(id: string | number | null, result: unknown): JsonRpcResponse {
	return { jsonrpc: '2.0', id, result }
}

/** Builds a JSON-RPC error response object */
/** Creates an HTTP POST request for HTTPServerTransport testing */
export function mcpPostRequest(body: unknown, headers?: Record<string, string>): Request {
	return new Request('http://localhost/mcp', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json, text/event-stream',
			...headers,
		},
		body: JSON.stringify(body),
	})
}

/** Creates an HTTP GET request for SSE stream testing */
export function mcpGetRequest(headers?: Record<string, string>): Request {
	return new Request('http://localhost/mcp', {
		method: 'GET',
		headers: {
			Accept: 'text/event-stream',
			...headers,
		},
	})
}

/** Creates an HTTP DELETE request for session teardown testing */
export function mcpDeleteRequest(headers?: Record<string, string>): Request {
	return new Request('http://localhost/mcp', {
		method: 'DELETE',
		headers: headers ?? {},
	})
}

/** Reads and parses a JSON response body */
export async function readJsonBody(response: Response): Promise<unknown> {
	return JSON.parse(await response.text())
}

/**
 * Reads SSE events from a response stream with a safety timeout.
 *
 * @param response - the SSE response
 * @param timeoutMs - max time to wait for the stream to close (default: 2000ms)
 * @returns parsed JSON-RPC messages from the SSE data lines
 */
export async function readSSEEvents(
	response: Response,
	timeoutMs = 2000,
): Promise<readonly JsonRpcMessage[]> {
	const body = response.body
	if (!body) return []

	const reader = body.getReader()
	const decoder = new TextDecoder()
	const events: JsonRpcMessage[] = []
	let buffer = ''

	const timeout = new Promise<void>((_, reject) => {
		setTimeout(() => reject(new Error(`readSSEEvents timed out after ${timeoutMs}ms`)), timeoutMs)
	})

	const read = async (): Promise<void> => {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			buffer += decoder.decode(value, { stream: true })
			const blocks = buffer.split('\n\n')
			buffer = blocks.pop() ?? ''
			for (const block of blocks) {
				for (const line of block.split('\n')) {
					const data = line.startsWith('data: ')
						? line.slice(6)
						: line.startsWith('data:')
							? line.slice(5)
							: undefined
					if (data !== undefined && data.length > 0) {
						try {
							const parsed = parseJsonRpcMessage(JSON.parse(data))
							if (parsed) events.push(parsed)
						} catch {
							// skip malformed
						}
					}
				}
			}
		}
	}

	try {
		await Promise.race([read(), timeout])
	} catch {
		reader.releaseLock()
	}

	return events
}

/** SSE event with optional event ID for resumability testing */
interface SSEEventWithId {
	readonly eventId: string | undefined
	readonly message: JsonRpcMessage
}

/**
 * Reads SSE events from a response stream, capturing event IDs.
 *
 * @param response - the SSE response
 * @param timeoutMs - max time to wait for the stream to close (default: 2000ms)
 * @returns SSE events with their assigned IDs
 */
export async function readSSEEventsWithIds(
	response: Response,
	timeoutMs = 2000,
): Promise<readonly SSEEventWithId[]> {
	const body = response.body
	if (!body) return []

	const reader = body.getReader()
	const decoder = new TextDecoder()
	const events: SSEEventWithId[] = []
	let buffer = ''

	const timeout = new Promise<void>((_, reject) => {
		setTimeout(
			() => reject(new Error(`readSSEEventsWithIds timed out after ${timeoutMs}ms`)),
			timeoutMs,
		)
	})

	const read = async (): Promise<void> => {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			buffer += decoder.decode(value, { stream: true })
			const blocks = buffer.split('\n\n')
			buffer = blocks.pop() ?? ''
			for (const block of blocks) {
				let data = ''
				let eventId: string | undefined
				for (const line of block.split('\n')) {
					if (line.startsWith('data: ')) {
						data += line.slice(6)
					} else if (line.startsWith('data:')) {
						data += line.slice(5)
					} else if (line.startsWith('id: ')) {
						eventId = line.slice(4)
					} else if (line.startsWith('id:')) {
						eventId = line.slice(3).trimStart()
					}
				}
				if (data.length > 0) {
					try {
						const parsed = parseJsonRpcMessage(JSON.parse(data))
						if (parsed) events.push({ eventId, message: parsed })
					} catch {
						// skip malformed
					}
				}
			}
		}
	}

	try {
		await Promise.race([read(), timeout])
	} catch {
		reader.releaseLock()
	}

	return events
}

interface HTTPClientTransportRequest {
	readonly url: string
	readonly method: string
	readonly headers: Record<string, string>
	readonly body: string
}

interface HTTPClientTransportResponse {
	readonly status: number
	readonly headers?: Record<string, string>
	readonly body?: string
	readonly delay?: number
	readonly pending?: boolean
}

export interface HTTPClientTransportHarness {
	readonly url: string
	readonly requests: readonly HTTPClientTransportRequest[]
	readonly count: number
	readonly last: HTTPClientTransportRequest | undefined
	enqueue(response: HTTPClientTransportResponse): void
	cleanup(): Promise<void>
}

function normalizeIncomingHeaders(headers: IncomingMessage['headers']): Record<string, string> {
	const normalized: Record<string, string> = {}
	for (const [key, value] of Object.entries(headers)) {
		if (typeof value === 'string') {
			normalized[key] = value
			continue
		}
		if (Array.isArray(value)) {
			normalized[key] = value.join(', ')
		}
	}
	return normalized
}

function readIncomingBody(incomingMessage: IncomingMessage): Promise<string> {
	return new Promise((resolve, reject) => {
		let body = ''
		incomingMessage.on('data', (chunk: Buffer | string) => {
			body += chunk.toString()
		})
		incomingMessage.on('end', () => resolve(body))
		incomingMessage.on('error', reject)
	})
}

export async function createHTTPClientTransportHarness(): Promise<HTTPClientTransportHarness> {
	const responses: HTTPClientTransportResponse[] = []
	const requests: HTTPClientTransportRequest[] = []
	const server = await createTestHttpServer((req, res) => {
		void readIncomingBody(req)
			.then((body) => {
				requests.push({
					url: `http://127.0.0.1:${server.port}${req.url ?? '/'}`,
					method: req.method ?? 'GET',
					headers: normalizeIncomingHeaders(req.headers),
					body,
				})

				const response = responses.shift()
				if (response === undefined) {
					res.writeHead(500, { 'Content-Type': 'text/plain' })
					res.end('No response queued')
					return
				}

				if (response.pending) {
					return
				}

				const send = () => {
					res.writeHead(response.status, response.headers)
					res.end(response.body)
				}

				if (typeof response.delay === 'number' && response.delay > 0) {
					setTimeout(send, response.delay)
					return
				}

				send()
			})
			.catch((error: unknown) => {
				res.writeHead(500, { 'Content-Type': 'text/plain' })
				res.end(error instanceof Error ? error.message : String(error))
			})
	})

	return {
		url: `http://127.0.0.1:${server.port}/mcp`,
		requests,
		get count() {
			return requests.length
		},
		get last() {
			return requests[requests.length - 1]
		},
		enqueue(response) {
			responses.push(response)
		},
		async cleanup() {
			await server.cleanup()
		},
	}
}

export function createJSONTransportResponse(
	body: unknown,
	headers?: Record<string, string>,
	status = 200,
): HTTPClientTransportResponse {
	return {
		status,
		headers: {
			'Content-Type': 'application/json',
			...headers,
		},
		body: JSON.stringify(body),
	}
}

export function createSSETransportResponse(
	events: readonly unknown[],
	headers?: Record<string, string>,
): HTTPClientTransportResponse {
	const body = events.map((event) => `event: message\ndata: ${JSON.stringify(event)}\n\n`).join('')
	return {
		status: 200,
		headers: {
			'Content-Type': 'text/event-stream',
			...headers,
		},
		body,
	}
}

export function createAcceptedTransportResponse(
	headers?: Record<string, string>,
): HTTPClientTransportResponse {
	return {
		status: 202,
		headers,
	}
}

export function createThrownFetch(error: unknown): typeof globalThis.fetch {
	return async () => Promise.reject(error)
}

interface OllamaRequestRecord {
	readonly path: string
	readonly method: string
	readonly headers: Record<string, string>
	readonly body: Record<string, unknown>
}

interface OllamaResponseRecord {
	readonly status: number
	readonly headers?: Record<string, string>
	readonly body?: string
	readonly chunks?: readonly string[]
	readonly delay?: number
	readonly pending?: boolean
}

export interface OllamaTestServer {
	readonly url: string
	readonly requests: readonly OllamaRequestRecord[]
	enqueue(response: OllamaResponseRecord): void
	cleanup(): Promise<void>
}

export async function createOllamaTestServer(): Promise<OllamaTestServer> {
	const responses: OllamaResponseRecord[] = []
	const requests: OllamaRequestRecord[] = []
	const server = await createTestHttpServer((req, res) => {
		void readIncomingBody(req)
			.then((bodyText) => {
				const parsedBody: unknown = bodyText.length > 0 ? JSON.parse(bodyText) : {}
				if (!isRecord(parsedBody)) {
					throw new Error('Expected JSON record body')
				}
				requests.push({
					path: req.url ?? '/',
					method: req.method ?? 'GET',
					headers: normalizeIncomingHeaders(req.headers),
					body: { ...parsedBody },
				})

				const response = responses.shift()
				if (response === undefined) {
					res.writeHead(500, { 'Content-Type': 'text/plain' })
					res.end('No Ollama response queued')
					return
				}

				const send = () => {
					res.writeHead(response.status, response.headers)
					if (response.chunks !== undefined) {
						for (const chunk of response.chunks) {
							res.write(chunk)
						}
					} else if (response.body !== undefined) {
						res.write(response.body)
					}

					if (!response.pending) {
						res.end()
					}
				}

				if (typeof response.delay === 'number' && response.delay > 0) {
					setTimeout(send, response.delay)
					return
				}

				send()
			})
			.catch((error: unknown) => {
				res.writeHead(500, { 'Content-Type': 'text/plain' })
				res.end(error instanceof Error ? error.message : String(error))
			})
	})

	return {
		url: `http://127.0.0.1:${server.port}`,
		requests,
		enqueue(response) {
			responses.push(response)
		},
		async cleanup() {
			await server.cleanup()
		},
	}
}

export function createOllamaJSONResponse(
	body: unknown,
	status = 200,
	headers?: Record<string, string>,
): OllamaResponseRecord {
	return {
		status,
		headers: {
			'Content-Type': 'application/json',
			...headers,
		},
		body: JSON.stringify(body),
	}
}

export function createOllamaNDJSONResponse(
	lines: readonly unknown[],
	options?: {
		readonly status?: number
		readonly headers?: Record<string, string>
		readonly delay?: number
		readonly pending?: boolean
	},
): OllamaResponseRecord {
	return {
		status: options?.status ?? 200,
		headers: {
			'Content-Type': 'application/x-ndjson',
			...options?.headers,
		},
		chunks: lines.map((line) => `${JSON.stringify(line)}\n`),
		delay: options?.delay,
		pending: options?.pending,
	}
}

export const WEBSOCKET_TEST_TIMEOUT = 5_000

interface TestWebSocketFrame {
	readonly opcode: number
	readonly payload: Buffer
}

interface TestNodeWebSocketConnection {
	readonly client: Socket
	readonly socket: NodeWebSocketInterface
}

/** Create a masked client-to-server WebSocket text frame. */
export function createMaskedTextFrame(text: string): Buffer {
	const payload = Buffer.from(text, 'utf-8')
	const mask = randomBytes(4)
	let headerLength = 6
	if (payload.length > 125 && payload.length < 65_536) {
		headerLength += 2
	} else if (payload.length >= 65_536) {
		headerLength += 8
	}

	const frame = Buffer.alloc(headerLength + payload.length)
	frame[0] = 0x81

	let offset = 1
	if (payload.length < 126) {
		frame[offset] = 0x80 | payload.length
		offset += 1
	} else if (payload.length < 65_536) {
		frame[offset] = 0x80 | 126
		offset += 1
		frame.writeUInt16BE(payload.length, offset)
		offset += 2
	} else {
		frame[offset] = 0x80 | 127
		offset += 1
		frame.writeUInt32BE(0, offset)
		frame.writeUInt32BE(payload.length, offset + 4)
		offset += 8
	}

	mask.copy(frame, offset)
	offset += 4

	for (let index = 0; index < payload.length; index++) {
		const payloadByte = payload[index]
		const maskByte = mask[index % 4]
		if (payloadByte !== undefined && maskByte !== undefined) {
			frame[offset + index] = payloadByte ^ maskByte
		}
	}

	return frame
}

/** Create a masked client-to-server WebSocket close frame. */
export function createMaskedCloseFrame(code = 1000, reason = ''): Buffer {
	const payload = Buffer.alloc(2 + Buffer.byteLength(reason, 'utf-8'))
	payload.writeUInt16BE(code, 0)
	if (reason.length > 0) {
		Buffer.from(reason, 'utf-8').copy(payload, 2)
	}

	const mask = randomBytes(4)
	const frame = Buffer.alloc(6 + payload.length)
	frame[0] = 0x88
	frame[1] = 0x80 | payload.length
	mask.copy(frame, 2)

	for (let index = 0; index < payload.length; index++) {
		const payloadByte = payload[index]
		const maskByte = mask[index % 4]
		if (payloadByte !== undefined && maskByte !== undefined) {
			frame[6 + index] = payloadByte ^ maskByte
		}
	}

	return frame
}

/** Create a masked client-to-server WebSocket ping frame. */
export function createMaskedPingFrame(payload = ''): Buffer {
	const data = Buffer.from(payload, 'utf-8')
	const mask = randomBytes(4)
	const frame = Buffer.alloc(6 + data.length)
	frame[0] = 0x89
	frame[1] = 0x80 | data.length
	mask.copy(frame, 2)

	for (let index = 0; index < data.length; index++) {
		const payloadByte = data[index]
		const maskByte = mask[index % 4]
		if (payloadByte !== undefined && maskByte !== undefined) {
			frame[6 + index] = payloadByte ^ maskByte
		}
	}

	return frame
}

/** Parse an unmasked server-to-client WebSocket frame. */
export function parseServerFrame(data: Buffer): TestWebSocketFrame | undefined {
	if (data.length < 2) {
		return undefined
	}

	const firstByte = data[0]
	const secondByte = data[1]
	if (firstByte === undefined || secondByte === undefined) {
		return undefined
	}

	const opcode = firstByte & 0x0f
	let payloadLength = secondByte & 0x7f
	let offset = 2

	if (payloadLength === 126) {
		if (data.length < 4) {
			return undefined
		}
		payloadLength = data.readUInt16BE(offset)
		offset += 2
	} else if (payloadLength === 127) {
		if (data.length < 10) {
			return undefined
		}
		payloadLength = data.readUInt32BE(offset + 4)
		offset += 8
	}

	if (data.length < offset + payloadLength) {
		return undefined
	}

	return {
		opcode,
		payload: data.subarray(offset, offset + payloadLength),
	}
}

/** Read a single chunk from a socket with a timeout. */
export function readSocket(socket: Socket, timeout = WEBSOCKET_TEST_TIMEOUT): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			socket.off('data', onData)
			socket.off('error', onError)
			reject(new Error(`Socket read timed out after ${timeout}ms`))
		}, timeout)

		const onData = (chunk: Buffer): void => {
			clearTimeout(timer)
			socket.off('error', onError)
			resolve(chunk)
		}

		const onError = (error: Error): void => {
			clearTimeout(timer)
			socket.off('data', onData)
			reject(error)
		}

		socket.once('data', onData)
		socket.once('error', onError)
	})
}

/** Close an HTTP server and any upgraded sockets tracked by Node. */
export async function closeHttpServer(server: HttpServer): Promise<void> {
	server.closeAllConnections()
	await new Promise<void>((resolve) => {
		server.close(() => resolve())
	})
}

/** Start a real HTTP server suitable for WebSocket upgrade tests. */
export async function createUpgradeServer(): Promise<{
	readonly http: HttpServer
	readonly port: number
}> {
	const http = createHttpServer((_request, response) => {
		response.writeHead(404)
		response.end()
	})

	const port = await new Promise<number>((resolve) => {
		http.listen(0, '127.0.0.1', () => {
			const address = http.address()
			resolve(typeof address === 'object' && address !== null ? address.port : 0)
		})
	})

	return { http, port }
}

/** Open a real WebSocket upgrade connection and return both ends. */
export function connectNodeWebSocket(options: {
	readonly server: HttpServer
	readonly port: number
	readonly path?: string
	readonly subprotocol?: string
	readonly upgrade?: WebSocketUpgradeOptions
	readonly accept?: (socket: NodeWebSocketInterface, request: IncomingMessage) => void
}): Promise<TestNodeWebSocketConnection> {
	return new Promise((resolve, reject) => {
		let nodeSocket: NodeWebSocketInterface | undefined
		const timeout = setTimeout(() => {
			reject(new Error(`WebSocket upgrade timed out after ${WEBSOCKET_TEST_TIMEOUT}ms`))
		}, WEBSOCKET_TEST_TIMEOUT)

		const handler = createWebSocketUpgradeHandler((socket, incoming) => {
			nodeSocket = socket
			options.accept?.(socket, incoming)
		}, options.upgrade)

		options.server.once('upgrade', (incoming, socket: Duplex, head) => {
			handler(incoming, socket, head)
		})

		const headers: Record<string, string> = {
			Connection: 'Upgrade',
			Upgrade: 'websocket',
			'Sec-WebSocket-Key': randomBytes(16).toString('base64'),
			'Sec-WebSocket-Version': '13',
		}

		if (options.subprotocol !== undefined) {
			headers['Sec-WebSocket-Protocol'] = options.subprotocol
		}

		const clientRequest = request({
			hostname: '127.0.0.1',
			port: options.port,
			path: options.path ?? '/',
			headers,
		})

		clientRequest.on('upgrade', (_response, client) => {
			clearTimeout(timeout)
			if (nodeSocket === undefined) {
				client.destroy()
				reject(new Error('Server NodeWebSocket was not created'))
				return
			}

			resolve({ client, socket: nodeSocket })
		})

		clientRequest.on('error', (error) => {
			clearTimeout(timeout)
			reject(error)
		})

		clientRequest.end()
	})
}

/** Writes a JSON-RPC request line to a PassThrough stdin stream */
export function writeStdinRequest(
	stdin: PassThrough,
	method: string,
	id: number | string,
	params?: Record<string, unknown>,
): void {
	const payload = JSON.stringify({
		jsonrpc: '2.0',
		method,
		id,
		...(params !== undefined ? { params } : {}),
	})
	stdin.write(payload + '\n')
}

/** Writes a JSON-RPC notification line to a PassThrough stdin stream */
export function writeStdinNotification(stdin: PassThrough, method: string): void {
	stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n')
}

/** Collects stdout chunks from a PassThrough stream as strings */
export function collectOutput(stdout: PassThrough): string[] {
	const chunks: string[] = []
	stdout.on('data', (chunk: Buffer) => {
		chunks.push(chunk.toString())
	})
	return chunks
}
