# Bin — CLI Entry Points

> **Two entry points: `bin/mcp.ts` — pre-configured MCP server exposing all tools over stdio, Streamable HTTP (SSE), and WebSocket with prompt bridging and companion mode. `bin/serve.ts` — HTTP inference server that loads a GGUF model and serves a web-based chat interface. Build once, run anywhere.**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [How It Works](#how-it-works)
4. [Dual Transport](#dual-transport)
5. [Prompt Bridge](#prompt-bridge)
6. [Configuration](#configuration)
7. [Client Configuration](#client-configuration)
8. [API Reference](#api-reference)
9. [Inference Server](#inference-server)

---

## Introduction

### Value Proposition

The MCP entry point (`bin/mcp.ts`) is a ready-to-run MCP server that:

- **Triple transport** — stdio for IDE communication + Streamable HTTP (SSE) at `/mcp` + WebSocket upgrade at `/mcp` for real-time bidirectional clients
- **Registers all four reasoning engines** — quantitative, logical, symbolic, and inferential
- **Enables memory** — inline definitions are stored at runtime for reuse by `definitionId`
- **Enables disk persistence** — definitions saved with `persist: true` survive restarts
- **Supports file import** — the agent can import definitions from `.json`, `.js`, `.mjs`, `.ts`, `.mts` files via the `import` parameter
- **Exposes a filesystem tool** — in-memory file editing with scan, open, read, write, persist, and snapshot support
- **Exposes an interpret tool** — natural language interpretation with normalize, parse, clarify, format, and generate stages
- **Exposes an agent tool** — autonomous sub-agent orchestration backed by Ollama; delegates complex tasks to a child agent with access to all other tools
- **Exposes a sandbox tool** — on-disk isolated temporary directories with guarded file operations and sandboxed process execution
- **Exposes a prompt tool** — interactive user prompts bridged via SSE for stdio environments
- **Exposes a workflow tool** — declarative workflow tracking with phases, tasks, and lifecycle management
- **Starts an HTTP server** — for SSE-based MCP access and prompt bridging (default port 3001, configurable via `ORKESTREL_PORT`)
- **Built-in companion mode** — `--companion` flag turns the same binary into a prompt companion client (no separate `prompt.ts`)
- **Zero configuration** — works out of the box with sensible defaults

### When to Use MCP

| Scenario                                             | Use mcp | Use a custom server |
| ---------------------------------------------------- | ------- | ------------------- |
| Standard reasoning + filesystem + interpret over MCP | ✅      |                     |
| IDE integration (Copilot, Claude, Cursor)            | ✅      |                     |
| Quick setup with all four reasoners                  | ✅      |                     |
| Both stdio and SSE from a single process             | ✅      |                     |
| Custom tools beyond reasoning/filesystem/interpret   |         | ✅                  |
| Selective reasoner registration                      |         | ✅                  |

---

## Quick Start

```bash
# Build the project
```

# Start the MCP server (stdio + SSE)

npm run mcp

````

Or run the built output directly:

```bash
node dist/bin/mcp.js
````

The server starts listening on stdin/stdout for JSON-RPC 2.0 messages and starts an HTTP server at `http://localhost:3001` for SSE MCP access and prompt bridging.

### Single Executable Application (SEA)

Build a standalone `orkestrel.exe` (or `orkestrel` on Linux/macOS) that bundles everything into a single binary — no Node.js installation required on the target machine:

```bash
# Build first, then seal
npm run build
npm run seal
```

The sealed binary is output to `dist/sea/orkestrel.exe`. It supports all the same modes and flags:

```bash
# Server mode (default)
dist/sea/orkestrel.exe

# Companion mode
dist/sea/orkestrel.exe --companion --port 3001 --token abc123

# Verbose
dist/sea/orkestrel.exe --verbose
```

**SEA behavior differences:**

- **Path resolution** — storage paths (`.orkestrel/definitions/`, `.orkestrel/snapshots/`, etc.) resolve relative to the executable's directory, not a project root
- **Companion launch** — the sealed binary spawns itself with `--companion` instead of `node mcp.js --companion`
- **Status command** — the prompt tool's `status` operation returns the direct executable path (no `node` prefix)

### MCP client configuration with SEA

```json
{
	"servers": {
		"orkestrel": {
			"type": "stdio",
			"command": "C:/path/to/orkestrel.exe"
		}
	}
}
```

---

## How It Works

The entry point has two modes: **server mode** (default) and **companion mode** (`--companion`).

### Server Mode

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              bin/mcp.ts                                   │
│                                                                             │
│  1. Create Reason instance with all four reasoners                          │
│     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│     │ Quantitative │ │   Logical    │ │   Symbolic   │ │ Inferential  │    │
│     └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
│                                                                             │
│  2. Create store manager with one writable directory                         │
│     ┌──────────────────────────────────────────────────────────────────┐     │
│     │  .orkestrel/definitions/ (r/w — persisted definitions)          │     │
│     └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  3. Create ReasonTool with memory + persistence + stores                    │
│                                                                             │
│  4. Create FileSystem rooted at project root and wrap it in FileSystemTool  │
│                                                                             │
│  5. Create Interpret with a session and wrap it in an InterpretTool         │
│                                                                             │
│  6. Create AgentTool backed by Ollama with access to all tools              │
│                                                                             │
│  7. Create SandboxTool for on-disk isolated file operations                 │
│                                                                             │
│  8. Start HTTP server for SSE-based prompt bridging + MCP SSE               │
│                                                                             │
│  9. Create PromptTool with remote companion launch/status support           │
│                                                                             │
│ 10. Create WorkflowTool with declarative workflow tracking                  │
│                                                                             │
│ 11. Create TWO MCPServer instances (stdio + SSE) and start both             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Companion Mode

When launched with `--companion`, the script acts as a prompt companion client instead of a server:

```
node dist/bin/mcp.js --companion --port 3001 --token abc123
```

The companion connects to the SSE endpoint at `/api/prompts`, displays pending prompts in the terminal, collects user input, and POSTs answers back. This eliminates the need for a separate `prompt.ts` file.

### Step-by-Step (Server Mode)

**Step 1 — Reason instance.** All four reasoners are registered so the tool can handle any definition type without configuration.

**Step 2 — Store manager.** One writable directory is configured:

- `.orkestrel/definitions/` — Read-write. Runtime persistence directory. Definitions saved with `persist: true` or imported via `import` are written here as JSON files.

The path is resolved relative to the package root, not `process.cwd()`.

**Step 3 — ReasonTool.** The tool wraps the Reason instance and exposes it with a comprehensive description that guides LLM clients on when and how to use each reasoning type. The agent can import definitions from user-specified files via the `import` parameter.

**Step 4 — FileSystemTool.** A `FileSystem` instance is created with `root` set to the project root so the tool operates on the project directory. A separate `MCPStoreManager` is configured with `.orkestrel/snapshots/` for snapshot persistence — snapshots are automatically saved to disk and loaded on `init()`. The tool is wrapped with a description covering all 15 filesystem operations (scan, stat, search, open, read, write, prepend, append, remove, move, list, revert, persist, snapshot, restore).

**Step 5 — InterpretTool.** An `Interpret` instance is created with a unique session id and default templates. A `MCPStoreManager` is configured with `.orkestrel/templates/` for template persistence. The tool wraps the interpreter with operations for interpret, describe, normalize, parse, and templates.

**Step 6 — AgentTool.** An `OllamaProvider` is created with the configured model and URL. An `AgentManager` is created and wrapped in an `AgentTool` with access to the reason, filesystem, and interpret tools for sub-agent orchestration.

**Step 7 — SandboxTool.** A `SandboxTool` is created for on-disk isolated file operations and process execution. The tool manages multiple concurrent sandboxes with 12 operations (create, writeFile, readFile, readDir, ensureDir, ensureFile, remove, stat, exists, execute, cleanup, list).

**Step 8 — HTTP Server.** An HTTP server is started for SSE-based prompt bridging and MCP SSE access. The server exposes `GET /api/prompts` (SSE stream), `POST /api/prompts` (answer submission), and `/mcp` routes (GET, POST, DELETE) for Streamable HTTP MCP sessions. The server must start before the PromptTool is created because the allocated port and authentication token are needed for the remote companion configuration.

**Step 9 — PromptTool.** A `RemotePrompt` is created and wrapped in a `PromptTool` with remote companion support. The tool's `remote` configuration includes `connected()` (checks SSE connection count) and `launch()` (spawns `mcp.js --companion` in a new terminal). The agent controls companion lifecycle via the `status` and `launch` operations — no auto-spawn on startup.

**Step 10 — WorkflowTool.** A `WorkflowsManager` is created for declarative workflow tracking. Blocked tasks are bridged to the remote prompt system when a companion is connected.

**Step 11 — Dual MCPServer + Initialization.** Two MCPServer instances are created sharing the same tools:

- **stdio server** — default StdioTransport for IDE communication
- **SSE server** — HTTPServerTransport registered on the HTTP server at `/mcp`

`reasonTool.init()`, `filesystemTool.init()`, `interpretTool.init()`, `promptTool.init()`, and `workflowTool.init()` are awaited. Both servers are started — the stdio server listens on stdin/stdout while the SSE server accepts connections at `/mcp`.

---

## Dual Transport

The MCP entry point runs **two MCPServer instances** simultaneously, sharing the same tools:

```
┌──────────────────────────────────────────────────────────────────┐
│                         bin/mcp.ts                              │
│                                                                  │
│  ┌─────────────────────┐    ┌─────────────────────────────────┐  │
│  │   stdio MCPServer   │    │      SSE MCPServer              │  │
│  │   (StdioTransport)  │    │   (HTTPServerTransport)         │  │
│  │                     │    │                                 │  │
│  │   IDE connects here │    │   Additional clients connect    │  │
│  │   via mcp.json      │    │   at http://localhost:3001/mcp  │  │
│  │   stdio entry       │    │   via mcp.json SSE entry        │  │
│  └─────────┬───────────┘    └──────────────┬──────────────────┘  │
│            │                               │                     │
│            └───────────┐   ┌───────────────┘                     │
│                        ▼   ▼                                     │
│                 ┌──────────────┐                                  │
│                 │  Shared Tools │                                 │
│                 │  (7 tools)   │                                  │
│                 └──────────────┘                                  │
└──────────────────────────────────────────────────────────────────┘
```

### mcp.json Configuration

The stdio entry launches the process, which also starts the HTTP server. Streamable HTTP clients can separately connect to `http://localhost:3001/mcp` — no mcp.json entry needed for that.

```json
{
	"servers": {
		"orkestrel": {
			"type": "stdio",
			"command": "node",
			"args": ["${workspaceFolder}/dist/bin/mcp.js"]
		}
	}
}
```

The stdio entry is the primary (and only) way to launch orkestrel via mcp.json. The Streamable HTTP endpoint at `/mcp` is always available for programmatic access but most MCP clients do not yet support `type: "streamable-http"` in their configuration.

---

## Prompt Bridge

When the MCP server runs on stdio inside an IDE plugin, it has no terminal access.
The prompt bridge solves this by pairing two entities from the `prompt` package:

- **`RemotePrompt`** (server-side, in `mcp.ts`) — creates pending prompts that block
  until `answer()` is called, broadcasts events via SSE subscriptions.
- **`PromptClient`** (client-side, companion mode) — connects to the SSE endpoint,
  dispatches prompts to a local `Prompt`, and POSTs answers back.

### Companion Mode

The CLI companion is built into `mcp.ts` itself. When launched with `--companion`, it:

1. Displays a styled banner using `ICON_CHECK`, `ICON_WARNING`, `LABEL_BOLD`, `LABEL_CYAN`, and `SEPARATOR` from `@orkestrel/prompt`
2. Creates a `PromptClient` with auto-discovery via the port info file
3. Connects to the SSE endpoint at `/api/prompts`
4. Displays prompts in the terminal and collects user input
5. POSTs responses back to the server

```ts
// Companion mode is activated via --companion flag
node dist/bin/mcp.js --companion

// With explicit port and token
node dist/bin/mcp.js --companion --port 3002 --token abc123

// With verbose logging
node dist/bin/mcp.js --companion --verbose
```

The companion reads the port info file written by the server's `PortManager`,
extracts the port and authentication token, and passes both to the `PromptClient`.
All requests include the `x-orkestrel-token` header, which the server's
`tokenMiddleware()` validates before allowing access.

---

## Configuration

### CLI Flags

| Flag          | Short | Default | Description                           |
| ------------- | ----- | ------- | ------------------------------------- |
| `--verbose`   | `-v`  | `false` | Enable debug logging                  |
| `--companion` |       | `false` | Run as prompt companion client        |
| `--port`      | `-p`  |         | Port override (companion mode)        |
| `--url`       | `-u`  |         | URL override (companion mode)         |
| `--token`     | `-t`  |         | Authentication token (companion mode) |

### Paths

| Path                              | Purpose                                     | Writable |
| --------------------------------- | ------------------------------------------- | -------- |
| `.orkestrel/definitions/reason`   | Runtime persistence for saved defs          | Yes      |
| `.orkestrel/snapshots/filesystem` | Runtime persistence for file snapshots      | Yes      |
| `.orkestrel/templates/interpret`  | Runtime persistence for interpret templates | Yes      |
| `.orkestrel/templates/prompt`     | Runtime persistence for prompt templates    | Yes      |
| `.orkestrel/snapshots/workflow`   | Runtime persistence for workflow snapshots  | Yes      |

### Server Identity

| Property  | Value       |
| --------- | ----------- |
| `name`    | `orkestrel` |
| `version` | `0.0.1`     |

### Tools

| Tool           | Name         | Description                                             |
| -------------- | ------------ | ------------------------------------------------------- |
| ReasonTool     | `reason`     | Deterministic computation coprocessor (all 4 types)     |
| FileSystemTool | `filesystem` | In-memory filesystem for safe file editing              |
| InterpretTool  | `interpret`  | Natural language interpretation pipeline                |
| AgentTool      | `agent`      | Autonomous sub-agent orchestration backed by Ollama     |
| SandboxTool    | `sandbox`    | On-disk isolated directories with process execution     |
| PromptTool     | `prompt`     | Interactive user prompts with remote companion bridging |
| WorkflowTool   | `workflow`   | Declarative workflow tracking with phases and tasks     |

### ReasonTool Configuration

| Property      | Value                                                                    |
| ------------- | ------------------------------------------------------------------------ |
| `name`        | `reason`                                                                 |
| `memory`      | `true` — inline definitions are stored at runtime for reuse              |
| `description` | Comprehensive guidance for LLM clients covering all four reasoning types |

### FileSystemTool Configuration

| Property      | Value                                                                   |
| ------------- | ----------------------------------------------------------------------- |
| `name`        | `filesystem`                                                            |
| `root`        | Project root — operates on the project directory                        |
| `stores`      | `MCPStoreManager` with `.orkestrel/snapshots/` for snapshot persistence |
| `description` | Comprehensive guidance covering all 15 filesystem operations            |

### InterpretTool Configuration

| Property      | Value                                                                   |
| ------------- | ----------------------------------------------------------------------- |
| `name`        | `interpret`                                                             |
| `memory`      | `true` — imported templates are persisted to stores                     |
| `stores`      | `MCPStoreManager` with `.orkestrel/templates/` for template persistence |
| `description` | Comprehensive guidance for natural language interpretation operations   |

### AgentTool Configuration

| Property      | Value                                                                           |
| ------------- | ------------------------------------------------------------------------------- |
| `name`        | `agent`                                                                         |
| `manager`     | `AgentManager` backed by `OllamaProvider`                                       |
| `tools`       | `[reasonTool, filesystemTool, interpretTool]` — tools available to child agents |
| `description` | Guidance for delegating tasks to a specialized sub-agent                        |

### SandboxTool Configuration

| Property      | Value                                                                   |
| ------------- | ----------------------------------------------------------------------- |
| `name`        | `sandbox`                                                               |
| `description` | Guidance covering all 12 sandbox operations including process execution |

### PromptTool Configuration

| Property      | Value                                                                                 |
| ------------- | ------------------------------------------------------------------------------------- |
| `name`        | `prompt`                                                                              |
| `prompt`      | `RemotePrompt` — SSE-bridged prompts for stdio environments                           |
| `templates`   | `TemplateManager` for reusable prompt templates                                       |
| `stores`      | `MCPStoreManager` with `.orkestrel/templates/prompt/` for template persistence        |
| `remote`      | `PromptToolRemote` with `connected()`, `launch()`, port, token, and script path       |
| `description` | Guidance covering prompt operations, template management, and companion launch/status |

### WorkflowTool Configuration

| Property      | Value                                                                            |
| ------------- | -------------------------------------------------------------------------------- |
| `name`        | `workflow`                                                                       |
| `manager`     | `WorkflowsManager` for workflow lifecycle                                        |
| `stores`      | `MCPStoreManager` with `.orkestrel/snapshots/workflow/` for snapshot persistence |
| `onBlocked`   | Bridges blocked tasks to the remote prompt system when a companion is connected  |
| `description` | Guidance covering workflow operations, snapshots, and task lifecycle management  |

---

## Client Configuration

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

```json
{
	"servers": {
		"orkestrel": {
			"type": "stdio",
			"command": "node",
			"args": ["${workspaceFolder}/dist/bin/mcp.js"]
		}
	}
}
```

The `orkestrel` entry launches the process, which starts both the stdio MCP server and the HTTP server for prompt bridging and Streamable HTTP MCP access.

### JetBrains IDEs (WebStorm, IntelliJ)

Add to `~/.config/github-copilot/intellij/mcp.json` (or `%LOCALAPPDATA%\github-copilot\intellij\mcp.json` on Windows):

```json
{
	"servers": {
		"orkestrel": {
			"type": "stdio",
			"command": "node",
			"args": ["${workspaceFolder}/dist/bin/mcp.js"]
		}
	}
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
	"mcpServers": {
		"orkestrel": {
			"command": "node",
			"args": ["C:/path/to/orkestrel/dist/bin/mcp.js"]
		}
	}
}
```

### Cursor

Add to Cursor MCP settings:

```json
{
	"mcpServers": {
		"orkestrel": {
			"command": "node",
			"args": ["C:/path/to/orkestrel/dist/bin/mcp.js"]
		}
	}
}
```

---

## API Reference

### Entry Point

The MCP script has no programmatic API — it is a standalone process. It exports nothing. Its sole purpose is to be invoked as `node dist/bin/mcp.js`.

### Modes

| Mode      | Flag          | Description                                        |
| --------- | ------------- | -------------------------------------------------- |
| Server    | _(default)_   | Starts MCP on stdio + SSE, HTTP server for prompts |
| Companion | `--companion` | Connects to prompt SSE endpoint as client          |

### npm Scripts

| Script          | Command                   | Description                           |
| --------------- | ------------------------- | ------------------------------------- |
| `npm run build` | Builds the project        | Produces `dist/bin/mcp.js` and others |
| `npm run mcp`   | Runs the MCP server       | Starts MCP server (stdio + SSE)       |
| `npm run serve` | Runs the inference server | Starts HTTP inference server          |

### Environment

| Variable         | Default                  | Description                  |
| ---------------- | ------------------------ | ---------------------------- |
| `ORKESTREL_PORT` | `3001`                   | HTTP server port             |
| `OLLAMA_HOST`    | `http://localhost:11434` | Ollama provider URL          |
| `OLLAMA_MODEL`   | `qwen3-vl:2b-instruct`   | Default model for agent tool |

All paths (store directories, filesystem root) are resolved relative to the package root — the directory two levels above the script (`dist/bin/mcp.js` → project root). This avoids `process.cwd()` which is unreliable in IDE-launched processes.

---

## Inference Server

### Overview

`bin/serve.ts` is an HTTP inference server that loads a GGUF model and serves a web-based chat interface. It is a standalone entry point separate from the MCP server.

```bash
# Start the inference server
npm run serve
```

Or run the built output directly:

```bash
node dist/bin/serve.js
```

### Endpoints

| Method | Path            | Description                               |
| ------ | --------------- | ----------------------------------------- |
| GET    | `/`             | Serves the SPA (web-based chat interface) |
| GET    | `/api/health`   | SSE health stream                         |
| GET    | `/api/config`   | Model configuration JSON                  |
| POST   | `/api/tokenize` | Encode text to tokens                     |
| POST   | `/api/chat`     | SSE streaming chat                        |
| POST   | `/api/clear`    | Clear the KV cache                        |
