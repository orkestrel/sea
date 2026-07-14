# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it leaves pre-release.

## [Unreleased]

### Added

- `SEAError` coded error taxonomy with a machine-readable `SEAErrorCode`, plus the
  `isSEAError` type guard.
- `openBrowser` helper — launch the system default browser at an http(s) URL (for
  bundled local-UI apps), surfacing `SEAErrorCode` `'BROWSER'` for an invalid or
  non-http(s) URL.
- `AbortSignal` and `timeout` support for shell-boundary operations, surfacing
  `SEAErrorCode` `'ABORT'` and `'TIMEOUT'`.
- SEA entry point module format selection — `cjs` (default) and `esm` (Node >= 25.7)
  via `SEAEntryOptions.format`.
- SEA blob generation toggles — `SEABlobOptions.cache` / `SEABlobOptions.snapshot`.
- `SEAResult` now reports `signed`, `stripped`, and the patched Windows `subsystem`.
- Executable signature verification support in the platform signing pipeline.
- `SECURITY.md` documenting the ad-hoc signing default and the consumer's
  re-signing responsibility for distribution.
- A CI matrix covering `ubuntu-latest`, `windows-latest`, `macos-latest`, and
  `macos-14` across Node `24` and `26`, plus an end-to-end SEA smoke build/run job.

### Changed

- **BREAKING:** `SEAOptions.entry` is now a `SEAEntryOptions` object
  (`{ path, format? }`) instead of a bare string path.
- Code signing now runs strictly after blob injection (sign-after-inject ordering)
  so a signature always covers the final injected binary.
- The final executable write is now atomic — the built binary is durably flushed
  and renamed into place rather than written directly to its target path.

### Fixed

- A swallowed error from signature stripping or signing no longer passes silently —
  failures now throw a coded `SEAError`.
- The Windows PE subsystem is now patched **after** signing, so the subsystem patch
  no longer invalidates a prior signature.

## [0.0.1] - 2026-07-14

Initial surface: SEA build orchestrator (`createSEA`), cross-platform binary
resource injector (`createInjector`), and asset management (`createAsset`,
`createAssetManager`) for embedding compressed client assets into a Node.js
Single Executable Application.
