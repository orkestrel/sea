# Security Policy

## Supported Versions

This package is at `0.0.x` (pre-release). Only the latest published `0.0.x` version
receives security fixes — there is no backward-compatible patch branch during
pre-release. Upgrade to the latest release to pick up a fix.

| Version | Supported                        |
| ------- | -------------------------------- |
| 0.0.x   | :white_check_mark: (latest only) |
| < 0.0.x | :x:                              |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately using
[GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
for this repository. **Do not open a public issue** for a suspected vulnerability.

We aim to acknowledge a report within 5 business days and to provide a resolution
timeline once the report is triaged. You will be credited in the advisory unless you
request otherwise.

## Scope

This package builds Node.js Single Executable Applications: it injects a data blob
into a copied Node binary and, on supported platforms, invokes the platform's code
signing tools as part of the build pipeline.

- **Signing is ad-hoc by default.** On macOS, the injector/signing pipeline signs the
  output with an ad-hoc identity (`codesign --sign -`) unless the consumer supplies
  their own signing configuration. An ad-hoc signature satisfies local Gatekeeper
  checks but is **not** a trusted, distributable signature.
- **Windows Authenticode signing is the consumer's responsibility.** This package does
  not perform Authenticode signing; the `SEAPlatform.sign` command surface exists for
  platform tooling but ships without a Windows signing identity.
- **Consumers must re-sign for distribution.** Anyone distributing a binary built with
  this package outside their own machine is responsible for re-signing it with a real,
  trusted code-signing identity (Apple Developer ID, Windows Authenticode certificate,
  etc.) as part of their own release pipeline. This package does not manage or handle
  private signing keys.

## Hardening roadmap

npm provenance / OIDC trusted publishing for this package's own release pipeline is a
documented follow-up (see `publish.yml` comment in `.github/workflows/`) — not yet
implemented.
