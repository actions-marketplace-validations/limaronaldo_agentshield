# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**AgentShield** is a Rust-based, offline-first security scanner for AI agent extensions
(MCP servers, OpenClaw skills, LangChain tools). It produces SARIF output compatible
with GitHub Code Scanning.

## Repository Structure

```
agentshield/
├── src/
│   ├── lib.rs                    # Public API: scan(), render_report()
│   ├── error.rs                  # ShieldError (thiserror)
│   ├── bin/cli.rs                # Clap CLI: scan, list-rules, init
│   ├── ir/                       # Intermediate Representation (ScanTarget)
│   │   ├── mod.rs                # ScanTarget, Framework, SourceFile
│   │   ├── tool_surface.rs       # Tool definitions, permissions
│   │   ├── execution_surface.rs  # Commands, file IO, network IO
│   │   ├── data_surface.rs       # Sources, sinks, taint paths
│   │   ├── dependency_surface.rs # Dependencies, lockfiles
│   │   └── provenance_surface.rs # Author, repo, license
│   ├── adapter/                  # Framework → IR translation
│   │   ├── mod.rs                # Adapter trait, auto_detect_and_load()
│   │   ├── mcp.rs                # MCP server adapter
│   │   └── openclaw.rs           # OpenClaw SKILL.md adapter
│   ├── parser/                   # Language parsers
│   │   ├── python.rs             # tree-sitter Python + regex patterns
│   │   ├── shell.rs              # Regex-based shell parser
│   │   └── json_schema.rs        # JSON Schema → ToolSurface
│   ├── analysis/                 # Static analysis helpers
│   │   ├── capability.rs         # Capability escalation scoring
│   │   └── supply_chain.rs       # Typosquat detection
│   ├── rules/                    # Detection engine
│   │   ├── mod.rs                # RuleEngine, Detector trait
│   │   ├── finding.rs            # Finding, Severity, Evidence structs
│   │   ├── registry.rs           # Rule metadata registry
│   │   ├── policy.rs             # Policy evaluation (.agentshield.toml)
│   │   └── builtin/              # 12 built-in detectors (SHIELD-001..012)
│   ├── output/                   # Report formatters
│   │   ├── mod.rs                # OutputFormat enum, render()
│   │   ├── console.rs            # Plain text
│   │   ├── json.rs               # JSON
│   │   ├── sarif.rs              # SARIF 2.1.0
│   │   └── html.rs               # Self-contained HTML
│   └── config/                   # .agentshield.toml parsing
├── tests/fixtures/               # Test MCP servers (safe + vulnerable)
├── .github/workflows/
│   ├── ci.yml                    # Test + clippy + fmt + smoke
│   └── release.yml               # 5-platform binary builds
└── action.yml                    # GitHub Action (composite)
```

## Common Commands

```bash
# Build
cargo build --release

# Test (69 tests)
cargo test

# Lint
cargo clippy -- -D warnings
cargo fmt --check

# Run CLI
cargo run -- scan tests/fixtures/mcp_servers/vuln_cmd_inject
cargo run -- list-rules
cargo run -- scan . --format html --output report.html
```

## Architecture Principles

1. **Adapters produce IR, detectors consume IR.** Adding a new framework never changes any detector.
2. **All adapters run.** `auto_detect_and_load()` runs every matching adapter, not just the first.
3. **ArgumentSource is the taint abstraction.** Detectors check `is_tainted()` — no full dataflow needed.
4. **Policy is separate from detection.** Detectors always run; policy decides what to report and whether to fail.

## Key Types

- `ScanTarget` — unified IR with 5 surfaces (tool, execution, data, dependency, provenance)
- `Finding` — detector output with severity, confidence, location, evidence, remediation
- `ArgumentSource` — `Literal` (safe), `Parameter` (tainted), `EnvVar`, `Interpolated`, `Unknown`
- `Detector` trait — `metadata() -> RuleMetadata`, `run(&ScanTarget) -> Vec<Finding>`
- `PolicyVerdict` — pass/fail with threshold and highest severity

## Adding a New Detector

1. Create `src/rules/builtin/your_detector.rs`
2. Implement `Detector` trait (`metadata()` + `run()`)
3. Register in `src/rules/builtin/mod.rs` → `all_detectors()`
4. Add tests in the same file
5. Add fixture in `tests/fixtures/` if applicable
6. Run `cargo test && cargo clippy -- -D warnings`

## Adding a New Adapter

1. Create `src/adapter/your_framework.rs`
2. Implement `Adapter` trait (`name()`, `detect()`, `load()`)
3. Register in `src/adapter/mod.rs` → `all_adapters()`
4. `detect()` checks for framework-specific files
5. `load()` uses parsers to populate `ScanTarget`

## Conventions

- `thiserror` for error types, `?` operator everywhere
- No `unwrap()` in production paths
- tree-sitter for AST parsing, regex for pattern matching
- Tests use real fixture files under `tests/fixtures/`
- Conventional Commits for git messages
