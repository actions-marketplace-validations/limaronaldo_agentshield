# Architecture

This document describes the internal architecture of AgentShield.

## Overview

AgentShield is a **static analysis tool** that scans AI agent extensions for security
vulnerabilities. It follows a pipeline architecture:

```
Input Files → Adapter → Unified IR → Detectors → Findings → Policy → Output
```

The key design principle is **separation of concerns**: adapters handle
framework-specific parsing, detectors operate only on the unified IR, and
output formatters produce different report formats.

## Pipeline Stages

### 1. Adapter (Framework Detection)

```
src/adapter/mod.rs      — Adapter trait, auto_detect_and_load()
src/adapter/mcp.rs      — MCP server adapter
src/adapter/openclaw.rs — OpenClaw SKILL.md adapter
```

Each adapter implements:

```rust
pub trait Adapter: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, root: &Path) -> bool;
    fn load(&self, root: &Path) -> Result<Vec<ScanTarget>>;
}
```

- `detect()` checks for framework-specific files (e.g., `package.json` with MCP SDK)
- `load()` uses parsers to populate a `ScanTarget`
- **All matching adapters run** — a project can be both an MCP server and contain OpenClaw skills

### 2. Parser (Language Analysis)

```
src/parser/python.rs      — tree-sitter AST + compiled regex
src/parser/shell.rs       — regex-based command extraction
src/parser/json_schema.rs — JSON Schema → ToolSurface
```

Parsers extract structured information from source files:

- **Function calls** with argument sources (literal, parameter, interpolated, env var)
- **Environment variable access** patterns
- **File operations** with path sources
- **Network operations** with URL sources
- **Shell commands** (pip install, curl, eval)

The Python parser uses tree-sitter for AST parsing combined with compiled
regex patterns for source/sink detection. This hybrid approach balances
accuracy with performance.

### 3. Unified IR (Intermediate Representation)

```
src/ir/mod.rs                — ScanTarget, Framework, SourceFile
src/ir/tool_surface.rs       — Tool definitions, permissions
src/ir/execution_surface.rs  — Commands, file IO, network IO, env vars
src/ir/data_surface.rs       — Sources, sinks, taint paths
src/ir/dependency_surface.rs — Dependencies, lockfiles, issues
src/ir/provenance_surface.rs — Author, repo, license
```

Every adapter produces a `ScanTarget` with 5 surfaces:

```rust
pub struct ScanTarget {
    pub name: String,
    pub framework: Framework,
    pub root_path: PathBuf,
    pub tools: Vec<ToolSurface>,
    pub execution: ExecutionSurface,
    pub data: DataSurface,
    pub dependencies: DependencySurface,
    pub provenance: ProvenanceSurface,
    pub source_files: Vec<SourceFile>,
}
```

#### ArgumentSource (Taint Abstraction)

The core insight: detectors don't need full dataflow analysis. They need to know
**where a function argument came from**:

```rust
pub enum ArgumentSource {
    Literal(String),           // Safe — hardcoded value
    Parameter { name: String }, // Dangerous — from tool input
    EnvVar { name: String },   // Context-dependent
    Interpolated,              // Dangerous — string concatenation
    Unknown,                   // Conservative — flag with lower confidence
}
```

`is_tainted()` returns `true` for everything except `Literal`.

### 4. Detector Engine

```
src/rules/mod.rs          — RuleEngine, Detector trait
src/rules/finding.rs      — Finding, Severity, Confidence, Evidence
src/rules/builtin/        — 12 built-in detectors
```

Each detector implements:

```rust
pub trait Detector: Send + Sync {
    fn metadata(&self) -> RuleMetadata;
    fn run(&self, target: &ScanTarget) -> Vec<Finding>;
}
```

The `RuleEngine` collects all registered detectors and runs them against each target:

```rust
pub fn run(&self, target: &ScanTarget) -> Vec<Finding> {
    self.detectors.iter().flat_map(|d| d.run(target)).collect()
}
```

Detectors read only from the IR — they never access the filesystem directly.

### 5. Policy Evaluation

```
src/rules/policy.rs — PolicyConfig, PolicyVerdict
src/config/mod.rs   — .agentshield.toml parsing
```

Policy is separate from detection:

- **Detectors always run** and produce all findings
- **Policy filters**: ignore rules, apply severity overrides
- **Policy evaluates**: compare highest severity against threshold
- **Verdict**: pass/fail with metadata (threshold, highest severity)

### 6. Output

```
src/output/mod.rs     — OutputFormat enum, render()
src/output/console.rs — Plain text with severity badges
src/output/json.rs    — Structured JSON
src/output/sarif.rs   — SARIF 2.1.0 (GitHub Code Scanning)
src/output/html.rs    — Self-contained HTML report
```

All formatters receive `(&[Finding], &PolicyVerdict)` and produce a `String`.

## Data Flow

```
                    ┌─────────────────────────────┐
                    │  auto_detect_and_load(path)  │
                    └──────────┬──────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
        ┌──────────┐   ┌──────────┐    ┌───────────┐
        │ MCP      │   │ OpenClaw │    │ (future)  │
        │ Adapter  │   │ Adapter  │    │ LangChain │
        └────┬─────┘   └────┬─────┘    └───────────┘
             │               │
             │  ┌────────────┘
             ▼  ▼
        Vec<ScanTarget>
             │
             ▼
     ┌───────────────┐
     │  RuleEngine   │
     │  12 detectors │
     └───────┬───────┘
             │
        Vec<Finding>
             │
      ┌──────▼───────┐
      │    Policy     │
      │ filter/eval   │
      └──────┬───────┘
             │
    (Vec<Finding>, PolicyVerdict)
             │
      ┌──────▼───────┐
      │    Output     │
      │ format/render │
      └──────────────┘
```

## Error Handling

```
src/error.rs — ShieldError enum
```

All public APIs return `Result<T, ShieldError>`. Error variants:

- `NoAdapter` — no framework detected at the given path
- `Config` — invalid `.agentshield.toml`
- `Parse` — source file parsing failure
- `Io` — filesystem errors
- `Serialization` — JSON/SARIF output errors

Exit codes: `0` = pass, `1` = findings above threshold, `2` = scan error.

## Performance Characteristics

- Single-threaded pipeline (detectors are fast enough)
- tree-sitter parsing is the heaviest operation
- Regex patterns are compiled once via `once_cell::Lazy`
- No network I/O — fully offline
- Typical scan: < 50ms for a single MCP server

## Extension Points

### Adding a Framework

1. Implement `Adapter` trait in `src/adapter/`
2. Register in `all_adapters()`
3. Reuse existing parsers or add new ones

### Adding a Language Parser

1. Add tree-sitter grammar as an optional dependency
2. Feature-gate it in `Cargo.toml`
3. Implement extraction → `ExecutionSurface` / `DataSurface`

### Adding a Detector

1. Implement `Detector` trait in `src/rules/builtin/`
2. Register in `all_detectors()`
3. Operate only on `ScanTarget` — never access files directly

### Adding an Output Format

1. Implement `render()` function in `src/output/`
2. Add variant to `OutputFormat` enum
3. Wire into `output::render()` match
