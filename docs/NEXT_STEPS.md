# Next Steps — Post v0.1.0

Status: v0.2.0 shipped Feb 20, 2026. TypeScript tree-sitter parser, crates.io, Homebrew, GitHub Action e2e — all done.

---

## 1. Real-World Validation (High Priority)

Scan popular open-source MCP servers to find false positives/negatives and tune detectors.

### Targets to scan

```bash
# Clone popular MCP servers
mkdir -p /tmp/mcp-audit && cd /tmp/mcp-audit

# Anthropic's reference servers
git clone https://github.com/modelcontextprotocol/servers.git mcp-official

# Community servers (pick from awesome-mcp-servers)
git clone https://github.com/punkpeye/awesome-mcp-servers.git awesome-list
# Browse awesome-list for popular servers, then clone individually

# Specific high-profile ones to try:
# - filesystem server (file read/write — should trigger SHIELD-004)
# - fetch/web server (HTTP requests — should trigger SHIELD-003/007)
# - git server (command execution — may trigger SHIELD-001)
# - database servers (SQL — watch for false positives)
```

### Run scans

```bash
# Scan each server, output to JSON for analysis
cd /tmp/mcp-audit

for dir in mcp-official/src/*/; do
  name=$(basename "$dir")
  echo "=== Scanning $name ==="
  agentshield scan "$dir" --format json --output "results-${name}.json" 2>&1
  echo "Exit: $?"
  echo ""
done

# Generate HTML reports for interesting ones
agentshield scan mcp-official/src/filesystem --format html --output report-filesystem.html
agentshield scan mcp-official/src/fetch --format html --output report-fetch.html
```

### What to look for

- **False positives**: safe patterns flagged as vulnerabilities (e.g., a server that validates URLs before fetching)
- **False negatives**: known-dangerous patterns not caught (look at server code manually)
- **Severity calibration**: are Critical/High findings actually that severe in context?
- **Missing detectors**: patterns we should catch but don't have rules for

### Tuning actions

After scanning, if you find issues:
- False positives → adjust regex patterns or add allowlist heuristics in the detector
- False negatives → add new patterns to the relevant parser (python.rs) or detector
- New category → create a new SHIELD-0XX detector

---

## ~~2. Test GitHub Action End-to-End~~ — Done

Tested Feb 20, 2026. Test repo: [`limaronaldo/agentshield-test`](https://github.com/limaronaldo/agentshield-test)

### Results

- [x] Action downloads correct binary for ubuntu-latest (x86_64-unknown-linux-gnu)
- [x] Scan finds SHIELD-001, SHIELD-002, SHIELD-003, SHIELD-004, SHIELD-007 (7 total findings)
- [x] SARIF uploads to Code Scanning tab (5 alerts with source locations)
- [x] Action fails with exit code 1 (findings above `high` threshold)
- [ ] Creating a PR shows annotations inline (not yet tested)

### SARIF bugs found and fixed

Three SARIF validation issues were discovered during e2e testing and fixed:

1. **`startColumn` must be >= 1** — parser emits 0-based columns, SARIF 2.1.0 requires 1-based. Fixed with `.max(1)`.
2. **`fixes[]` requires `artifactChanges`** — removed invalid `fixes` array, moved remediation text to `result.properties.remediation`.
3. **Location-less results rejected** — supply-chain findings (SHIELD-009, SHIELD-012) have no source location; GitHub Code Scanning requires at least one. Fixed by filtering them from SARIF output (still appear in console/JSON/HTML).

---

## 3. ~~Publish to crates.io~~ — Done

Published as [`agent-shield`](https://crates.io/crates/agent-shield) v0.2.0 on Feb 20, 2026.
(`agentshield` name was taken by an unrelated crate; binary name remains `agentshield`.)

### Pre-publish checklist

- [x] Cargo.toml has: name, version, description, license, repository, readme
- [x] README.md exists
- [x] LICENSE exists
- [x] `cargo publish --dry-run` succeeds
- [x] No private/internal dependencies
- [x] Published to crates.io as `agent-shield`

---

## 4. v0.2.0 Roadmap

Features deferred from v0.1.0:

| Feature | Linear | Effort | Impact |
|---------|--------|--------|--------|
| ~~TypeScript parser (tree-sitter)~~ | ~~RML-1078~~ | ~~Done v0.2.0~~ | ~~High~~ |
| Cross-file taint analysis | — | High | High — catches multi-file exfil |
| ~~Homebrew formula~~ | — | ~~Done v0.2.0~~ | ~~Medium~~ |
| ~~GitHub Action e2e test~~ | — | ~~Done v0.2.0~~ | ~~High~~ |
| GitHub Marketplace submission | — | Low | High — discoverability |
| Blog post / announcement | — | Medium | High — launch content |
| VS Code extension | — | Medium | Medium — inline findings |
| LangChain adapter | — | Medium | Medium — new framework |
| CrewAI adapter | — | Low | Low — new framework |

### Suggested v0.2.0 scope

Focus on TypeScript parser + real-world tuning from step 1 above. That covers
the most common MCP server language and improves detection quality.

---

## 5. Launch / Promotion

### Blog post outline: "We scanned N MCP servers — here's what we found"

1. Intro: AI agents are getting powerful tools, but who's checking the tools?
2. Methodology: scanned X open-source MCP servers with AgentShield
3. Findings breakdown: N command injections, N SSRF, N credential leaks
4. Case studies: 2-3 interesting real findings with code snippets
5. How to protect yourself: add AgentShield to your CI
6. CTA: GitHub Action link, star the repo

### Distribution channels

- Hacker News (Show HN)
- Reddit r/MachineLearning, r/rust
- Twitter/X (AI security community)
- MCP Discord / community channels
- Dev.to / Hashnode blog post

---

## Linear Project Reference

- Project: AgentShield - Security Scanner for AI Agent Extensions
- Project ID: 9996399b-d697-44fe-a4bf-2756f58a39ad (IBVI org)
- Team ID: 65a52083-4c10-4a6a-b1bc-0a5d63cbe207 (IBVI-AI / RML)
- Repo: https://github.com/limaronaldo/agentshield
- All v0.1.0 issues: Done (RML-1062 through RML-1091, migrated from MBRAS IBVI-311..340)
- Deferred: RML-1078 (TypeScript parser → v0.2.0)
