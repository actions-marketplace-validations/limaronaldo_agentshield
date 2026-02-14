# Detection Rules

AgentShield ships with 12 built-in detectors targeting the most common security
issues in AI agent extensions. Each rule has an ID, severity, confidence level,
and CWE mapping where applicable.

---

## SHIELD-001: Command Injection

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| Category | Command Injection |

**What it detects:** Calls to `subprocess.run`, `subprocess.Popen`, `subprocess.call`,
`subprocess.check_output`, or `os.system` where the command argument comes from a
tool parameter, interpolated string, or other tainted source.

**Why it matters:** An attacker controlling the command string can execute arbitrary
OS commands on the host machine.

**Example (flagged):**
```python
@server.tool()
def run_command(command: str):
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout
```

**Example (safe):**
```python
@server.tool()
def list_files():
    result = subprocess.run(["ls", "-la"], capture_output=True)
    return result.stdout
```

**Remediation:** Use an allowlist of permitted commands. Avoid `shell=True`.
Pass arguments as a list, not a string.

---

## SHIELD-002: Credential Exfiltration

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| Category | Credential Exfiltration |

**What it detects:** A file that both accesses sensitive environment variables
(`os.environ`, `os.getenv`, `os.environ.get`) and makes outbound HTTP requests
(`requests.post`, `requests.put`, `urllib`, `httpx`). Findings are scoped by file
with proximity-based confidence (same region = High, far apart = Medium).

**Why it matters:** A malicious extension can read API keys, database credentials,
or tokens from environment variables and exfiltrate them to an attacker-controlled server.

**Remediation:** Audit all environment variable access. Ensure secrets are never
passed to outbound HTTP calls. Use an allowlist for permitted outbound domains.

---

## SHIELD-003: SSRF (Server-Side Request Forgery)

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| Category | SSRF |

**What it detects:** HTTP client calls (`requests.get`, `requests.post`, `urllib`,
`httpx`, `aiohttp`, `fetch`) where the URL argument comes from a tool parameter.

**Why it matters:** An attacker can use the extension as a proxy to access internal
services, cloud metadata endpoints (169.254.169.254), or other restricted resources.

**Remediation:** Validate URLs against an allowlist of permitted domains and schemes.
Block private IP ranges and metadata endpoints.

---

## SHIELD-004: Arbitrary File Access

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| Category | Arbitrary File Access |

**What it detects:** File operations (`open`, `read`, `write`, `Path`) where the
file path comes from a tool parameter, allowing path traversal.

**Why it matters:** An attacker can read sensitive files (`/etc/passwd`, `.env`,
SSH keys) or write to arbitrary locations on the filesystem.

**Remediation:** Validate and sanitize file paths. Use a chroot or restrict access
to a specific directory. Reject paths containing `..`.

---

## SHIELD-005: Runtime Package Install

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) |
| Category | Supply Chain |

**What it detects:** Commands that install packages at runtime: `pip install`,
`npm install`, `yarn add`, `apt-get install`, `brew install`.

**Why it matters:** Runtime installation bypasses code review and lockfile
verification. A compromised or typosquatted package gets installed silently.

**Remediation:** Pre-install all dependencies at build time. Never install
packages inside tool handlers.

---

## SHIELD-006: Self-Modification

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) |
| Category | Self-Modification |

**What it detects:** File write operations targeting the extension's own source
files, or write operations with dynamic/parameter-derived paths.

**Why it matters:** A self-modifying extension can inject backdoors, persist
malicious code, or escalate privileges across restarts.

**Remediation:** Extensions should never write to their own source directory.
Write to designated output directories only.

---

## SHIELD-007: Prompt Injection Surface

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | — |
| Category | Prompt Injection Surface |

**What it detects:** Tools that fetch external content via HTTP GET requests and
return it to the LLM without sanitization. External content can contain prompt
injection payloads.

**Why it matters:** An attacker can plant malicious instructions on a web page
that gets fetched by the tool and injected into the LLM's context.

**Remediation:** Sanitize external content before returning it to the LLM.
Strip or escape instruction-like patterns. Consider content-type validation.

---

## SHIELD-008: Excessive Permissions

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) |
| Category | Excessive Permissions |

**What it detects:** Tools that declare permissions (network, filesystem, process
execution) in their tool surface but don't actually use those capabilities in
their implementation.

**Why it matters:** Overly broad permissions violate the principle of least
privilege and increase the attack surface if the extension is compromised.

**Remediation:** Request only the permissions your extension actually uses.
Remove unused capability declarations.

---

## SHIELD-009: Unpinned Dependencies

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) |
| Category | Supply Chain |

**What it detects:** Dependencies with loose version constraints: `>=`, `~=`,
`^`, `*`, or no version at all.

**Why it matters:** Unpinned dependencies can silently upgrade to compromised
versions. A supply chain attacker who publishes a malicious patch version
automatically affects all consumers.

**Remediation:** Pin dependencies to exact versions (e.g., `requests==2.31.0`).
Use a lockfile with hashes for verification.

---

## SHIELD-010: Typosquat Detection

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) |
| Category | Supply Chain |

**What it detects:** Package names with Levenshtein distance 1-2 from popular
packages (requests, flask, django, numpy, express, react, etc.). Distance 1
gets High confidence, distance 2 gets Medium.

**Why it matters:** Typosquatting is a common supply chain attack. Packages
like `reqeusts` or `djang0` contain malware but look legitimate at a glance.

**Remediation:** Verify package names carefully. Use `pip install --require-hashes`
or equivalent. Review new dependencies in code review.

---

## SHIELD-011: Dynamic Code Execution

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| Category | Code Injection |

**What it detects:** Calls to `eval()` or `exec()` where the code argument
comes from a tool parameter, interpolated string, or other tainted source.

**Why it matters:** Dynamic code execution with user-controlled input allows
arbitrary code execution — the most severe class of vulnerability.

**Remediation:** Never use `eval`/`exec` with external input. Use safe
alternatives like `ast.literal_eval` for data parsing, or a proper parser.

---

## SHIELD-012: No Lockfile

| Field | Value |
|-------|-------|
| Severity | Low |
| CWE | — |
| Category | Supply Chain |

**What it detects:** Projects that declare dependencies (in `requirements.txt`,
`pyproject.toml`, `package.json`) but have no corresponding lockfile
(`Pipfile.lock`, `poetry.lock`, `uv.lock`, `package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`).

**Why it matters:** Without a lockfile, dependency resolution is non-deterministic.
Different environments may install different versions, and there's no cryptographic
verification of package integrity.

**Remediation:** Generate a lockfile: `poetry lock`, `uv lock`, `npm install`,
`yarn install`, or `pip freeze > requirements.txt` with `--require-hashes`.

---

## Severity Levels

| Level | Meaning | Default action |
|-------|---------|----------------|
| Critical | Immediate exploitation risk | Fail scan |
| High | Significant security risk | Fail scan (default threshold) |
| Medium | Moderate risk, may need context | Pass (configurable) |
| Low | Best practice recommendation | Pass |
| Info | Informational | Pass |

## Confidence Levels

| Level | Meaning |
|-------|---------|
| High | Strong pattern match, likely true positive |
| Medium | Pattern match with some ambiguity |
| Low | Heuristic match, may be false positive |
