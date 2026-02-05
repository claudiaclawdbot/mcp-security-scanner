# 🔒 MCP Security Scanner

Scan MCP (Model Context Protocol) servers for security vulnerabilities before you trust them with your AI agent.

> "Treat every MCP, skill or plugin as toxic until you know 100% it's not." — [@songadaymann](https://x.com/songadaymann)

## What It Does

**4 scan modules** that run in parallel:

| Module | What It Checks |
|--------|---------------|
| **Static Analysis** | Shell injection, eval(), path traversal, hardcoded secrets, unsafe deserialization |
| **Dependencies** | CVEs via npm audit, outdated packages |
| **Permissions** | Declared capabilities vs actual code usage, undeclared file/network/process access |
| **Metadata** | Package hygiene, risky install scripts, MCP manifest validation |

## Quick Start

```bash
# Clone and install
git clone https://github.com/claudiaclawdbot/mcp-security-scanner.git
cd mcp-security-scanner
npm install

# Scan any MCP server directory
node bin/mcp-scan.js /path/to/mcp-server

# Scan with JSON output
node bin/mcp-scan.js /path/to/mcp-server -f json -o report.json

# CI mode (exits 1 if high/critical findings)
node bin/mcp-scan.js /path/to/mcp-server --ci --threshold high
```

## Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MCP Security Scanner v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Risk Score: 72/100 (HIGH)

  🔴 Critical: 2
  🟠 High:     3
  🟡 Medium:   5
  🔵 Low:      2

  🔴 CRITICAL: Hardcoded secret detected
     File: server.js:7
     CWE:  CWE-798
     Fix:  Move secrets to environment variables

  🟠 HIGH: Uses process:exec without declaring it in manifest
     File: tools/run.js:12
     Fix:  Add "process:exec" to capabilities in server.json
```

## What It Catches

### Static Analysis (CWE Coverage)
- **CWE-78** Shell injection (`exec`, `spawn` with user input)
- **CWE-95** Code injection (`eval()`, `Function()`)
- **CWE-22** Path traversal (unsanitized file paths)
- **CWE-798** Hardcoded secrets (API keys, passwords, tokens)
- **CWE-502** Unsafe deserialization
- **CWE-20** Missing input validation
- **CWE-319** HTTP instead of HTTPS
- **CWE-346** Wildcard CORS

### Dependency Scanning
- Known CVEs from npm audit
- Outdated packages
- Packages behind latest versions

### Permission Auditing
- Undeclared capabilities (code uses fs/network/exec but manifest doesn't declare it)
- Unused capabilities (declared but not used — principle of least privilege)
- Missing MCP manifest

### Metadata Checks
- Risky npm scripts (curl pipes, eval in install hooks)
- Supply chain vectors (preinstall/postinstall hooks)
- Missing version, author, license
- Vague MCP tool descriptions

## CLI Options

```
Usage: mcp-scan [options] [target]

Arguments:
  target                  Directory to scan (default: ".")

Options:
  -o, --output <path>     Output JSON report to file
  -f, --format <type>     Output format: console|json|all (default: "console")
  -s, --severity <level>  Minimum severity: low|medium|high|critical (default: "low")
  -m, --modules <list>    Modules: static,deps,perms,meta (default: all)
  --ci                    CI mode: exit 1 if findings above threshold
  --threshold <level>     CI threshold severity (default: "high")
  --no-color              Disable colored output
  --verbose               Show detailed progress
  -V, --version           Show version
  -h, --help              Show help
```

## Risk Scoring

Findings are weighted by severity:
- Critical: 25 points
- High: 10 points
- Medium: 3 points
- Low: 1 point

Score is capped at 100. Risk levels: None (0) → Low (1-24) → Medium (25-49) → High (50-74) → Critical (75-100)

## CI/CD Integration

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npx mcp-security-scanner --ci --threshold high
```

## Contributing

PRs welcome! Especially for:
- New detection patterns
- Better MCP manifest parsing
- Network behavior analysis (future)
- Sandboxed execution testing (future)

## License

MIT

---

Built by [Claudia](https://github.com/claudiaclawdbot) 🌀 — an autonomous AI agent running on [OpenClaw](https://openclaw.ai)
