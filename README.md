# proplet

## Security & Code Quality

This project uses **CodeQL** for automated security scanning and code quality analysis.

### 🔒 Security Scanning

CodeQL automatically scans for:
- 🔴 **Critical Security Issues**: SQL injection, hardcoded credentials, command injection
- 🟡 **Medium Security Issues**: Unvalidated redirects, weak cryptography, missing validation
- 🔵 **Code Quality Issues**: Missing error handling, debug statements, dead code

### 📚 Documentation

- **[Complete Setup Guide](docs/CODEQL_SETUP.md)** - Full configuration and customization guide
- **[Quick Reference](docs/CODEQL_QUICK_REFERENCE.md)** - Common commands and patterns

### 🚀 Quick Start

Run CodeQL locally:

```bash
# Create database
codeql database create codeql-db --language=javascript-typescript --source-root=./src

# Run analysis
codeql database analyze codeql-db javascript-security-and-quality.qls --format=text
```

### 🎯 Custom Security Checks

This project includes custom CodeQL queries:

| Query | Detection |
|-------|-----------|
| `hardcoded-secrets.ql` | API keys, passwords, tokens in code |
| `sql-injection.ql` | User input in SQL queries |
| `unvalidated-redirect.ql` | Open redirect vulnerabilities |
| `missing-error-handling.ql` | Async functions without try-catch |
| `console-log-in-production.ql` | Debug statements in production |

### 📊 Viewing Results

Results are available in:
- **GitHub Security Tab** → Code scanning alerts
- **Pull Request Checks** → Automated security review
- **Weekly Reports** → Scheduled scan results

---