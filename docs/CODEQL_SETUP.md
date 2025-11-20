# CodeQL Setup Guide

## Overview

CodeQL is a semantic code analysis engine that helps you discover vulnerabilities across your codebase. This project is configured with CodeQL to automatically scan for security vulnerabilities, bugs, and code quality issues.

## What's Configured

### 1. GitHub Actions Workflow
Location: `.github/workflows/codeql.yml`

The workflow runs automatically on:
- **Push** to the `main` branch
- **Pull requests** targeting `main`
- **Weekly schedule** (Fridays at 8:17 AM UTC)

### 2. Query Suites Enabled

#### Built-in Query Suites
- **security-extended**: Comprehensive security queries (high and medium precision)
- **security-and-quality**: Security queries plus code quality checks

#### Custom Queries
Located in: `codeql-custom-queries-javascript/`

1. **hardcoded-secrets.ql** - Detects hardcoded API keys, passwords, and tokens
2. **sql-injection.ql** - Identifies SQL injection vulnerabilities
3. **unvalidated-redirect.ql** - Finds open redirect vulnerabilities
4. **missing-error-handling.ql** - Detects async functions without proper error handling
5. **console-log-in-production.ql** - Flags debug console statements in production code

### 3. Configuration File
Location: `.github/codeql/codeql-config.yml`

Configured to:
- Scan only the `src` directory
- Exclude `node_modules`, `dist`, and test files
- Run both built-in and custom query suites

## Running CodeQL Locally

### Prerequisites
Install the CodeQL CLI:
```bash
# macOS
brew install codeql

# Or download from: https://github.com/github/codeql-cli-binaries/releases
```

### Steps to Run Locally

1. **Create a CodeQL database:**
```bash
codeql database create ./codeql-db \
  --language=javascript-typescript \
  --source-root=./src
```

2. **Run analysis with built-in queries:**
```bash
codeql database analyze ./codeql-db \
  javascript-security-and-quality.qls \
  --format=sarif-latest \
  --output=results.sarif
```

3. **Run custom queries:**
```bash
codeql database analyze ./codeql-db \
  ./codeql-custom-queries-javascript \
  --format=sarif-latest \
  --output=custom-results.sarif
```

4. **View results in readable format:**
```bash
codeql database analyze ./codeql-db \
  javascript-security-and-quality.qls \
  --format=text
```

## Understanding Results

### Severity Levels
- **Error** (Critical/High): Security vulnerabilities that need immediate attention
- **Warning** (Medium): Potential issues that should be reviewed
- **Note** (Low): Code quality suggestions

### Common Issues Detected

#### 🔴 Critical Security Issues
- SQL Injection vulnerabilities
- Hardcoded credentials
- Command injection
- Path traversal
- XSS (Cross-Site Scripting)

#### 🟡 Medium Security Issues
- Unvalidated redirects
- Weak cryptography
- Insecure randomness
- Missing input validation

#### 🔵 Code Quality Issues
- Missing error handling
- Dead code
- Unused variables
- Console.log statements
- Complex functions

## Customizing the Setup

### Adding New Custom Queries

1. Create a new `.ql` file in `codeql-custom-queries-javascript/`
2. Follow this template:

```ql
/**
 * @name Your Query Name
 * @description What this query detects
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id javascript/your-query-id
 * @tags security
 */

import javascript

from Expr e
where
  // Your detection logic here
select e, "Your message here"
```

3. Add it to `codeql-custom-queries-javascript/codeql-pack.yml`:

```yaml
suites:
  - name: security-custom
    queries:
      - your-new-query.ql
```

### Adjusting Scan Paths

Edit `.github/codeql/codeql-config.yml`:

```yaml
paths:
  - src
  - lib  # Add more paths

paths-ignore:
  - "**/*.test.ts"  # Add more exclusions
```

### Disabling Specific Queries

In `.github/codeql/codeql-config.yml`:

```yaml
query-filters:
  - exclude:
      id: js/unused-local-variable
  - exclude:
      tags contain: experimental
```

## Viewing Results on GitHub

1. Go to your repository on GitHub
2. Click the **Security** tab
3. Click **Code scanning alerts**
4. Review and triage alerts

### Alert Actions
- **Dismiss**: Mark as false positive or won't fix
- **Create issue**: Track the fix
- **Open PR**: Fix directly

## Best Practices

### 1. Fix High-Severity Issues First
Focus on security vulnerabilities (marked as Error/Critical) before code quality issues.

### 2. Don't Disable All Warnings
Review warnings carefully - they often indicate real issues.

### 3. Use Suppressions Sparingly
Only suppress false positives with clear comments:

```javascript
// codeql[js/sql-injection] - Input is validated by middleware
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

### 4. Keep CodeQL Updated
GitHub automatically updates the action, but for local CLI:
```bash
brew upgrade codeql  # macOS
```

### 5. Review Custom Queries Regularly
As your codebase evolves, update custom queries to match new patterns.

## Troubleshooting

### Issue: Workflow Fails with "Out of Memory"
**Solution**: Use a larger runner in `.github/workflows/codeql.yml`:
```yaml
runs-on: ubuntu-latest-4-cores
```

### Issue: Too Many False Positives
**Solution**: Adjust precision in custom queries or add sanitizers:
```ql
override predicate isSanitizer(DataFlow::Node node) {
  // Add your sanitization logic
}
```

### Issue: Missing Vulnerabilities
**Solution**: Lower precision threshold or add more custom queries.

### Issue: Custom Queries Not Running
**Solution**: Verify `codeql-pack.yml` is valid:
```bash
codeql pack install codeql-custom-queries-javascript/
```

## Integration with CI/CD

### Block PRs with High-Severity Issues

Add to `.github/workflows/codeql.yml`:

```yaml
- name: Check for critical alerts
  run: |
    CRITICAL=$(gh api repos/${{ github.repository }}/code-scanning/alerts \
      --jq '[.[] | select(.state == "open" and .rule.security_severity_level == "critical")] | length')
    if [ "$CRITICAL" -gt 0 ]; then
      echo "❌ Found $CRITICAL critical security issues"
      exit 1
    fi
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Resources

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL for JavaScript](https://codeql.github.com/codeql-standard-libraries/javascript/)
- [Query Writing Tutorial](https://codeql.github.com/docs/writing-codeql-queries/)
- [Standard Query Library](https://github.com/github/codeql/tree/main/javascript/ql/src)
- [CWE Database](https://cwe.mitre.org/) - Common Weakness Enumeration

## Getting Help

- **GitHub Discussions**: [CodeQL Community](https://github.com/github/codeql/discussions)
- **Stack Overflow**: Tag `codeql`
- **Security Lab**: [GitHub Security Lab](https://securitylab.github.com/)

## Quick Commands Reference

```bash
# Install dependencies for custom queries
codeql pack install codeql-custom-queries-javascript/

# Create database
codeql database create ./codeql-db --language=javascript-typescript

# Run analysis
codeql database analyze ./codeql-db javascript-security-and-quality.qls

# Run specific query
codeql query run your-query.ql --database=./codeql-db

# Format query file
codeql query format -i your-query.ql

# Test a query
codeql test run codeql-custom-queries-javascript/
```

## Maintenance Schedule

- **Weekly**: Review new alerts from scheduled scans
- **Monthly**: Update custom queries based on new vulnerability patterns
- **Quarterly**: Review false positives and tune query precision
- **Annually**: Audit entire CodeQL configuration and query suite

---

**Last Updated**: 2024
**Maintained By**: Security Team