# CodeQL Quick Reference

## 🚀 Quick Start

### Run CodeQL Scan Locally
```bash
# 1. Create database
codeql database create codeql-db --language=javascript-typescript --source-root=./src

# 2. Run analysis
codeql database analyze codeql-db javascript-security-and-quality.qls --format=sarif-latest --output=results.sarif

# 3. View results
codeql database analyze codeql-db javascript-security-and-quality.qls --format=text
```

## 📋 What Gets Checked

### 🔴 Critical Security Issues
- ✅ SQL Injection vulnerabilities
- ✅ Hardcoded credentials (API keys, passwords, tokens)
- ✅ Command injection
- ✅ Path traversal
- ✅ Cross-Site Scripting (XSS)
- ✅ Prototype pollution

### 🟡 Medium Security Issues
- ✅ Unvalidated URL redirects
- ✅ Weak cryptographic algorithms
- ✅ Insecure randomness
- ✅ Missing rate limiting
- ✅ Information exposure

### 🔵 Code Quality Issues
- ✅ Missing error handling in async/await
- ✅ Console.log in production code
- ✅ Dead/unreachable code
- ✅ Unused variables and imports
- ✅ Complex cyclomatic complexity

## 🎯 Custom Queries in This Project

| Query | What It Detects | Severity |
|-------|----------------|----------|
| `hardcoded-secrets.ql` | API keys, passwords, tokens in code | 🔴 Error |
| `sql-injection.ql` | User input flowing into SQL queries | 🔴 Error |
| `unvalidated-redirect.ql` | Open redirect vulnerabilities | 🟡 Warning |
| `missing-error-handling.ql` | Async functions without try-catch | 🟡 Warning |
| `console-log-in-production.ql` | Debug statements in production | 🔵 Warning |

## 📁 File Locations

```
.github/
├── workflows/
│   └── codeql.yml              # GitHub Actions workflow
└── codeql/
    └── codeql-config.yml       # Configuration file

codeql-custom-queries-javascript/
├── codeql-pack.yml             # Query pack definition
├── hardcoded-secrets.ql        # Custom query
├── sql-injection.ql            # Custom query
├── unvalidated-redirect.ql     # Custom query
├── missing-error-handling.ql   # Custom query
└── console-log-in-production.ql # Custom query
```

## ⚙️ Common Commands

### Database Operations
```bash
# Create database
codeql database create <db-path> --language=javascript-typescript

# Upgrade database
codeql database upgrade <db-path>

# Clean database
rm -rf <db-path>
```

### Running Queries
```bash
# Run all security queries
codeql database analyze <db-path> javascript-security-and-quality.qls

# Run custom queries only
codeql database analyze <db-path> ./codeql-custom-queries-javascript

# Run single query
codeql query run <query.ql> --database=<db-path>
```

### Output Formats
```bash
# SARIF (for GitHub/tools)
--format=sarif-latest --output=results.sarif

# Human-readable text
--format=text

# CSV format
--format=csv --output=results.csv

# JSON format
--format=json --output=results.json
```

## 🔧 Suppressing False Positives

### Inline Suppression
```javascript
// codeql[js/sql-injection] - Input validated by middleware
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

### Configuration File Suppression
In `.github/codeql/codeql-config.yml`:
```yaml
query-filters:
  - exclude:
      id: js/unused-local-variable
  - exclude:
      tags contain: experimental
```

## 🎨 Writing Custom Queries

### Basic Query Template
```ql
/**
 * @name Query Name
 * @description What this detects
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id javascript/custom-check
 * @tags security
 */

import javascript

from Expr e
where
  // Your logic here
select e, "Alert message"
```

### Path-Problem Query Template
```ql
/**
 * @name Data Flow Issue
 * @kind path-problem
 * @problem.severity error
 */

import javascript
import DataFlow::PathGraph

class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    // Define sources
  }
  
  override predicate isSink(DataFlow::Node sink) {
    // Define sinks
  }
}

from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Message $@", source.getNode(), "source"
```

## 🐛 Troubleshooting

### Issue: Workflow taking too long
```yaml
# Use larger runner
runs-on: ubuntu-latest-4-cores
```

### Issue: Out of memory
```yaml
# Increase memory
env:
  CODEQL_RAM: 8192
```

### Issue: Custom queries not found
```bash
# Install dependencies
codeql pack install codeql-custom-queries-javascript/
```

### Issue: Query syntax errors
```bash
# Format and validate
codeql query format -i your-query.ql
codeql query compile your-query.ql
```

## 📊 Viewing Results

### GitHub UI
1. Go to **Security** tab
2. Click **Code scanning alerts**
3. Filter by severity/status/rule

### Command Line
```bash
# Install GitHub CLI
gh extension install github/gh-codeql

# List alerts
gh api repos/:owner/:repo/code-scanning/alerts

# Filter critical alerts
gh api repos/:owner/:repo/code-scanning/alerts \
  --jq '.[] | select(.rule.security_severity_level == "critical")'
```

## 🔍 Common Patterns to Detect

### SQL Injection
```javascript
// ❌ BAD
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

// ✅ GOOD
const query = 'SELECT * FROM users WHERE id = $1';
db.query(query, [req.params.id]);
```

### Hardcoded Secrets
```javascript
// ❌ BAD
const apiKey = "sk_live_abc123xyz789";

// ✅ GOOD
const apiKey = process.env.API_KEY;
```

### Missing Error Handling
```javascript
// ❌ BAD
async function fetchData() {
  const data = await api.getData();
  return data;
}

// ✅ GOOD
async function fetchData() {
  try {
    const data = await api.getData();
    return data;
  } catch (error) {
    logger.error('Failed to fetch data', error);
    throw error;
  }
}
```

### Unvalidated Redirect
```javascript
// ❌ BAD
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// ✅ GOOD
app.get('/redirect', (req, res) => {
  const allowedDomains = ['example.com'];
  const url = new URL(req.query.url);
  if (allowedDomains.includes(url.hostname)) {
    res.redirect(req.query.url);
  } else {
    res.status(400).send('Invalid redirect');
  }
});
```

## 📈 Severity Levels

| Level | Icon | Description | Action Required |
|-------|------|-------------|-----------------|
| Critical | 🔴 | Exploitable security flaw | Fix immediately |
| High | 🟠 | Significant security risk | Fix in current sprint |
| Medium | 🟡 | Potential vulnerability | Fix in next sprint |
| Low | 🔵 | Code quality issue | Address when convenient |
| Note | ⚪ | Suggestion | Optional improvement |

## 🔄 Workflow Triggers

The CodeQL scan runs on:
- ✅ Push to `main` branch
- ✅ Pull requests to `main`
- ✅ Weekly schedule (Fridays at 8:17 AM UTC)
- ✅ Manual workflow dispatch

## 📚 Useful Links

- [Full Setup Guide](./CODEQL_SETUP.md)
- [CodeQL Docs](https://codeql.github.com/docs/)
- [JavaScript Queries](https://codeql.github.com/codeql-standard-libraries/javascript/)
- [Query Help](https://codeql.github.com/codeql-query-help/)
- [CWE Reference](https://cwe.mitre.org/)

## 💡 Pro Tips

1. **Run locally before pushing** - Catch issues early
2. **Review alerts weekly** - Don't let them pile up
3. **Customize for your stack** - Add queries for your specific frameworks
4. **Use suppressions wisely** - Document why you're suppressing
5. **Keep queries updated** - New vulnerability patterns emerge regularly

---

**Need Help?** Check the [full documentation](./CODEQL_SETUP.md) or open an issue.