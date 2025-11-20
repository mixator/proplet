# CodeQL Query Testing Guide

This guide explains how to test your custom CodeQL queries to ensure they correctly detect vulnerabilities and minimize false positives.

## Quick Start

```bash
# Test all queries in the pack
codeql test run codeql-custom-queries-javascript/

# Test a specific query
codeql query run codeql-custom-queries-javascript/hardcoded-secrets.ql --database=codeql-db

# Create a test database
codeql database create test-db --language=javascript-typescript --source-root=./test-code
```

## Testing Methodology

### 1. Create Test Cases

For each query, create test files with both vulnerable and safe code examples.

**Directory Structure:**
```
codeql-custom-queries-javascript/
├── tests/
│   ├── hardcoded-secrets/
│   │   ├── test.js
│   │   └── test.expected
│   ├── sql-injection/
│   │   ├── test.js
│   │   └── test.expected
│   └── ...
```

### 2. Example Test File

**tests/hardcoded-secrets/test.js:**
```javascript
// Should trigger: Hardcoded API key
const apiKey1 = "sk_live_abc123xyz789def456ghi012jkl345"; // $ MISSING: hardcoded-credentials

// Should trigger: AWS key
const awsKey = "AKIAIOSFODNN7EXAMPLE"; // $ MISSING: hardcoded-credentials

// Should NOT trigger: Environment variable
const apiKey2 = process.env.API_KEY;

// Should NOT trigger: Example/placeholder
const apiKey3 = "your_api_key_here";

// Should trigger: Password
const password = "SuperSecret123Password!"; // $ MISSING: hardcoded-credentials

// Should NOT trigger: Short string
const status = "active";

// Should NOT trigger: Commented example
// const apiKey = "sk_live_example123";

// Should trigger: Database password
const config = {
  user: "admin",
  password: "MyDatabaseP@ssw0rd123" // $ MISSING: hardcoded-credentials
};
```

**tests/hardcoded-secrets/test.expected:**
```
| test.js:2:17:2:53 | Potential hardcoded secret or API key found in string literal |
| test.js:5:16:5:36 | Potential hardcoded secret or API key found in string literal |
| test.js:14:17:14:43 | Potential hardcoded secret in variable 'password' |
| test.js:22:13:22:39 | Potential hardcoded secret in property 'password' |
```

### 3. Run Tests

```bash
# Run all tests
codeql test run codeql-custom-queries-javascript/tests/

# Run specific test
codeql test run codeql-custom-queries-javascript/tests/hardcoded-secrets/

# Update expected results (after verifying changes are correct)
codeql test run codeql-custom-queries-javascript/tests/ --update
```

## Writing Effective Tests

### True Positives (Should Detect)

Test cases that SHOULD trigger alerts:

```javascript
// SQL Injection - Direct concatenation
const query1 = `SELECT * FROM users WHERE id = ${userId}`; // SHOULD DETECT

// SQL Injection - Template literal
const query2 = `DELETE FROM users WHERE name = '${userName}'`; // SHOULD DETECT

// Unvalidated Redirect - Query parameter
res.redirect(req.query.returnUrl); // SHOULD DETECT

// Missing Error Handling - Unhandled await
async function getData() {
  const result = await fetch(url); // SHOULD DETECT (no try-catch)
  return result;
}

// Console.log - Production code
function processPayment(data) {
  console.log('Payment data:', data); // SHOULD DETECT
  return stripe.charge(data);
}
```

### True Negatives (Should NOT Detect)

Test cases that should NOT trigger alerts:

```javascript
// SQL Injection - Parameterized query
const query1 = 'SELECT * FROM users WHERE id = $1'; // SHOULD NOT DETECT
db.query(query1, [userId]);

// SQL Injection - ORM usage
db.select().from(users).where(eq(users.id, userId)); // SHOULD NOT DETECT

// Unvalidated Redirect - Validated URL
if (ALLOWED_DOMAINS.includes(new URL(returnUrl).hostname)) {
  res.redirect(returnUrl); // SHOULD NOT DETECT
}

// Missing Error Handling - Proper try-catch
async function getData() {
  try {
    const result = await fetch(url); // SHOULD NOT DETECT
    return result;
  } catch (error) {
    logger.error(error);
    throw error;
  }
}

// Console.log - Test file (test.js)
test('should work', () => {
  console.log('test output'); // SHOULD NOT DETECT (test file)
});

// Console.log - Dev block
if (process.env.NODE_ENV !== 'production') {
  console.log('debug info'); // SHOULD NOT DETECT
}
```

### Edge Cases

Test boundary conditions:

```javascript
// Hardcoded Secrets - Edge cases
const short = "abc123"; // SHOULD NOT DETECT (too short)
const long = "a".repeat(50); // SHOULD NOT DETECT (no secret pattern)
const encoded = Buffer.from('secret').toString('base64'); // CONSIDER
const encrypted = encryptSecret('actual_secret'); // SHOULD NOT DETECT

// SQL Injection - Edge cases
const staticQuery = 'SELECT * FROM users'; // SHOULD NOT DETECT (no user input)
const number = parseInt(userId); // SHOULD NOT DETECT (sanitized)
const query = sql`SELECT * FROM users WHERE id = ${userId}`; // SHOULD NOT DETECT (tagged template)

// Path Traversal - Edge cases
const safePath = path.join(BASE_DIR, sanitize(filename)); // SHOULD NOT DETECT
const relativePath = './data.txt'; // SHOULD NOT DETECT (relative, no user input)
```

## Test Annotations

Use special comments to mark expected results:

```javascript
// SHOULD trigger on this line
const bad = "sk_live_key123"; // $ MISSING: hardcoded-credentials

// Should NOT trigger
const good = process.env.KEY;

// Multiple issues on same line
const query = `DELETE FROM ${table} WHERE id = ${id}`; // $ MISSING: sql-injection $ MISSING: sql-injection
```

## Automated Testing with GitHub Actions

Add to your workflow:

```yaml
name: Test CodeQL Queries

on:
  push:
    paths:
      - 'codeql-custom-queries-javascript/**'
  pull_request:
    paths:
      - 'codeql-custom-queries-javascript/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v4
        with:
          languages: javascript-typescript
      
      - name: Run Query Tests
        run: |
          cd codeql-custom-queries-javascript
          codeql test run tests/
          
      - name: Check for test failures
        run: |
          if [ $? -ne 0 ]; then
            echo "❌ Query tests failed"
            exit 1
          fi
          echo "✅ All query tests passed"
```

## Performance Testing

### Measure Query Performance

```bash
# Time query execution
time codeql query run hardcoded-secrets.ql --database=codeql-db

# Get detailed performance metrics
codeql query run hardcoded-secrets.ql \
  --database=codeql-db \
  --evaluator-log evaluator.log

# Analyze evaluator log
codeql query run-log analyze evaluator.log
```

### Performance Guidelines

- **< 1 second**: Excellent (simple queries)
- **1-10 seconds**: Good (moderate complexity)
- **10-60 seconds**: Acceptable (complex data flow)
- **> 60 seconds**: Needs optimization

### Optimization Tips

1. **Add early filters:**
```ql
// Bad - evaluates everything
from CallExpr call
where call.getCalleeName() = "query"
select call

// Good - filters early
from CallExpr call
where 
  call.getCalleeName() = "query" and
  call.getFile().getBaseName().matches("%.js")
select call
```

2. **Use specific predicates:**
```ql
// Bad - too broad
from Expr e
where e.toString().matches("%password%")

// Good - specific type
from StringLiteral s
where s.getValue().matches("%password%")
```

3. **Limit recursion depth:**
```ql
// Bad - unlimited recursion
expr.getAChild*()

// Good - limited recursion
expr.getAChild().getAChild().getAChild()
```

## Validation Checklist

Before committing a new query:

- [ ] Query compiles without errors
- [ ] At least 5 true positive test cases
- [ ] At least 5 true negative test cases
- [ ] Edge cases covered
- [ ] Performance < 60 seconds on medium codebase
- [ ] Documentation includes:
  - [ ] @name (user-friendly)
  - [ ] @description (clear explanation)
  - [ ] @kind (problem or path-problem)
  - [ ] @problem.severity (error/warning/note)
  - [ ] @security-severity (0.0-10.0)
  - [ ] @precision (low/medium/high)
  - [ ] @id (unique identifier)
  - [ ] @tags (security/reliability/etc)
- [ ] False positive rate < 10%
- [ ] No overlap with existing queries

## Common Testing Pitfalls

### 1. Over-fitting to Examples

**Problem:**
```ql
// Only detects exact pattern
where s.getValue() = "sk_live_abc123"
```

**Solution:**
```ql
// Detects pattern family
where s.getValue().regexpMatch("sk_live_[a-zA-Z0-9]{20,}")
```

### 2. Missing Sanitizers

**Problem:**
```ql
// Doesn't account for validation
override predicate isSink(DataFlow::Node sink) {
  sink = any(SqlQuery q)
}
```

**Solution:**
```ql
override predicate isSanitizer(DataFlow::Node node) {
  node = any(ValidationCall v)
}
```

### 3. Ignoring Context

**Problem:**
```ql
// Flags all console.log
from CallExpr call
where call.getCallee().(PropAccess).getPropertyName() = "log"
```

**Solution:**
```ql
// Excludes test files and dev blocks
from CallExpr call
where 
  call.getCallee().(PropAccess).getPropertyName() = "log" and
  not call.getFile().getBaseName().matches("%test%") and
  not isInDevBlock(call)
```

## Debugging Failed Tests

### 1. Query Didn't Fire

```bash
# Check what the query sees
codeql query run your-query.ql --database=test-db --output=debug.csv --format=csv

# Inspect the AST
codeql query run show-ast.ql --database=test-db
```

### 2. Too Many False Positives

```bash
# Analyze matches
codeql query run your-query.ql --database=test-db --format=csv > results.csv

# Review each match
grep "SHOULD NOT" results.csv
```

### 3. Performance Issues

```bash
# Profile the query
codeql query run your-query.ql \
  --database=test-db \
  --evaluator-log evaluator.log

# Check which predicates are slow
codeql query run-log analyze evaluator.log --sort-key time
```

## Continuous Improvement

### Monthly Review

1. Check false positive rate from production runs
2. Review dismissed alerts
3. Update queries based on new patterns
4. Add tests for missed vulnerabilities

### Quarterly Audit

1. Compare with standard CodeQL queries
2. Update to latest CodeQL version
3. Benchmark performance on large codebases
4. Document lessons learned

## Resources

- [CodeQL Testing Guide](https://codeql.github.com/docs/writing-codeql-queries/testing-queries/)
- [Query Writing Best Practices](https://codeql.github.com/docs/writing-codeql-queries/)
- [Standard Query Test Suite](https://github.com/github/codeql/tree/main/javascript/ql/test)
- [Performance Tips](https://codeql.github.com/docs/writing-codeql-queries/performance-tips/)

## Getting Help

- Review standard query tests in the CodeQL repo
- Ask in [CodeQL Discussions](https://github.com/github/codeql/discussions)
- Check [Stack Overflow](https://stackoverflow.com/questions/tagged/codeql)

---

**Remember:** Good tests are the foundation of reliable security scanning. Invest time in comprehensive test coverage!