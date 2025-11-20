/**
 * @name Hardcoded secrets or API keys
 * @description Detects potential hardcoded secrets, API keys, passwords, and tokens
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id javascript/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import javascript

/**
 * Holds if the string literal looks like it contains a secret
 */
predicate looksLikeSecret(StringLiteral s) {
  exists(string value | value = s.getValue() |
    // Check for common secret patterns
    (
      // API keys and tokens (at least 20 chars, alphanumeric)
      value.regexpMatch("(?i).*(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key).*") and
      value.length() > 20 and
      value.regexpMatch(".*[a-zA-Z0-9]{20,}.*")
    ) or
    (
      // AWS keys
      value.regexpMatch("AKIA[0-9A-Z]{16}")
    ) or
    (
      // Generic long alphanumeric strings in secret-related variables
      value.length() > 32 and
      value.regexpMatch("[a-zA-Z0-9+/=]{32,}") and
      not value.regexpMatch(".*[\\s].*") // no spaces
    )
  )
}

/**
 * Holds if the variable or property name suggests it holds a secret
 */
predicate isSecretRelatedName(string name) {
  name.regexpMatch("(?i).*(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth|credential).*") and
  not name.regexpMatch("(?i).*(hash|hashed|encrypted|example|test|mock|dummy|placeholder).*")
}

from Expr e, string message
where
  (
    // String literals that look like secrets
    exists(StringLiteral s |
      s = e and
      looksLikeSecret(s) and
      // Exclude common false positives
      not s.getValue().regexpMatch("(?i).*(example|test|mock|dummy|placeholder|xxx|yyy|zzz|TODO).*") and
      message = "Potential hardcoded secret or API key found in string literal"
    )
  ) or
  (
    // Variable declarations with secret-like names and non-empty string values
    exists(VariableDeclarator vd, StringLiteral s |
      vd.getInit() = s and
      e = vd and
      isSecretRelatedName(vd.getBindingPattern().getAName()) and
      s.getValue().length() > 8 and
      not s.getValue().regexpMatch("(?i).*(example|test|mock|dummy|placeholder|xxx|env\\.).*") and
      not s.getValue() = "" and
      message = "Potential hardcoded secret in variable '" + vd.getBindingPattern().getAName() + "'"
    )
  ) or
  (
    // Property assignments with secret-like names
    exists(Property p, StringLiteral s |
      p.getInit() = s and
      e = p and
      isSecretRelatedName(p.getName()) and
      s.getValue().length() > 8 and
      not s.getValue().regexpMatch("(?i).*(example|test|mock|dummy|placeholder|xxx|env\\.).*") and
      not s.getValue() = "" and
      message = "Potential hardcoded secret in property '" + p.getName() + "'"
    )
  )
select e, message
