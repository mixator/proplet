/**
 * @name Unvalidated URL redirect
 * @description Detects redirects to URLs derived from user input which can lead to open redirect vulnerabilities
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id javascript/unvalidated-url-redirect
 * @tags security
 *       external/cwe/cwe-601
 */

import javascript
import DataFlow::PathGraph

/**
 * A source of user-controlled input
 */
class UserControlledInput extends DataFlow::Node {
  UserControlledInput() {
    // Request parameters (query, body, params)
    exists(DataFlow::PropRead pr |
      pr.getPropertyName() = "query" or
      pr.getPropertyName() = "params" or
      pr.getPropertyName() = "body"
    |
      this = pr.getAPropertyRead()
    ) or
    // Direct access to request properties
    this = any(HTTP::RequestInputAccess ria).getASourceNode() or
    // URL search params
    exists(DataFlow::PropRead pr |
      pr.getPropertyName() = "searchParams"
    |
      this = pr.getAMethodCall("get")
    ) or
    // Headers (Referer, Origin, etc.)
    exists(DataFlow::MethodCallNode mcn |
      mcn.getMethodName() = "get" or mcn.getMethodName() = "header"
    |
      this = mcn
    )
  }
}

/**
 * A redirect sink where user input could cause an open redirect
 */
class RedirectSink extends DataFlow::Node {
  RedirectSink() {
    // Express/Hono redirect
    exists(DataFlow::MethodCallNode redirect |
      redirect.getMethodName() = "redirect" and
      this = redirect.getArgument(0)
    ) or
    exists(DataFlow::MethodCallNode redirect |
      redirect.getMethodName() = "redirect" and
      this = redirect.getArgument(1)
    ) or
    // Location header
    exists(DataFlow::MethodCallNode setHeader |
      setHeader.getMethodName() = "setHeader" or
      setHeader.getMethodName() = "set"
    |
      setHeader.getArgument(0).asExpr().(StringLiteral).getValue().toLowerCase() = "location" and
      this = setHeader.getArgument(1)
    ) or
    // Hono's c.redirect()
    exists(DataFlow::MethodCallNode hono |
      hono.getMethodName() = "redirect" and
      this = hono.getAnArgument()
    ) or
    // Response headers in object literals
    exists(Property p |
      p.getName().toLowerCase() = "location" and
      this.asExpr() = p.getInit()
    )
  }
}

/**
 * Taint tracking configuration for unvalidated redirects
 */
class UnvalidatedRedirectConfig extends TaintTracking::Configuration {
  UnvalidatedRedirectConfig() { this = "UnvalidatedRedirectConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserControlledInput
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof RedirectSink }

  override predicate isSanitizer(DataFlow::Node node) {
    // URL validation functions
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(validate|sanitize|check|verify|is).*[Uu][Rr][Ll].*") and
      node = call
    ) or
    // Allowlist checks
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() = "includes" or
        call.getCalleeName() = "startsWith" or
        call.getCalleeName() = "match"
      ) and
      node = call.getReceiver()
    ) or
    // URL parsing that extracts safe parts
    exists(DataFlow::NewNode url |
      url.getCalleeName() = "URL" and
      node = url.getAPropertyRead("pathname")
    ) or
    // Relative path sanitization (removing protocol)
    exists(DataFlow::MethodCallNode replace |
      replace.getMethodName() = "replace" and
      exists(RegExpLiteral re |
        re = replace.getArgument(0).asExpr() and
        re.getRoot().toString().matches("%https?%")
      ) and
      node = replace
    )
  }

  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode guard) {
    // Guards that check for relative URLs
    guard.asExpr().(MethodCallNode).getMethodName() = "startsWith" and
    guard.asExpr().(MethodCallNode).getArgument(0).asExpr().(StringLiteral).getValue() = "/" or
    // Guards that check against allowlist
    exists(DataFlow::MethodCallNode includes |
      includes.getMethodName() = "includes" and
      guard.asExpr() = includes
    )
  }
}

from UnvalidatedRedirectConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Unvalidated URL redirect from user-controlled input $@ may allow an attacker to redirect users to malicious sites",
  source.getNode(), "this source"
