/**
 * @name SQL Injection vulnerability
 * @description Detects potential SQL injection vulnerabilities where user input flows into SQL queries
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id javascript/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript
import DataFlow::PathGraph

/**
 * A source of user input that could be malicious
 */
class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    // Request parameters
    this = any(HTTP::RequestInputAccess ria).getASourceNode() or
    // Query parameters
    exists(DataFlow::PropRead pr |
      pr.getPropertyName() = "query" or
      pr.getPropertyName() = "params" or
      pr.getPropertyName() = "body"
    |
      this = pr
    ) or
    // Environment variables (less direct but still user-controllable)
    exists(DataFlow::GlobalVarAccess gva |
      gva.getName() = "process" and
      this = gva.getAPropertyRead("env").getAPropertyRead()
    )
  }
}

/**
 * A SQL query execution sink
 */
class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    // SQL execution methods
    exists(DataFlow::CallNode call |
      (
        // Direct SQL execution
        call.getCalleeName().regexpMatch("(query|execute|exec|run|all|get|prepare)") or
        // Database query methods
        exists(string name | name = call.getCalleeName() |
          name = "query" or name = "execute" or name = "exec" or
          name = "raw" or name = "unsafe" or name = "sql"
        )
      ) and
      (
        this = call.getArgument(0) or
        this = call.getAnArgument()
      )
    ) or
    // Template literals used in SQL context
    exists(TemplateLiteral tl |
      this.asExpr() = tl.getAnElement() and
      exists(DataFlow::CallNode call |
        call.getAnArgument().asExpr() = tl
      )
    ) or
    // String concatenation in SQL context
    exists(AddExpr add |
      this.asExpr() = add.getAnOperand() and
      exists(string sqlKeyword |
        sqlKeyword = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "FROM", "WHERE"] |
        add.getAnOperand().(StringLiteral).getValue().toUpperCase().matches("%" + sqlKeyword + "%")
      )
    )
  }
}

/**
 * Configuration for tracking user input to SQL queries
 */
class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInputSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node node) {
    // Parameterized queries (using $1, $2, etc.)
    exists(DataFlow::ArrayCreationNode arr |
      node = arr.getAnElement() and
      exists(DataFlow::CallNode call |
        call.getArgument(1) = arr
      )
    ) or
    // Validation/sanitization functions
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(sanitize|escape|validate|clean|parse).*") and
      node = call
    ) or
    // Type conversion that might sanitize
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["parseInt", "parseFloat", "Number"] and
      node = call
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SQL injection vulnerability: user input from $@ flows into SQL query", source.getNode(),
  "this source"
