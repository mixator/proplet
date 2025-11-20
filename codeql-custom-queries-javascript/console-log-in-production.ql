/**
 * @name Console log statements in production code
 * @description Detects console.log and similar debug statements that should not be in production code
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id javascript/console-log-in-production
 * @tags maintainability
 *       best-practice
 */

import javascript

/**
 * A call to a console method that is typically used for debugging
 */
class DebugConsoleCall extends CallExpr {
  DebugConsoleCall() {
    exists(PropAccess prop |
      prop = this.getCallee() and
      prop.getBase().(GlobalVarAccess).getName() = "console" and
      (
        prop.getPropertyName() = "log" or
        prop.getPropertyName() = "debug" or
        prop.getPropertyName() = "trace" or
        prop.getPropertyName() = "dir" or
        prop.getPropertyName() = "dirxml" or
        prop.getPropertyName() = "table" or
        prop.getPropertyName() = "time" or
        prop.getPropertyName() = "timeEnd" or
        prop.getPropertyName() = "timeLog" or
        prop.getPropertyName() = "profile" or
        prop.getPropertyName() = "profileEnd" or
        prop.getPropertyName() = "count" or
        prop.getPropertyName() = "countReset"
      )
    )
  }

  string getMethodName() {
    result = this.getCallee().(PropAccess).getPropertyName()
  }
}

/**
 * Holds if the call is in a test file
 */
predicate isInTestFile(CallExpr call) {
  call.getFile().getBaseName().regexpMatch(".*\\.(test|spec)\\.(ts|js|tsx|jsx)") or
  call.getFile().getAbsolutePath().matches("%/__tests__/%") or
  call.getFile().getAbsolutePath().matches("%/test/%") or
  call.getFile().getAbsolutePath().matches("%/tests/%")
}

/**
 * Holds if the call is in a development-only code block
 */
predicate isInDevBlock(CallExpr call) {
  exists(IfStmt ifStmt |
    call.getParent*() = ifStmt.getThen() and
    (
      // Check for process.env.NODE_ENV !== 'production'
      exists(Comparison cmp |
        cmp = ifStmt.getCondition().getUnderlyingValue() and
        cmp.getAnOperand().toString().matches("%NODE_ENV%") and
        cmp.getAnOperand().(StringLiteral).getValue() = "production" and
        cmp.getOperator() = "!=="
      ) or
      // Check for process.env.NODE_ENV === 'development'
      exists(Comparison cmp |
        cmp = ifStmt.getCondition().getUnderlyingValue() and
        cmp.getAnOperand().toString().matches("%NODE_ENV%") and
        cmp.getAnOperand().(StringLiteral).getValue() = "development" and
        cmp.getOperator() = "==="
      ) or
      // Check for __DEV__ or similar flags
      exists(VarAccess va |
        va = ifStmt.getCondition().getUnderlyingValue() and
        va.getName().regexpMatch("(__)?DEV(ELOPMENT)?(__)?")
      )
    )
  )
}

/**
 * Holds if the call is in a debug utility function
 */
predicate isInDebugFunction(CallExpr call) {
  exists(Function f |
    call.getEnclosingFunction() = f and
    f.getName().regexpMatch("(?i).*(debug|log|trace|print).*")
  )
}

/**
 * Holds if the call is part of an error logging strategy (console.error, console.warn are acceptable)
 */
predicate isErrorOrWarnCall(CallExpr call) {
  exists(PropAccess prop |
    prop = call.getCallee() and
    prop.getBase().(GlobalVarAccess).getName() = "console" and
    (
      prop.getPropertyName() = "error" or
      prop.getPropertyName() = "warn"
    )
  )
}

from DebugConsoleCall call
where
  not isInTestFile(call) and
  not isInDevBlock(call) and
  not isInDebugFunction(call) and
  not isErrorOrWarnCall(call)
select call,
  "console." + call.getMethodName() +
    "() call found in production code. Consider using a proper logging library or removing debug statements."
