/**
 * @name Missing error handling in async functions
 * @description Detects async functions and promise chains without proper error handling
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id javascript/missing-error-handling
 * @tags reliability
 *       maintainability
 *       external/cwe/cwe-391
 */

import javascript

/**
 * Holds if the function is an async function
 */
predicate isAsyncFunction(Function f) {
  f instanceof AsyncFunction
}

/**
 * Holds if the call node is a promise-returning call
 */
predicate isPromiseReturningCall(CallExpr call) {
  // Common async methods
  call.getCalleeName().regexpMatch(".*(Async|async|fetch|query|execute|send|request|read|write|load|save)") or
  // Promise constructor
  call.getCallee().(GlobalVarAccess).getName() = "Promise" or
  // Known promise-returning APIs
  exists(string methodName | methodName = call.getCalleeName() |
    methodName = "fetch" or
    methodName = "readFile" or
    methodName = "writeFile" or
    methodName = "query" or
    methodName = "execute" or
    methodName = "connect"
  )
}

/**
 * Holds if the async function has a try-catch block
 */
predicate hasTryCatch(AsyncFunction f) {
  exists(TryStmt try |
    try.getEnclosingFunction() = f
  )
}

/**
 * Holds if the promise chain has a catch handler
 */
predicate hasCatchHandler(MethodCallExpr chain) {
  exists(MethodCallExpr catch |
    catch.getReceiver*() = chain and
    catch.getMethodName() = "catch"
  )
}

/**
 * Holds if the call is in a try block
 */
predicate isInTryBlock(CallExpr call) {
  exists(TryStmt try |
    call.getParent*() = try.getBody()
  )
}

/**
 * Holds if the call has a catch in the promise chain
 */
predicate hasPromiseCatch(CallExpr call) {
  exists(MethodCallExpr chain |
    chain.getReceiver*() = call and
    chain.getMethodName() = "catch"
  )
}

/**
 * Holds if the function result is awaited
 */
predicate isAwaited(CallExpr call) {
  exists(AwaitExpr await |
    await.getOperand() = call
  )
}

from Expr e, string message
where
  (
    // Async functions without try-catch blocks
    exists(AsyncFunction f |
      e = f and
      not hasTryCatch(f) and
      // Contains await expressions
      exists(AwaitExpr await |
        await.getEnclosingFunction() = f
      ) and
      // Not in a top-level handler (like route handlers might have error middleware)
      not f.getName().regexpMatch(".*(handler|Handler|middleware|Middleware)") and
      message = "Async function '" + f.getName() + "' uses await but lacks try-catch error handling"
    )
  ) or
  (
    // Await expressions not in try-catch
    exists(AwaitExpr await, AsyncFunction f |
      e = await and
      await.getEnclosingFunction() = f and
      not isInTryBlock(await.getOperand()) and
      not hasTryCatch(f) and
      message = "Await expression without try-catch or surrounding error handler"
    )
  ) or
  (
    // Promise chains without catch
    exists(MethodCallExpr chain |
      e = chain and
      (chain.getMethodName() = "then" or chain.getMethodName() = "finally") and
      not hasCatchHandler(chain) and
      not isInTryBlock(chain) and
      // Not already awaited (handled by async/await rules)
      not exists(AwaitExpr await | await.getOperand() = chain) and
      message = "Promise chain with ." + chain.getMethodName() + "() but no .catch() handler"
    )
  ) or
  (
    // Promise-returning calls without await or catch
    exists(CallExpr call |
      e = call and
      isPromiseReturningCall(call) and
      not isAwaited(call) and
      not hasPromiseCatch(call) and
      not isInTryBlock(call) and
      // Not returned (caller might handle it)
      not exists(ReturnStmt ret | ret.getExpr() = call) and
      // Not assigned to a variable (might be handled later)
      not exists(VariableDeclarator vd | vd.getInit() = call) and
      message = "Promise-returning call without await, .catch(), or error handling"
    )
  )
select e, message
