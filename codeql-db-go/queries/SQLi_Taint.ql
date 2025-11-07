/**
 * @name SQL injection from user input
 * @kind problem
 * @id org.go.sqli.taint
 * @problem.severity error
 * @tags security; external/cwe/cwe-89; owasp-a03
 */
import go
import semmle.go.security.dataflow.TaintTracking
import DataFlow::PathGraph

class DBQueryCall extends CallExpr {
  DBQueryCall() {
    this.getCallee().getQualifiedName().matches("%Query") or
    this.getCallee().getQualifiedName().matches("%Exec")
  }
}

class SQLiConfig extends TaintTracking::Configuration {
  SQLiConfig() { this = "SQLiConfig" }

  override predicate isSource(DataFlow::Node src) {
    exists(CallExpr c |
      src.asExpr() = c and
      c.getCallee().getQualifiedName().matches("%Query%") or
      c.getCallee().getQualifiedName().matches("%FormValue%") or
      c.getCallee().getQualifiedName().matches("%PostForm%") or
      c.getCallee().getQualifiedName().matches("%Param%") or
      c.getCallee().getQualifiedName().matches("%Bind%")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DBQueryCall q | sink.asExpr() = q.getArgument(0))
  }
}

from DataFlow::PathNode src, DataFlow::PathNode sink, SQLiConfig cfg
where cfg.hasFlowPath(src, sink)
select sink, "User-controlled data flows into database query: possible SQL injection.", src, sink, cfg.getEnclosingCallable(sink)