import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.semanticcpg.language._

val targets = List("cmd_wifi_connect", "cmd_wifi_ap_enable", "nrf5_tx", "fatfs_stat")

targets.map { funcName =>
  println(s"--- Unified Analysis for: $funcName ---")

  val astHits = cpg.methodRef
     .filter(_.methodFullName.endsWith(funcName))
     .map { ref =>
       var ctx = ref.astParent
       var depth = 0
       val maxDepth = 20
       
       var containerVar = "UNKNOWN"
       var finalCode = "<empty>"
       var foundAnyAssignment = false
       
       while (depth < maxDepth && ctx.label != "METHOD" && ctx.label != "TYPE_DECL") {
         
         if (ctx.isCall && ctx.asInstanceOf[nodes.Call].name == "<operator>.assignment") {
            val callNode = ctx.asInstanceOf[nodes.Call]
            
            val lhsCode = callNode.start.argument(1).code.headOption.getOrElse("")
            
            if (lhsCode.nonEmpty) {
                containerVar = lhsCode
                
                var bestCode = ctx.code 
                
                val defNode = callNode.start.argument(1).isIdentifier.refsTo.headOption
                
                if (defNode.nonEmpty) {
                    val defCode = defNode.get.asInstanceOf[nodes.AstNode].code
                    
                    if (defCode.contains("struct") || defCode.contains("static") || defCode.contains(containerVar)) {
                        bestCode = defCode
                    }
                }
                // ----------------------------------

                finalCode = bestCode
                foundAnyAssignment = true
            }
         } 

         if (ctx.astParent != null) {
            ctx = ctx.astParent
            depth += 1
         } else {
            depth = maxDepth
         }
       }
       
       if (!foundAnyAssignment && (finalCode == "<global>" || finalCode == "<empty>")) {
           finalCode = "INVALID"
       }

       Map(
         "source" -> "AST_GREEDY_SEARCH",
         "function" -> funcName,
         "container_var" -> containerVar,
         "code" -> finalCode, 
         "file" -> ref.file.name.headOption.getOrElse("N/A"),
         "line" -> ref.lineNumber.getOrElse(-1).toString
       )
     }
     .filterNot(_("code") == "INVALID")
     .l

  if (astHits.isEmpty) {
      cpg.unknown.filter(_.code.contains(funcName)).map { node =>
       Map(
         "source" -> "UNKNOWN_NODE_SEARCH",
         "function" -> funcName,
         "container_var" -> "UNKNOWN_MACRO",
         "code" -> node.code,
         "file" -> node.file.name.headOption.getOrElse("N/A"),
         "line" -> node.lineNumber.getOrElse(-1).toString
       )
     }.l
  } else {
     astHits.groupBy(r => r("code") + r("file")).map(_._2.head).toList
  }
}.flatten.foreach(println)