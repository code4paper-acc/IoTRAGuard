import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.semanticcpg.language._

val targetVarName = "nrf5_radio_api" 

println(s"--- Finding Usage for Variable: $targetVarName ---")

val idHits = cpg.identifier
   .nameExact(targetVarName)
   .map { id =>
     
     val method = id.method
     Map(
       "source" -> "IDENTIFIER_USAGE",
       "user_func" -> method.name,
       "code" -> id.code,         
       "line" -> id.lineNumber.getOrElse(-1).toString,
       "file" -> method.file.name.headOption.getOrElse("N/A"),
       "is_global" -> (method.name == "<global>").toString
     )
   }
   .l


val unknownHits = cpg.unknown
   .filter(_.code.contains(targetVarName))
   .map { node =>
     Map(
       "source" -> "UNKNOWN_MACRO_USAGE",
       "user_func" -> "<global_macro>", 
       "code" -> node.code,
       "line" -> node.lineNumber.getOrElse(-1).toString,
       "file" -> node.file.name.headOption.getOrElse("N/A"),
       "is_global" -> "true"
     )
   }
   .l

val results = idHits ++ unknownHits

if (results.isEmpty) {
  println(s"No usage found for $targetVarName")
} else {
  results.groupBy(r => r("code") + r("line")).map(_._2.head).foreach(println)
}