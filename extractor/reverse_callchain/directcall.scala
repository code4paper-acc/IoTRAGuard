import io.shiftleft.codepropertygraph.generated.nodes.Method
import scala.collection.mutable.{ListBuffer, HashSet}
import io.shiftleft.semanticcpg.language._

val targetFuncName = "register_dispatcher"
val targetFilePath = "subsys/net/lib/dns/resolve.c"

val targetMethod = cpg.method
  .name(targetFuncName)
  .filter(_.file.name.headOption.exists(_.contains(targetFilePath)))
  .headOption.getOrElse(throw new RuntimeException("Target not found"))

println(s"Starting analysis from: ${targetMethod.fullName}")

val allChains = ListBuffer[List[Map[String, String]]]()

def traverse(node: Method, path: List[Method], visited: Set[String]): Unit = {
  val currentChain = path :+ node
  
  
  val callers = node.callIn.method.filterNot(_.name.startsWith("<operator>")).l
  
  if (callers.isEmpty || node.name == "<global>") {
    saveChain(currentChain)
    return
  }

  var hasValidCaller = false
  callers.foreach { caller =>
    
    if (!visited.contains(caller.fullName)) {
      hasValidCaller = true
      traverse(caller, currentChain, visited + caller.fullName)
    }
  }
  
  
  if (!hasValidCaller) {
    saveChain(currentChain)
  }
}

def saveChain(methods: List[Method]): Unit = {
  val chainData = methods.map { m =>
    Map(
      "name" -> m.name,
      "file" -> m.file.name.headOption.getOrElse("N/A"),
      "is_public" -> m.tag.name("PUBLIC_API").nonEmpty.toString,
      "id" -> m.fullName
    )
  }
  allChains += chainData
}

traverse(targetMethod, List(), Set(targetMethod.fullName))

val jsonOutput = allChains.map { chain =>
  chain.map { node =>
    s"""{"name": "${node("name")}", "file": "${node("file")}", "is_public": ${node("is_public")}}"""
  }.mkString("[", ", ", "]")
}.mkString("[\n  ", ",\n  ", "\n]")

println(jsonOutput)
