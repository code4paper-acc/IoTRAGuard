import io.shiftleft.codepropertygraph.generated.nodes.Method
import scala.collection.mutable.{ArrayBuffer, HashMap, HashSet}

// ---------- Environment ----------
val cpgPath        = sys.env.getOrElse("CPG_PATH",        throw new Exception("CPG_PATH not set"))
val targetFuncName = sys.env.getOrElse("TARGET_FUNC_NAME",throw new Exception("TARGET_FUNC_NAME not set"))
val targetFilePath = sys.env.getOrElse("TARGET_FILE_PATH",throw new Exception("TARGET_FILE_PATH not set"))
val outputPath     = sys.env.getOrElse("OUTPUT_PATH",     throw new Exception("OUTPUT_PATH not set"))
importCpg(cpgPath)

// ---------- 1. Locate Target ----------
val targetMethod = cpg.method
  .name(targetFuncName)
  .filter(_.file.name.headOption.exists(_.contains(targetFilePath)))
  .headOption
  .getOrElse(throw new Exception(s"Target not found: $targetFuncName  File: $targetFilePath"))

val targetFullName = targetMethod.fullName
val targetName     = targetMethod.name
val targetFile     = targetMethod.file.name.head
println(s"Target found: $targetFullName  (File: $targetFile)")

// ---------- 2. Build Reverse Call Graph ----------
val callChainMap = HashMap[String, List[Method]]()
val done         = HashSet[String]()

def callersOf(m: Method): List[Method] =
  m.callIn.method.filterNot(_.name.startsWith("<operator>")).toList

def build(cur: List[Method]): Unit = cur match {
  case Nil =>
  case h :: t =>
    val fname = h.fullName
    if (!done.contains(fname)) {
      done.add(fname)
      val callers = callersOf(h)
      callChainMap += fname -> callers
      build(t ++ callers.filterNot(c => done.contains(c.fullName)))
    } else build(t)
}

build(List(targetMethod))
println(s"Call graph built, ${done.size} nodes")

// ---------- 3. Generate Patterns with File ----------
val callPatterns = ArrayBuffer[String]()
val visitedInGen = HashSet[String]()

def fmt(m: Method): String = s"${m.name}(${m.file.name.head})"

def generatePatterns(curFullName: String, path: List[String]): Unit = {
  if (visitedInGen.contains(curFullName)) return
  visitedInGen.add(curFullName)

  val callers = callChainMap.getOrElse(curFullName, Nil)
  if (callers.isEmpty) {
    val pattern = (fmt(targetMethod) +: path).mkString("<-")
    callPatterns += pattern
  } else {
    callers.foreach { caller =>
      generatePatterns(caller.fullName, path :+ fmt(caller))
    }
  }
}

generatePatterns(targetFullName, Nil)

// ---------- 4. Output ----------
import java.io._
val writer = new PrintWriter(new File(outputPath))
callPatterns.foreach(writer.println)
writer.close()
println(s"Patterns written to $outputPath  (${callPatterns.size} chains)")