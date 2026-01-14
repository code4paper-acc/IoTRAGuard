val cpgPath = sys.env.getOrElse("CPG_PATH", throw new Exception("CPG_PATH is not set"))
val outPath = sys.env.getOrElse("OUTPUT_PATH", throw new Exception("OUTPUT_PATH is not set"))


importCpg(cpgPath)


val buf = scala.collection.mutable.ArrayBuffer.empty[String]

cpg.method
  .nameNot(".*<init>.*")
  .foreach { m =>
    val fileName = Option(m.filename).filter(_.nonEmpty).getOrElse("unknown_file")
    val funcName = Option(m.name).filter(_.nonEmpty).getOrElse("unknown_func")
    val paramTps = m.parameter.map(p => Option(p.typeFullName).filter(_.nonEmpty).getOrElse("unknown_type")).l.mkString(",")
    val startLn  = m.lineNumber.getOrElse(-1)     
    val endLn    = m.lineNumberEnd.getOrElse(-1)

    buf += raw"$fileName||$funcName||$paramTps||$startLn||$endLn"
  }


val out = java.io.File(outPath)
Option(out.getParentFile).foreach(_.mkdirs())
val pw = java.io.PrintWriter(out)
buf.foreach(pw.println)
pw.close()

println(s"Extraction completed, total ${buf.size} entries, written to $outPath")