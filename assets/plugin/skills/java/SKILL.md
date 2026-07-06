---
name: java
description: Java archive and bytecode analysis
---

For JAR/WAR/EAR files:
1. `unravel_java_info` — archive metadata, class count, manifest, dependencies
2. `unravel_java_decompile` — decompile all classes to Java source (pure Go, no Java required)
3. `unravel_java_extract` — extract archive contents
4. `unravel_java_manifest` — MANIFEST.MF, web.xml, pom.xml details

The decompiler handles Java 8-21 bytecode with pattern recognition for string concatenation, autoboxing, enhanced for-each, and try-with-resources.
