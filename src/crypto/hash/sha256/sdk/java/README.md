# ABC SHA-256 for Java

The research `windows-amd64` artifact contains an ABC C ABI library and a JNI adapter. The byte-array API runs on JDK 17 and identifies its actual native provider. `finish()` closes the current hash operation. `reset()` begins a fresh message. Close the native context with try-with-resources. JVM operations on a context are synchronized by the binding.

The platform-classified JAR uses candidate Maven coordinates `org.allbasket:abc-sha256:0.1.0:windows-amd64`. JDK 17 was selected because JNI supports the existing C ABI on it without requiring the newer Foreign Function and Memory API. Android and other desktop platforms need independent evidence.
