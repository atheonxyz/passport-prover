plugins {
    kotlin("jvm") version "1.9.24"
    application
}

group = "verity.passport"
version = "0.1.0"

repositories {
    mavenCentral()
}

// Verity SDK source directory — we compile its Kotlin sources directly
// since it's an Android library and we need a JVM executable.
// The native JNI library (libverity_jni.so / .dylib) must be on
// java.library.path at runtime.
// Clone https://github.com/atheonxyz/verity and place at ../../verity relative to this repo,
// or set VERITY_DIR env var.
val verityDir = System.getenv("VERITY_DIR") ?: "../../../verity"
val veritysdkSrcDir = file("$verityDir/sdks/kotlin/src/main/kotlin")

sourceSets {
    main {
        kotlin {
            // Include Verity SDK sources alongside our own
            if (veritysdkSrcDir.exists()) {
                srcDir(veritysdkSrcDir)
            }
        }
    }
}

dependencies {
    // ASN.1 / CMS / X.509 parsing
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // JSON (used by Verity SDK's Witness.fromJson and our witness serialization)
    implementation("org.json:json:20240303")

    // Testing
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("verity.passport.prover.MainKt")
}

// Build a fat JAR with all dependencies
tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "verity.passport.prover.MainKt"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    // Exclude JAR signature files (BouncyCastle jars are signed and break fat JARs)
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    with(tasks.jar.get())
}
