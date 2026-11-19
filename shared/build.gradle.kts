plugins { kotlin("multiplatform") }
kotlin {
    jvm {
        val main = compilations.getByName("main")
        val smoke = compilations.create("smoke") {
            associateWith(main)
            defaultSourceSet.kotlin.apply {
                srcDirs("../tests", "../app/src/main/java/com/passwordprotection/vault")
                include("Smoke.kt", "Aead.kt")
            }
        }
        tasks.register<JavaExec>("smokeTest") {
            group = "verification"
            description = "Runs the standalone vault and portable-backup smoke suite."
            dependsOn(smoke.compileTaskProvider)
            classpath(smoke.output.allOutputs, smoke.runtimeDependencyFiles)
            mainClass.set("SmokeKt")
        }
    }
    jvmToolchain(17)
    if (System.getProperty("os.name").startsWith("Mac")) {
        iosArm64(); iosSimulatorArm64(); iosX64()
    }
}
