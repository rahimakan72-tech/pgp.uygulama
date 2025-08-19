pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

// ✅ pluginManagement'tan SONRA plugins bloğu gelmeli
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Kibele"
include(":app")
