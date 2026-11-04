plugins {
    id("com.android.application")
}
android {
    namespace = "io.github.pocketufw.neonicons"
    compileSdk = 36
    defaultConfig {
        applicationId = "io.github.pocketufw.neonicons"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.1.1"
    }
    buildTypes {
        release { isMinifyEnabled = false }
        debug { isMinifyEnabled = false }
    }
}
