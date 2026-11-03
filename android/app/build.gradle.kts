plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.pocketufw.alpha"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.pocketufw.alpha"
        minSdk = 26
        targetSdk = 35
        versionCode = 14
        versionName = "0.1.0-alpha14"
    }

    buildTypes {
        release { isMinifyEnabled = false }
        debug { isMinifyEnabled = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.8" }

    sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("generated/firewallAssets"))
}

val stageFirewallAssets by tasks.registering(Copy::class) {
    // Source of truth is the repository root; don't hand-edit duplicate copies.
    from(rootProject.file("../pocketufw"))
    from(rootProject.file("../vpn-probe"))
    from(rootProject.file("../bootctl"))
    from(rootProject.file("../boot-service"))
    from(rootProject.file("../android-bridge"))
    from(rootProject.file("../rules-report"))
    from(rootProject.file("../udp-config"))
    into(layout.buildDirectory.dir("generated/firewallAssets"))
}
tasks.named("preBuild") { dependsOn(stageFirewallAssets) }

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.activity:activity-compose:1.8.1")
    implementation(platform("androidx.compose:compose-bom:2024.04.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
}
