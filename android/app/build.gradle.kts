plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.pocketufw"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.pocketufw"
        minSdk = 26
        targetSdk = 35
        versionCode = 26
        versionName = "0.1.0-beta5"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.8" }
    testOptions { unitTests { isIncludeAndroidResources = true } }

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
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.04.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    // Audit regression tooling is test-only; never bundled into the APK.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation(platform("androidx.compose:compose-bom:2024.04.01"))
    testImplementation("androidx.compose.ui:ui-test-junit4")
}
