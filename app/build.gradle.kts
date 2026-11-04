plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "snf.app"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.ohaiibuzzle.snf"
        minSdk = 29 // getConnectionOwnerUid
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
    }
    buildFeatures { compose = true }
}

dependencies {
    implementation(files("libs/core.aar"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    // shortcut: icon library is frozen at 1.7.8 (deprecated); swap for Material Symbols drawables if it ever breaks.
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.13.0")
}
