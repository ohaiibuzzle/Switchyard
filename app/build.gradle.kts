plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "snf.app"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.ohaiibuzzle.switchyard"
        minSdk = 29 // getConnectionOwnerUid
        targetSdk = 36
        // CI passes the tag without its "v" (v0.1.3 -> 0.1.3); the code packs it so a later tag always upgrades.
        val ver = System.getenv("SNF_VERSION") ?: "0.1.0"
        val (major, minor, patch) = ver.split(".").map(String::toInt)
        versionName = ver
        versionCode = major * 1_000_000 + minor * 1_000 + patch
    }
    // Release signing comes from the environment (CI secrets, or your shell); without it the release APK is unsigned.
    signingConfigs {
        System.getenv("SNF_KEYSTORE")?.let { ks ->
            create("release") {
                storeFile = file(ks)
                storePassword = System.getenv("SNF_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("SNF_KEY_ALIAS")
                keyPassword = System.getenv("SNF_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
            // The Go bindings' keep rules ship inside core.aar (go.**, snf.**).
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    // One APK per ABI core.aar is built for (phones; x86 Chromebooks and the emulator), plus a universal one.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }
    // Compose's tiny 32-bit libs would let a 32-bit device install the universal APK, then crash without the engine.
    packaging {
        jniLibs {
            excludes += listOf("lib/x86/**", "lib/armeabi-v7a/**")
            useLegacyPackaging = true // compressed: the Go engine is 21 MB raw, ~8 MB zipped; unpacked once at install
        }
    }
    buildFeatures { compose = true }
}

dependencies {
    implementation(files("libs/core.aar"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material3:material3-adaptive-navigation-suite")
    // shortcut: icon library is frozen at 1.7.8 (deprecated); swap for Material Symbols drawables if it ever breaks.
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.13.0")
}
