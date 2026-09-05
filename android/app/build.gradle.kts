plugins {
    id("com.android.application")
    id("com.chaquo.python")
}
android {
    namespace = "io.ngagesims.dev"
    compileSdk = 35
    defaultConfig {
        applicationId = "io.ngagesims.dev"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-alpha"
        ndk { abiFilters += listOf("arm64-v8a") }
    }
}
chaquopy {
    defaultConfig {
        version = "3.13"
        pip {
            // Deliberately no Unicorn wheel here yet.
            // The existing desktop runtime imports `unicorn`; Android native
            // binding integration is the next gate.
        }
    }
}
