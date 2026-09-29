import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.gms.google-services") apply false
    id("io.gitlab.arturbosch.detekt")
}

if (file("google-services.json").exists()) apply(plugin = "com.google.gms.google-services")

val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "ru.vpncheck.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "ru.vpncheck.agent"
        minSdk = 26
        targetSdk = 35
        versionCode = 40
        versionName = "0.12.12"
        ndk { abiFilters += listOf("arm64-v8a") }
        buildConfigField("String", "SERVER", "\"${keystoreProps.getProperty("server", "http://127.0.0.1:8787")}\"")
        buildConfigField("String", "MANIFEST_PUBKEY", "\"${keystoreProps.getProperty("manifestPubKey", "")}\"")
        buildConfigField("String", "CORE_VERSION", "\"26.6.27\"")
    }

    signingConfigs {
        create("release") {
            if (keystoreProps.getProperty("storeFile") != null) {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    val ownKey = keystoreProps.getProperty("storeFile") != null
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName(if (ownKey) "release" else "debug")
        }
        debug {
            if (ownKey) signingConfig = signingConfigs.getByName("release")
        }
    }

    packaging {
        jniLibs { useLegacyPackaging = true }
    }

    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions {
        unitTests.all {
            val cases = rootProject.file("../tests/data/chain_cases.json")
            it.systemProperty("chainCases", cases.absolutePath)
            it.inputs.file(cases)
            val fields = rootProject.file("../stand/node_fields.json")
            it.systemProperty("nodeFields", fields.absolutePath)
            it.inputs.file(fields)
        }
    }
}

val coreLib = file("src/main/jniLibs/arm64-v8a/libxray.so")
tasks.configureEach {
    if (name == "preReleaseBuild") {
        doFirst {
            if (!coreLib.isFile) throw GradleException("libxray.so not found - run: python tools/fetch_binaries.py")
        }
    }
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(rootProject.file("detekt.yml"))
    source.setFrom("src/main/java")
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("com.google.android.gms:play-services-location:21.3.0")
    implementation(platform("com.google.firebase:firebase-bom:33.7.0"))
    implementation("com.google.firebase:firebase-messaging")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.vaadin.external.google:android-json:0.0.20131108.vaadin1")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
}
