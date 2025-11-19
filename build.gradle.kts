import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("org.zaproxy.add-on") version "0.12.0" // provides zapAddOn DSL and packaging
    `java-library` // provides implementation/test configs and test task
    // Optional: enable only if you need spotless tasks
    // id("com.diffplug.spotless") version "6.25.0"
}

version = "0.0.1" // REQUIRED so generateZapAddOnManifest succeeds

description = "Software Version Reporter with CVE Enrichment"

repositories {
    mavenCentral()
}

zapAddOn {
    addOnName.set("Software Version Reporter")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.15.0")
    manifest {
        author.set("Raghavendra Patil")
        url.set("https://www.zaproxy.org/docs/desktop/addons/software-version-reporter/")
    }
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

// Optional: only if Spotless plugin above is enabled
// spotless {
//     java {
//         target("src/**/*.java")
//         googleJavaFormat("1.17.0")
//     }
// }
