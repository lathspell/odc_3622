import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent.*
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.owasp.dependencycheck.gradle.extension.DataExtension

buildscript {
    dependencies {
        classpath("org.postgresql:postgresql:42.2.23") // für Task dependencyCheckAnalyze
    }
}

plugins {
    val kotlinVersion = "1.5.30"
    kotlin("jvm") version kotlinVersion
    kotlin("plugin.jpa") version kotlinVersion
    kotlin("plugin.spring") version kotlinVersion
    id("io.spring.dependency-management") version "1.0.11.RELEASE"
    id("org.springframework.boot") version "2.5.4"

    id("com.gorylenko.gradle-git-properties") version "2.3.1"   // erstellt "git.properties" mit "git.commit.id.abbrev"

    id("com.github.ben-manes.versions") version "0.39.0"        // https://github.com/ben-manes/gradle-versions-plugin for ":dependencyUpdates"
    id("com.dorongold.task-tree") version "2.1.0"               // https://github.com/dorongold/gradle-task-tree/ for ":taskTree"

    jacoco                                                      // Test Coverage Generator
    id("org.owasp.dependencycheck") version "6.3.1"             // OWASP Security Check
    id("org.sonarqube") version "3.3"                           // Code Quality Analyzer
}

group = "test"
java.sourceCompatibility = JavaVersion.VERSION_11

repositories {
    mavenCentral()
}

dependencies {
    // Kotlin
    implementation(kotlin("reflect"))
    val kotlinCoroutinesVersion = "1.5.2"
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:$kotlinCoroutinesVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactive:$kotlinCoroutinesVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:$kotlinCoroutinesVersion")
    // Spring Configuration
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    // Web & Security
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // HTTP Client
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    // Swagger / OpenAPI
    val springdocVersion = "1.5.10"
    implementation("org.springdoc:springdoc-openapi-ui:$springdocVersion")
    implementation("org.springdoc:springdoc-openapi-kotlin:$springdocVersion")
    implementation("org.springdoc:springdoc-openapi-security:$springdocVersion")
    // Prometheus
    runtimeOnly("io.micrometer:micrometer-registry-prometheus:1.7.3")
    // Datenbank
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.flywaydb:flyway-core:7.14.1")
    testImplementation("org.flywaydb.flyway-test-extensions:flyway-spring-test:7.0.0")
    runtimeOnly("org.postgresql:postgresql:42.2.23")
    // Validation
    implementation("org.springframework.boot:spring-boot-starter-validation")
    // JSON
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.12.5")
    // ZIP mit UTF-8
    implementation("org.apache.commons:commons-compress:1.21")
    // Logging
    runtimeOnly("net.logstash.logback:logstash-logback-encoder:6.6")
    // Tracing
    implementation("io.opentracing.contrib:opentracing-spring-jaeger-cloud-starter:3.3.1")
    // OAuth2
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server") // für Bearer-Tokens
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client") // für Login-Redirect
    // Tests
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.assertj", module = "assertj-core")
        exclude(group = "org.hamcrest", module = "hamcrest")
    }
    testImplementation("io.strikt:strikt-core:0.32.0")
    testImplementation("org.springframework.security:spring-security-test")
    val testContainersVersion = "1.16.0" // Transitive Dependency auf JUnit4 fliegt erst mit 2.0 raus
    testImplementation("org.testcontainers:testcontainers:$testContainersVersion") {
        exclude(group = "junit", module = "junit")
    }
    testImplementation("org.testcontainers:junit-jupiter:$testContainersVersion")
    testImplementation("org.testcontainers:postgresql:$testContainersVersion")
    val okhttpVersion = "4.9.1"
    testImplementation("com.squareup.okhttp3:mockwebserver:$okhttpVersion")
    testImplementation("com.squareup.okhttp3:okhttp:$okhttpVersion")
}

fun isStable(version: String): Boolean {
    val stableKeyword = setOf("RELEASE", "FINAL", "GA").any { version.toUpperCase().contains(it) }
    val stablePattern = version.matches(Regex("""^[0-9,.v-]+(-r)?$"""))
    return stableKeyword || stablePattern
}

tasks.withType<DependencyUpdatesTask> {
    rejectVersionIf {
        !isStable(candidate.version) && isStable(currentVersion) // no unstable proposals for stable dependencies
    }
    gradleReleaseChannel = "stable"
}

dependencyCheck {
    cveValidForHours = 24
    analyzers.assemblyEnabled = false
    suppressionFile = "./dependency-check-suppressions.xml"
    failBuildOnCVSS = 7.0f
    val dbUser = System.getenv("DEPENDENCYCHECK_READ_USER")
    if (dbUser != null) {
        autoUpdate = false
        data(closureOf<DataExtension> {
            driver = "org.postgresql.Driver"
            connectionString = "jdbc:postgresql://dependencycheck-postgresql.infra-security.svc.cluster.local:5432/dependencycheck?ssl=false"
            username = dbUser
            password = System.getenv("DEPENDENCYCHECK_READ_PASSWORD")
        })
    }
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "11"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()

    outputs.upToDateWhen { false } // Tests immer ausführen!
    testLogging.exceptionFormat = TestExceptionFormat.FULL
    testLogging.showStandardStreams = true // print all stdout/stderr output to console
    testLogging.minGranularity = 0 // show class and method names
    testLogging.events = setOf(SKIPPED, STARTED, PASSED, FAILED)
}

jacoco {
    // https://docs.gradle.org/current/userguide/jacoco_plugin.html
    toolVersion = "0.8.7"
}

tasks.jacocoTestReport {
    reports {
        html.isEnabled = true
        xml.isEnabled = true // für SonarQube
        csv.isEnabled = false
    }
}

sonarqube {
    properties {
        property("sonar.qualitygate.wait", "true")
        property(
            "sonar.exclusions", listOf(
                "build/generated-src/**"
            )
        )
    }
}
