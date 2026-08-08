import io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension
import org.gradle.kotlin.dsl.invoke
import org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES
import org.gradle.plugins.ide.idea.model.IdeaLanguageLevel

val junitJupiter: String by project

val testcontainersBom: String by project
val protobufBom: String by project
val guava: String by project
val jmh: String by project
val asm: String by project
val glassfishJson: String by project
val errorProneAnnotations: String by project
val j2objcAnnotations: String by project
val redisson: String by project

val jetty: String by project
val freemarker: String by project

val reflections: String by project

val sockjs: String by project
val stomp: String by project
val bootstrap: String by project
val springDocOpenapiUi: String by project
val jsr305: String by project

val grpc: String by project
val wiremock: String by project
val r2dbcPostgresql: String by project
val springDataBom: String by project


plugins {
    java
    idea
    id("fr.brouillard.oss.gradle.jgitver")
    id("io.spring.dependency-management")
    id("org.springframework.boot") apply false
    id("name.remal.sonarlint") apply false
    id("com.diffplug.spotless") apply false
}

idea {
    project {
        languageLevel = IdeaLanguageLevel(21)
    }
    module {
        isDownloadJavadoc = true
        isDownloadSources = true
    }
}

group = "ru.sinara.cryptoon"

repositories {
    mavenLocal()
    mavenCentral()

    flatDir {
        dirs = setOf(file("lib"))
    }
}



apply(plugin = "io.spring.dependency-management")
dependencyManagement {
    dependencies {
        imports {
            mavenBom(BOM_COORDINATES)
            mavenBom("org.testcontainers:testcontainers-bom:$testcontainersBom")
            mavenBom("com.google.protobuf:protobuf-bom:$protobufBom")
            mavenBom("org.springframework.data:spring-data-bom:$springDataBom")
        }
        dependency("com.google.guava:guava:$guava")
        dependency("org.openjdk.jmh:jmh-core:$jmh")
        dependency("org.openjdk.jmh:jmh-generator-annprocess:$jmh")
        dependency("org.ow2.asm:asm-commons:$asm")
        dependency("org.glassfish:jakarta.json:$glassfishJson")
        dependency("com.google.errorprone:error_prone_annotations:$errorProneAnnotations")
        dependency("com.google.j2objc:j2objc-annotations:$j2objcAnnotations")
        dependency("org.redisson:redisson:$redisson")

        dependency("com.google.code.findbugs:jsr305:$jsr305")
        dependency("com.github.tomakehurst:wiremock-standalone:$wiremock")

        dependency("org.junit.jupiter:junit-jupiter:$junitJupiter")
    }
}

// ---- test dependencies ----

dependencies {
    implementation(files("lib/JCSP.jar"))
    implementation(files("lib/JCP.jar"))
    implementation(files("lib/CAdES.jar"))
    implementation(files("lib/asn1rt.jar"))
    implementation(files("lib/ASN1P.jar"))
    implementation(files("lib/AdES-core.jar"))
    implementation(files("lib/cmsutil.jar"))

    testImplementation("org.junit.jupiter:junit-jupiter")
}

configurations.all {
    resolutionStrategy {
        failOnVersionConflict()

        force("javax.servlet:servlet-api:2.5")
        force("commons-logging:commons-logging:1.1.1")
        force("commons-lang:commons-lang:2.5")
        force("org.codehaus.jackson:jackson-core-asl:1.8.8")
        force("org.codehaus.jackson:jackson-mapper-asl:1.8.8")
        force("commons-io:commons-io:2.18.0")
        force("org.checkerframework:checker-qual:3.48.3")
    }
}


plugins.apply(JavaPlugin::class.java)
extensions.configure<JavaPluginExtension> {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-parameters", "-Xlint:all,-serial,-processing"))

    dependsOn("spotlessApply")
}
apply<name.remal.gradle_plugins.sonarlint.SonarLintPlugin>()
apply<com.diffplug.gradle.spotless.SpotlessPlugin>()
configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        palantirJavaFormat("2.63.0")
    }
}

plugins.apply(fr.brouillard.oss.gradle.plugins.JGitverPlugin::class.java)
extensions.configure<fr.brouillard.oss.gradle.plugins.JGitverPluginExtension> {
    strategy("PATTERN")
    nonQualifierBranches("main,master")
    tagVersionPattern("\${v}\${<meta.DIRTY_TEXT}")
    versionPattern(
        "\${v}\${<meta.COMMIT_DISTANCE}\${<meta.GIT_SHA1_8}" +
                "\${<meta.QUALIFIED_BRANCH_NAME}\${<meta.DIRTY_TEXT}-SNAPSHOT"
    )
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging.showExceptions = true
    reports {
        junitXml.required.set(true)
        html.required.set(true)
    }
}


tasks {
    val managedVersions by registering {
        doLast {
            project.extensions.getByType<DependencyManagementExtension>()
                .managedVersions
                .toSortedMap()
                .map { "${it.key}:${it.value}" }
                .forEach(::println)
        }
    }
}