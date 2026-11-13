package io.github.pocketufw

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Execute the copied command only against disposable host ZIPs and a temporary PREFIX. */
class TermuxInstallerTest {
    @get:Rule val temporary = TemporaryFolder()
    private lateinit var prefix: File
    private lateinit var commands: File
    private lateinit var apk: File
    private val helper = "#!/system/bin/sh\necho 'helper must not execute during installation'\n".toByteArray()
    private val digest get() = MessageDigest.getInstance("SHA-256").digest(helper)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private val destination get() = File(prefix, "bin/pufw")

    @Before fun setUp() {
        prefix = temporary.newFolder("Termux prefix")
        File(prefix, "bin").mkdir()
        commands = temporary.newFolder("commands")
        // Simulate Termux identity, even if a host test runner itself is root.
        fakeCommand("id", "printf '%s\\n' 10378")
        apk = File(temporary.root, "PocketUFW.apk")
        archive()
        destination.writeText("existing helper\n")
        Files.setPosixFilePermissions(destination.toPath(), PosixFilePermissions.fromString("rwx------"))
    }

    private fun fakeCommand(name: String, body: String) {
        File(commands, name).apply { writeText("#!/bin/sh\n$body\n"); setExecutable(true) }
    }

    private fun archive(bytes: ByteArray = helper, entry: String = "assets/$TERMUX_HELPER_ASSET") {
        ZipOutputStream(apk.outputStream()).use {
            it.putNextEntry(ZipEntry(entry))
            it.write(bytes)
            it.closeEntry()
        }
    }

    private data class Result(val exit: Int, val output: String)
    private fun runCommand(path: String = apk.absolutePath, extra: Map<String, String> = emptyMap()): Result {
        val command = termuxInstallCommand(path, digest)
        assertFalse("One copyable shell command", command.contains('\n'))
        val output = File(temporary.root, "command-output")
        val builder = ProcessBuilder("/bin/sh", "-c", command).directory(temporary.root)
            .redirectErrorStream(true).redirectOutput(output)
        builder.environment().apply {
            put("PREFIX", prefix.absolutePath)
            put("PATH", "${commands.absolutePath}:${System.getenv("PATH")}")
            putAll(extra)
        }
        val process = builder.start()
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            fail("Installer did not finish")
        }
        return Result(process.exitValue(), output.readText())
    }

    private fun assertNoTemporaryHelper() {
        assertTrue(File(prefix, "bin").listFiles()!!.none { it.name.startsWith(".pufw.") })
    }

    private fun assertPreserved(result: Result) {
        assertNotEquals(result.output, 0, result.exit)
        assertEquals("existing helper\n", destination.readText())
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(destination.toPath()))
        assertFalse(result.output.contains("pufw installed."))
        assertNoTemporaryHelper()
    }

    @Test fun copiesVerifiedBytesWithoutExecutingThemAndSetsPrivatePermissions() {
        val result = runCommand()
        assertEquals(result.output, 0, result.exit)
        assertArrayEquals(helper, destination.readBytes())
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(destination.toPath()))
        assertEquals("pufw installed. Run pufw in Termux.\n", result.output)
        assertNoTemporaryHelper()
        destination.delete()
        assertEquals(0, runCommand().exit) // First installation uses the same path.
        assertArrayEquals(helper, destination.readBytes())
    }

    @Test fun apkAndPrefixShellMetacharactersStayLiteral() {
        apk = File(temporary.root, "app ' \$(touch INJECTED) `touch ALSO_INJECTED`; &.apk")
        archive()
        prefix = temporary.newFolder("prefix ' \$(touch PREFIX_INJECTED) `touch PREFIX_ALSO_INJECTED`; &")
        File(prefix, "bin").mkdir()
        val result = runCommand()
        assertEquals(result.output, 0, result.exit)
        assertArrayEquals(helper, destination.readBytes())
        for (name in listOf("INJECTED", "ALSO_INJECTED", "PREFIX_INJECTED", "PREFIX_ALSO_INJECTED"))
            assertFalse(File(temporary.root, name).exists())
        assertNoTemporaryHelper()
    }

    @Test fun rejectsInvalidPathOrDigestBeforeGeneratingShell() {
        for (path in listOf("", "relative.apk", "/a\nb.apk", "/a\rb.apk", "/a\u0000b.apk"))
            assertThrows(IllegalArgumentException::class.java) { termuxInstallCommand(path, digest) }
        for (hash in listOf("", "0".repeat(63), "g".repeat(64), "$digest; touch INJECTED"))
            assertThrows(IllegalArgumentException::class.java) { termuxInstallCommand(apk.absolutePath, hash) }
    }

    @Test fun staleApkPathAndMissingAssetPreserveTheInstalledHelper() {
        assertPreserved(runCommand(path = File(temporary.root, "old.apk").absolutePath))
        archive(entry = "assets/different-file")
        assertPreserved(runCommand())
    }

    @Test fun corruptZipEmptyAssetAndDigestMismatchPreserveTheInstalledHelper() {
        apk.writeText("not a ZIP")
        assertPreserved(runCommand())
        archive(bytes = byteArrayOf())
        assertPreserved(runCommand())
        archive(bytes = "#!/bin/sh\necho untrusted\n".toByteArray())
        val mismatch = runCommand()
        assertPreserved(mismatch)
        assertTrue(mismatch.output.contains("integrity check failed"))
    }

    @Test fun partialExtractionFailureNeverCommitsEvenWhenItsBytesMatch() {
        val payload = File(temporary.root, "payload").also { it.writeBytes(helper) }
        fakeCommand("unzip", "cat \"\$PUFW_TEST_PAYLOAD\"; exit 2")
        assertPreserved(runCommand(extra = mapOf("PUFW_TEST_PAYLOAD" to payload.absolutePath)))
    }

    @Test fun interruptedExtractionRemovesItsTemporaryFileAndPreservesTheHelper() {
        fakeCommand("unzip", "printf partial; kill -TERM \"\$PPID\"; exit 1")
        assertPreserved(runCommand())
    }

    @Test fun failuresBeforeCommitPreserveTheInstalledHelper() {
        for (tool in listOf("mktemp", "sha256sum", "chmod", "mv")) {
            fakeCommand(tool, "exit 1")
            assertPreserved(runCommand())
            File(commands, tool).delete()
        }
    }

    @Test fun rootAndUnknownIdentityAreRejectedBeforeAnyInstallation() {
        for (body in listOf("echo 0", "exit 1", "echo unknown")) {
            fakeCommand("id", body)
            assertPreserved(runCommand())
        }
    }

    @Test fun missingDependencyAndInvalidPrefixPreserveTheInstalledHelper() {
        for (tool in listOf("sh", "sha256sum", "mktemp", "chmod", "mv", "rm"))
            Files.createSymbolicLink(File(commands, tool).toPath(), File("/usr/bin/$tool").toPath())
        val missing = runCommand(extra = mapOf("PATH" to commands.absolutePath))
        assertPreserved(missing)
        assertTrue(missing.output.contains("Missing command: unzip"))
        assertPreserved(runCommand(extra = mapOf("PREFIX" to "")))
        assertPreserved(runCommand(extra = mapOf("PREFIX" to "relative")))
        assertPreserved(runCommand(extra = mapOf("PREFIX" to File(temporary.root, "missing").absolutePath)))
    }

    @Test fun destinationDirectoryIsRejectedWithoutWritingIntoIt() {
        destination.delete()
        destination.mkdir()
        val keep = File(destination, "keep").also { it.writeText("untouched") }
        assertNotEquals(0, runCommand().exit)
        assertEquals(listOf("keep"), destination.list()!!.toList())
        assertEquals("untouched", keep.readText())
        assertNoTemporaryHelper()
    }

    @Test fun replacementDoesNotFollowAnExistingDestinationSymlink() {
        val other = temporary.newFile("other").also { it.writeText("untouched") }
        destination.delete()
        Files.createSymbolicLink(destination.toPath(), other.toPath())
        val result = runCommand()
        assertEquals(result.output, 0, result.exit)
        assertFalse(Files.isSymbolicLink(destination.toPath()))
        assertArrayEquals(helper, destination.readBytes())
        assertEquals("untouched", other.readText())
        assertNoTemporaryHelper()
    }
}
