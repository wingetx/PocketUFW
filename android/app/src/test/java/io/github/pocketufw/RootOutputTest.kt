package io.github.pocketufw

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

/** Local unprivileged processes only. These exercise pipes, not a fake su response. */
class RootOutputTest {
    private fun process(script: String) = ProcessBuilder("sh", "-c", script).redirectErrorStream(true).start()

    @Test fun completeOutputAboveEightKiBIsRetainedIncludingItsEndMarker() {
        val p = process("head -c 12000 /dev/zero | tr '\\000' x; printf '\\nrules_report=READY\\n'")
        val result = collectRootOutput(p, 3)
        assertTrue(result.succeeded)
        assertTrue(result.text.endsWith("rules_report=READY\n"))
        assertEquals(12020, result.text.length) // Leading output is part of the response.
    }

    @Test fun outputBeyondTheBoundIsDrainedWithoutBlockingTheProducerOrTrustingThePrefix() {
        val marker = Files.createTempFile("pufw-output-complete-", ".txt").toFile()
        marker.delete()
        try {
            val p = ProcessBuilder("sh", "-c",
                "printf 'root=GRANTED\\nstate=ACTIVE\\n'; dd if=/dev/zero bs=1024 count=512 2>/dev/null; printf done > \"\$1\"",
                "test", marker.absolutePath).redirectErrorStream(true).start()
            val result = collectRootOutput(p, 3)
            assertEquals(122, result.exitCode)
            assertTrue(result.text.length <= 65536)
            assertTrue(p.waitFor(1, TimeUnit.SECONDS))
            assertEquals(0, p.exitValue())
            assertEquals("done", marker.readText())
            assertFalse(result.succeeded)
        } finally { marker.delete() }
    }

    @Test fun continuousOutputCannotExtendTheOriginalDeadline() {
        val p = process("while :; do printf '0123456789012345678901234567890123456789'; done")
        val start = System.nanoTime()
        val result = collectRootOutput(p, 1)
        assertEquals(124, result.exitCode)
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2500)
        assertTrue(p.waitFor(1, TimeUnit.SECONDS))
    }

    @Test fun nonzeroExitAndTimeoutAreNotConvertedToSuccess() {
        assertEquals(7, collectRootOutput(process("printf failed; exit 7"), 2).exitCode)
        val p = process("exec sleep 10")
        assertEquals(124, collectRootOutput(p, 1).exitCode)
        assertTrue(p.waitFor(1, TimeUnit.SECONDS))
    }

    @Test fun theExactByteLimitIsAcceptedButOneMoreByteIsNot() {
        for (size in listOf(ROOT_OUTPUT_LIMIT, ROOT_OUTPUT_LIMIT + 1)) {
            val result = collectRootOutput(process("head -c $size /dev/zero"), 3)
            assertEquals(if (size == ROOT_OUTPUT_LIMIT) 0 else 122, result.exitCode)
            if (result.succeeded) assertEquals(size, result.text.toByteArray().size)
        }
    }

    @Test fun anExitedParentDoesNotWaitForADescendantHoldingThePipe() {
        val start = System.nanoTime()
        val result = collectRootOutput(process("sleep 10 & echo \$!; exit 0"), 3)
        val child = result.text.trim().toLong().toString()
        try {
            assertTrue(result.succeeded)
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1500)
        } finally { ProcessBuilder("kill", "-KILL", child).start().waitFor() }
    }

    /**
     * Deterministic: the process's last bytes land, and it exits, exactly between the
     * empty available() check and the isAlive check.
     */
    private class LateExit(first: String, private val late: ByteArray, private val exit: Int = 0) : Process() {
        private val pending = ArrayDeque(first.toByteArray().toList())
        private var landed = false
        private val stream = object : InputStream() {
            override fun available() = pending.size
            override fun read(): Int = pending.removeFirstOrNull()?.toInt()?.and(0xff) ?: -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pending.isEmpty()) return -1
                var n = 0
                while (n < len && pending.isNotEmpty()) b[off + n++] = pending.removeFirst()
                return n
            }
        }
        override fun isAlive(): Boolean {
            if (!landed) { landed = true; late.forEach { pending.addLast(it) } }
            return false
        }
        override fun getInputStream(): InputStream = stream
        override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun waitFor() = exit
        override fun waitFor(timeout: Long, unit: TimeUnit) = true
        override fun exitValue() = exit
        override fun destroy() {}
    }

    @Test fun outputThatLandsJustBeforeTheExitIsNotLost() {
        val tail = "state=ACTIVE\nboot=ENABLED\nrules_report=READY\n"
        val result = collectRootOutput(LateExit("root=GRANTED\n", tail.toByteArray()), 3)
        assertTrue(result.succeeded)
        assertEquals("root=GRANTED\n" + tail, result.text)
    }

    @Test fun lateOutputKeepsTheExitStatusAndTheSizeLimit() {
        val failed = collectRootOutput(LateExit("", "error=late\n".toByteArray(), exit = 7), 3)
        assertEquals(7, failed.exitCode)
        assertEquals("error=late\n", failed.text)
        assertEquals(ROOT_OUTPUT_LIMIT, collectRootOutput(LateExit("", ByteArray(ROOT_OUTPUT_LIMIT), 0), 3).text.length)
        assertEquals(122, collectRootOutput(LateExit("", ByteArray(ROOT_OUTPUT_LIMIT + 1), 0), 3).exitCode)
    }

    @Test fun interruptionOrReadFailureCannotProduceSuccessAndStopsTheProcess() {
        for (interrupt in listOf(false, true)) {
            val p = process("exec sleep 10")
            try {
                if (interrupt) Thread.currentThread().interrupt() else p.inputStream.close()
                assertEquals(122, collectRootOutput(p, 3).exitCode)
                if (interrupt) assertTrue(Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
            assertTrue(p.waitFor(1, TimeUnit.SECONDS))
        }
    }
}
