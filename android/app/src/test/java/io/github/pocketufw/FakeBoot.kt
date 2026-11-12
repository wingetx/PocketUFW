package io.github.pocketufw

import java.io.File
import java.nio.file.Files

/** Sets the boot identity the tile cache sees, then puts the real readers back. */
internal class FakeBoot {
    private val count = TileStatusStore.readBootCount
    private val file = TileStatusStore.bootIdFile

    /** A null part is unreadable, as it can be on a device. */
    fun now(bootCount: Int?, bootId: String?) {
        TileStatusStore.readBootCount = { bootCount }
        TileStatusStore.bootIdFile = if (bootId == null) File("/nonexistent/pocketufw-test/boot_id")
            else Files.createTempFile("pufw-boot-id", "").toFile().apply { writeText("$bootId\n"); deleteOnExit() }
    }

    fun restore() {
        TileStatusStore.readBootCount = count
        TileStatusStore.bootIdFile = file
    }

    companion object {
        const val FIRST = "6f1c2a9e-0b3d-4c7e-9a51-2d8f0e4b7c11"
        const val SECOND = "a3e5d7c9-1f2b-4a6c-8e0d-5b7f9c1e3a22"
    }
}
