package io.github.pocketufw

import android.graphics.Bitmap
import android.graphics.Canvas
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextLayoutResult
import java.io.File
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideTermuxTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun close() = drainMainLooper(screens)
    private fun node(text: String) = compose.onNodeWithText(text)
    private fun click(text: String) = node(text).performScrollTo().performClick()

    private class Clipboard : ClipboardManager {
        var writes = mutableListOf<String>()
        override fun getText() = writes.lastOrNull()?.let(::AnnotatedString)
        override fun setText(annotatedString: AnnotatedString) { writes += annotatedString.text }
    }

    private fun open(dark: Boolean = false, fontScale: Float = 1f, invalidApkPath: Boolean = false): Pair<FakeGateway, Clipboard> {
        RuntimeEnvironment.setQualifiers("w320dp-h800dp-${if (dark) "night" else "notnight"}-xxhdpi")
        RuntimeEnvironment.setFontScale(fontScale)
        val fake = FakeGateway(tunnelDashboard())
        val clipboard = Clipboard()
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent {
            val context = LocalContext.current
            val commandContext = if (invalidApkPath) object : ContextWrapper(context) {
                override fun getApplicationInfo() = ApplicationInfo(super.getApplicationInfo()).apply { sourceDir = "" }
            } else context
            CompositionLocalProvider(LocalClipboardManager provides clipboard, LocalContext provides commandContext) {
                TideTheme(dark) { PocketScreen(fake) }
            }
        }
        compose.settle { fake.count("inspect") == 1 && compose.hasText("Active.") }
        return fake to clipboard
    }

    @Test fun disclosureIsOptionalCollapsedAndDoesNotInspectOrInstallAnything() {
        val (fake, clipboard) = open()
        node("Termux quick commands").performScrollTo()
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        node("Check your firewall from the terminal").assertExists()
        node("pufw").assertDoesNotExist()
        compose.onNodeWithText("Root access granted", substring = true).performScrollTo().assertIsDisplayed()
        shot("collapsed")
        click("Termux quick commands")
        node("Termux quick commands").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        node("To use these commands, install the optional helper first. See “Install the helper” below.").assertExists()
        for (command in listOf("pufw", "pufw tunnel", "pufw stats", "pufw clear", "pufw raw")) node(command).assertExists()
        node("Install the helper").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        node("Copy installation command").assertDoesNotExist()
        compose.onNodeWithText("Root access granted", substring = true).performScrollTo().assertIsDisplayed()
        shot("expanded")
        click("Install the helper")
        node("Install the helper").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        compose.onNodeWithText("The helper is included in this app; no download or storage permission is needed.", substring = true).assertExists()
        node("Included in this app · one command").assertExists()
        node("Copy installation command").assertIsEnabled()
        node("GitHub Releases").assertDoesNotExist()
        node("termux-setup-storage").assertDoesNotExist()
        compose.onNodeWithText("Installation verifies the helper before replacing an existing copy.", substring = true).assertExists()
        compose.onNodeWithText("source folder", substring = true).assertDoesNotExist()
        compose.onNodeWithText("tools/pufw", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Separate from the experimental pufw-inspect", substring = true).assertExists()
        click("Install the helper")
        node("Copy installation command").assertDoesNotExist()
        node("pufw").assertExists()
        click("Termux quick commands")
        node("pufw").assertDoesNotExist()
        assertTrue(clipboard.writes.isEmpty())
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun commandTextCopiesExactlyAndAnnouncesEachCopyWithoutRootWork() {
        val (fake, clipboard) = open()
        click("Termux quick commands")
        click("Install the helper")
        val commands = listOf("pufw", "pufw tunnel", "pufw stats", "pufw clear", "pufw raw", "pufw raw")
        for (command in commands) {
            node(command).assert(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button))
            assertEquals("Copy command", node(command).fetchSemanticsNode().config[SemanticsActions.OnClick].label)
            click(command)
            assertEquals(command, clipboard.getText()?.text)
            node(command).assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Copied to clipboard"))
            node("Copied: $command").assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite))
        }
        assertEquals(commands, clipboard.writes)
        assertEquals(listOf("inspect"), fake.calls.toList())
        click("Termux quick commands")
        click("Termux quick commands")
        node("Copied: pufw raw").assertDoesNotExist()
    }

    @Test fun oneTapCopiesInstallationCommandAndAnnouncesItWithoutRootWork() {
        val (fake, clipboard) = open()
        click("Termux quick commands")
        click("Install the helper")
        val expected = bundledTermuxInstallCommand(screens.last().get())
        assertFalse(expected.contains('\n'))
        repeat(2) {
            click("Copy installation command")
            assertEquals(expected, clipboard.getText()?.text)
            node("Copy installation command").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Copied to clipboard"))
            node("Installation command copied. Paste it into Termux.")
                .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite))
        }
        assertEquals(listOf(expected, expected), clipboard.writes)
        assertEquals(listOf("inspect"), fake.calls.toList())
        click("Install the helper")
        click("Install the helper")
        node("Installation command copied. Paste it into Termux.").assertDoesNotExist()
    }

    @Test fun bundledHelperMatchesTheCompanionSource() {
        val context = RuntimeEnvironment.getApplication()
        val bundled = context.assets.open(TERMUX_HELPER_ASSET).use { it.readBytes() }
        assertArrayEquals(File("../../tools/pufw").readBytes(), bundled)
    }

    @Test fun unavailableInstallationCommandDoesNotCopyOrClaimSuccess() {
        val (fake, clipboard) = open(invalidApkPath = true)
        click("Termux quick commands")
        click("Install the helper")
        click("Copy installation command")
        node("Could not copy the installation command. Reopen PocketUFW and try again.").assertExists()
        node("Installation command copied. Paste it into Termux.").assertDoesNotExist()
        assertTrue(clipboard.writes.isEmpty())
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    private fun shot(name: String) {
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        val directory = File("build/reports/tide-termux").also { it.mkdirs() }
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }

    private fun largeText(dark: Boolean) {
        val (fake, _) = open(dark, 2f)
        click("Termux quick commands")
        click("Install the helper")
        val appearance = if (dark) "dark" else "light"
        for (command in listOf("Copy installation command", "pufw", "pufw tunnel", "pufw stats", "pufw clear", "pufw raw")) {
            node(command).performScrollTo().assertIsDisplayed()
            val bounds = node(command).getUnclippedBoundsInRoot()
            assertTrue("Copy target remains at least 48dp high", (bounds.bottom - bounds.top).value >= 48f)
        }
        compose.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.GetTextLayoutResult), useUnmergedTree = true)
            .fetchSemanticsNodes().forEach { node ->
                val layouts = mutableListOf<TextLayoutResult>()
                node.config[SemanticsActions.GetTextLayoutResult].action!!(layouts)
                layouts.forEach { layout ->
                    for (line in 0 until layout.lineCount) {
                        assertTrue("Clipped: ${layout.layoutInput.text}", layout.getLineRight(line) <= layout.size.width + 1)
                        assertTrue("Clipped height: ${layout.layoutInput.text}", layout.getLineBottom(line) <= layout.size.height + 1)
                        assertFalse(layout.isLineEllipsized(line))
                    }
                    assertEquals(layout.layoutInput.text.length, layout.getLineEnd(layout.lineCount - 1))
                }
            }
        click("pufw stats")
        node("Copied: pufw stats").performScrollTo().assertIsDisplayed()
        shot("$appearance-large")
        click("Copy installation command")
        node("Installation command copied. Paste it into Termux.").performScrollTo().assertIsDisplayed()
        shot("$appearance-install-large")
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
    @Test fun largeLightCommandsWrapAndRemainAccessible() = largeText(false)
    @Test fun largeDarkCommandsWrapAndRemainAccessible() = largeText(true)

    @Test fun commandsRemainAvailableWhenFirewallIsIntentionallyInactive() {
        val fake = FakeGateway(stateDashboard(FirewallClient.Protection.INACTIVE, true, "Off.", FirewallClient.BootRestore.DISABLED))
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Inactive.") }
        click("Termux quick commands")
        node("pufw").assertIsEnabled()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
}
