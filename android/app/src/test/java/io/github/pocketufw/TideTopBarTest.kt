package io.github.pocketufw

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.dp
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
class TideTopBarTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun close() = drainMainLooper(screens)

    private fun labelFits(text: String) {
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(text, useUnmergedTree = true).assertIsDisplayed()
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { assertTrue(it(layouts)) }
        assertFalse("$text should not clip", layouts.single().hasVisualOverflow)
        assertEquals(1, layouts.single().lineCount)
    }

    private fun layout(width: Int, fontScale: Float, back: Boolean, dark: Boolean = false) {
        RuntimeEnvironment.setQualifiers("w${width}dp-h915dp-${if (dark) "night" else "notnight"}-xxhdpi")
        RuntimeEnvironment.setFontScale(fontScale)
        val checking = mutableStateOf(false)
        var rechecks = 0
        var backs = 0
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent { TideTheme { Surface(Modifier.fillMaxSize(), color = Background) {
            // The bar measures to its content, as it does in Scaffold's topBar slot.
            androidx.compose.foundation.layout.Column {
                TideTopBar(back, { backs++ }, checking.value, recheckEnabled = true,
                    onRecheck = { rechecks++; checking.value = true })
            }
        } } }
        val button = compose.onNodeWithTag("recheck-status")
        button.assertIsDisplayed().assertHeightIsAtLeast(48.dp).assertWidthIsAtLeast(48.dp)
        labelFits("Recheck")
        val before = button.getUnclippedBoundsInRoot()
        val title = compose.onNodeWithTag("toolbar-title").getUnclippedBoundsInRoot()
        assertTrue("Action stays within the screen", before.left >= 0.dp && before.right <= width.dp)
        if (fontScale >= 2f) assertTrue("Large text gets its own action row", before.top >= title.bottom)
        else if (width >= 412) assertTrue("Ordinary text retains a single-row toolbar", before.top < title.bottom)
        if (back) compose.onNodeWithContentDescription("Back").assertIsDisplayed()
        button.performClick()
        labelFits("Checking…")
        button.assertIsNotEnabled().assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Checking…"))
        assertEquals("Loading must not reflow the bar", before, button.getUnclippedBoundsInRoot())
        button.performClick()
        assertEquals(1, rechecks)
        val directory = File("build/reports/tide-recheck").also { it.mkdirs() }
        val view = controller.get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        File(directory, "${width}dp-${fontScale}x-back-$back.png").outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
        bitmap.recycle()
        compose.runOnIdle { checking.value = false }
        labelFits("Recheck")
        button.assertIsEnabled()
        if (back) {
            compose.onNodeWithContentDescription("Back").performClick()
            assertEquals(1, backs)
        }
    }

    @Test fun visibleLabelFitsTheExistingToolbar() = layout(412, 1f, back = false)
    @Test fun narrowScreenKeepsTheLabelAndBackControl() = layout(320, 1f, back = true)
    @Test fun largeTextKeepsBothControlsAndLoadingVisible() = layout(320, 2f, back = true)
    @Test fun largeTextAndDarkModeKeepTheLabelVisible() = layout(412, 2f, back = false, dark = true)
}
