package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithText
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController

/** Runs the real [PocketScreen] in a real ComponentActivity, against a fake gateway. */
internal fun ComposeTestRule.launchScreen(
    gateway: FirewallGateway,
    qualifiers: String = "w412dp-h915dp-xxhdpi",
    fontScale: Float = 1f,
): ActivityController<ComponentActivity> {
    RuntimeEnvironment.setQualifiers(qualifiers)
    RuntimeEnvironment.setFontScale(fontScale)
    val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
    controller.get().setContent {
        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = Mint, onPrimary = Background,
                background = Background, onBackground = Foreground,
                surface = Panel, onSurface = Foreground
            )
        ) { PocketScreen(gateway) }
    }
    return controller
}

internal fun ComposeTestRule.hasText(text: String, substring: Boolean = false) =
    onAllNodesWithText(text, substring = substring).fetchSemanticsNodes().isNotEmpty()

/** Waits for background work: the screen uses Dispatchers.IO, which the test clock can't see. */
internal fun ComposeTestRule.settle(timeoutMillis: Long = 10_000, condition: () -> Boolean) {
    waitUntil(timeoutMillis) { condition() }
    waitForIdle()
}
