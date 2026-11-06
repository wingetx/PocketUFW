package io.github.pocketufw

import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithText
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.android.controller.ActivityController
import org.robolectric.shadows.ShadowLooper

/** Runs the real [PocketScreen] in a real ComponentActivity, against a fake gateway. */
internal fun ComposeTestRule.launchScreen(
    gateway: FirewallGateway,
    qualifiers: String = "w412dp-h915dp-xxhdpi",
    fontScale: Float = 1f,
    openAppInfo: (android.content.Context) -> Boolean = { true },
): ActivityController<ComponentActivity> {
    RuntimeEnvironment.setQualifiers(qualifiers)
    RuntimeEnvironment.setFontScale(fontScale)
    val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
    controller.get().setContent {
        TideTheme { PocketScreen(gateway, openAppInfo) }
    }
    return controller
}

internal fun ComposeTestRule.hasText(text: String, substring: Boolean = false) =
    onAllNodesWithText(text, substring = substring).fetchSemanticsNodes().isNotEmpty()

/**
 * Waits for background work: the screen uses Dispatchers.IO, which the test clock can't see.
 * Results come back through the main looper, and waitUntil pumps only Compose, so a condition
 * that doesn't happen to query Compose would otherwise wait forever for them.
 */
internal fun ComposeTestRule.settle(timeoutMillis: Long = 10_000, condition: () -> Boolean) {
    waitUntil(timeoutMillis) { ShadowLooper.idleMainLooper(); condition() }
    waitForIdle()
}

/**
 * Call last in a test's teardown. Robolectric clears the main looper between tests, and if
 * Compose's static AndroidUiDispatcher still had a dispatch queued there it would believe so
 * forever: snapshot changes stop flushing, and every later test in this sandbox spins in
 * waitForIdle until it times out. So one failed test used to cost a minute per test after it.
 */
internal fun drainMainLooper(controllers: List<ActivityController<ComponentActivity>> = emptyList()) {
    controllers.forEach { runCatching { it.pause().stop().destroy() } }
    Shadows.shadowOf(Looper.getMainLooper()).runToEndOfTasks()
}
