package io.github.pocketufw

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.systemGestures
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.dp
import kotlin.math.abs

/** Only unclaimed, deliberate horizontal gestures in the content navigate tabs. */
@Composable
internal fun Modifier.tideTabSwipes(enabled: Boolean, onSwipe: (Int) -> Unit): Modifier {
    val density = LocalDensity.current
    val direction = LocalLayoutDirection.current
    val gestures = WindowInsets.systemGestures
    val edge = with(density) { 24.dp.toPx() }
    val leftEdge = maxOf(edge, gestures.getLeft(density, direction).toFloat())
    val rightEdge = maxOf(edge, gestures.getRight(density, direction).toFloat())
    val distance = with(density) { 64.dp.toPx() }
    val navigate = rememberUpdatedState(onSwipe)
    return pointerInput(enabled, leftEdge, rightEdge, distance) {
        if (!enabled) return@pointerInput
        awaitEachGesture {
            // Main pass gives child drag handlers and nested scrollers first refusal.
            // Clickables consume DOWN too: a pending tap must not veto a later swipe.
            val down = awaitFirstDown(requireUnconsumed = false)
            if (down.position.x < leftEdge || down.position.x > size.width - rightEdge)
                return@awaitEachGesture
            var horizontal = false
            while (true) {
                val event = awaitPointerEvent()
                if (event.changes.size != 1) break
                val change = event.changes.single()
                if (change.id != down.id || change.isConsumed) break
                val delta = change.position - down.position
                if (!horizontal) {
                    // Long presses and vertical/diagonal intent belong to the current screen.
                    if (change.uptimeMillis - down.uptimeMillis >= viewConfiguration.longPressTimeoutMillis) break
                    if (abs(delta.y) > viewConfiguration.touchSlop) break
                    horizontal = abs(delta.x) > viewConfiguration.touchSlop && abs(delta.x) > 2 * abs(delta.y)
                }
                // Cancel a pending tap once horizontal intent is established.
                // Consumption belongs to this event, not subsequent pointer events.
                if (horizontal) change.consume()
                if (!change.pressed) {
                    if (horizontal && abs(delta.x) >= distance && abs(delta.x) > 2 * abs(delta.y))
                        navigate.value(if (delta.x < 0) 1 else -1)
                    break
                }
            }
        }
    }
}
