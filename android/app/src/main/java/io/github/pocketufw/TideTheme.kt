package io.github.pocketufw

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

internal val TideDisplay = FontFamily(Font(R.font.tide_display_500, FontWeight.Medium))
internal val TideSans = FontFamily(
    Font(R.font.tide_sans_400), Font(R.font.tide_sans_500, FontWeight.Medium),
    Font(R.font.tide_sans_600, FontWeight.SemiBold), Font(R.font.tide_sans_700, FontWeight.Bold)
)
internal val TideMono = FontFamily(Font(R.font.tide_mono))

private val Day = lightColorScheme(
    primary = Color(0xFF244BC4), onPrimary = Color.White,
    primaryContainer = Color(0xFFE4EAFF), onPrimaryContainer = Color(0xFF18388D),
    background = Color(0xFFF7F6EF), onBackground = Color(0xFF202C3B),
    surface = Color(0xFFF7F6EF), onSurface = Color(0xFF202C3B),
    surfaceVariant = Color(0xFFEEEEE5),
    onSurfaceVariant = Color(0xFF59606B), outline = Color(0xFF747B82),
    outlineVariant = Color(0xFFD5D8CF), secondary = Color(0xFF8F4915),
    secondaryContainer = Color(0xFFFAEBD8), onSecondaryContainer = Color(0xFF793C10),
    error = Color(0xFFAC3930), errorContainer = Color(0xFFFCE4DF), onErrorContainer = Color(0xFF8A2921)
)
private val Night = darkColorScheme(
    primary = Color(0xFFA9BFFF), onPrimary = Color(0xFF152C65),
    primaryContainer = Color(0xFF273852), onPrimaryContainer = Color(0xFFD4DFFF),
    background = Color(0xFF141B29), onBackground = Color(0xFFF1F2ED),
    surface = Color(0xFF141B29), onSurface = Color(0xFFF1F2ED),
    surfaceVariant = Color(0xFF202A3B), onSurfaceVariant = Color(0xFFB3BDCE),
    outline = Color(0xFF8997AC), outlineVariant = Color(0xFF3D495C),
    secondary = Color(0xFFF3B778), secondaryContainer = Color(0xFF423123),
    onSecondaryContainer = Color(0xFFF3C99B), error = Color(0xFFFFB5A6),
    errorContainer = Color(0xFF4D2925), onErrorContainer = Color(0xFFFFC7BD)
)

private fun sans(size: Int, height: Int, weight: FontWeight = FontWeight.Normal) =
    TextStyle(fontFamily = TideSans, fontSize = size.sp, lineHeight = height.sp, fontWeight = weight)

@Composable
internal fun TideTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val view = LocalView.current
    if (!view.isInEditMode) SideEffect {
        (view.context as? Activity)?.window?.let { window ->
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }
    MaterialTheme(
        colorScheme = if (dark) Night else Day,
        typography = Typography(
            displayLarge = TextStyle(fontFamily = TideDisplay, fontWeight = FontWeight.Medium, fontSize = 64.sp, lineHeight = 70.sp, letterSpacing = (-2).sp),
            headlineLarge = TextStyle(fontFamily = TideDisplay, fontWeight = FontWeight.Medium, fontSize = 40.sp, lineHeight = 46.sp, letterSpacing = (-1).sp),
            headlineMedium = TextStyle(fontFamily = TideDisplay, fontWeight = FontWeight.Medium, fontSize = 32.sp, lineHeight = 38.sp),
            titleLarge = sans(22, 28, FontWeight.SemiBold), titleMedium = sans(16, 22, FontWeight.SemiBold),
            titleSmall = sans(14, 20, FontWeight.SemiBold), bodyLarge = sans(16, 24),
            bodyMedium = sans(14, 21), bodySmall = sans(12, 18),
            labelLarge = sans(14, 20, FontWeight.SemiBold), labelMedium = sans(12, 18, FontWeight.Medium),
            labelSmall = sans(11, 16, FontWeight.Medium)
        ), content = content
    )
}

// Shared with the existing UDP editor; values always follow the active appearance.
internal val Background: Color @Composable get() = MaterialTheme.colorScheme.background
internal val Panel: Color @Composable get() = MaterialTheme.colorScheme.surfaceVariant
internal val Border: Color @Composable get() = MaterialTheme.colorScheme.outlineVariant
internal val Foreground: Color @Composable get() = MaterialTheme.colorScheme.onSurface
internal val Muted: Color @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
internal val Mint: Color @Composable get() = MaterialTheme.colorScheme.primary
// Protection has its own success color; navigation and actions retain Tide's blue.
internal val VerifiedProtection: Color @Composable get() =
    if (Background.luminance() < 0.5f) Color(0xFF85DEB4) else Color(0xFF176443)
internal val Amber: Color @Composable get() = MaterialTheme.colorScheme.secondary
