package com.kibele.securekeys.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.TileMode
import androidx.compose.ui.unit.dp

private val DarkScheme = darkColorScheme(
    primary = PurpleNeon,
    secondary = PurpleGlow,
    background = PurpleDeep,
    surface = Purple01,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = TextOnDark,
    onSurface = TextOnDark
)

@Composable
fun KibeleTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkScheme, typography = Typography(), content = content)
}

/** Arkaplanlarda kullanmak için mor neon çizgili degrade */
@Composable
fun kibeleGradient(): Brush = Brush.verticalGradient(
    0f to PurpleDeep,
    0.35f to Purple01,
    0.7f to Purple02,
    1f to PurpleDeep,
    tileMode = TileMode.Clamp
)
