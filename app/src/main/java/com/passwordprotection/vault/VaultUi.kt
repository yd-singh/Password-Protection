package com.passwordprotection.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

internal enum class ThemeMode { SYSTEM, DARK, LIGHT }

internal data class VaultPalette(
    val isDark: Boolean,
    val bgDeep: Color,
    val bgSurface: Color,
    val bgElevated: Color,
    val borderSubtle: Color,
    val accentEmerald: Color,
    val accentCyan: Color,
    val accentAmber: Color,
    val accentDanger: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val onAccentDark: Color,
    val lockButtonBg: Color
)

private val DarkVaultPalette = VaultPalette(
    isDark = true,
    bgDeep = Color(0xFF0A0F16),
    bgSurface = Color(0xFF111923),
    bgElevated = Color(0xFF172230),
    borderSubtle = Color(0xFF233246),
    accentEmerald = Color(0xFF34D399),
    accentCyan = Color(0xFF38BDF8),
    accentAmber = Color(0xFFFBBF24),
    accentDanger = Color(0xFFF87171),
    textPrimary = Color(0xFFF1F5F9),
    textSecondary = Color(0xFF94A3B8),
    onAccentDark = Color(0xFF062319),
    lockButtonBg = Color(0xFF2B1519)
)

private val LightVaultPalette = VaultPalette(
    isDark = false,
    bgDeep = Color(0xFFF4F7FB),
    bgSurface = Color(0xFFFFFFFF),
    bgElevated = Color(0xFFEEF3F9),
    borderSubtle = Color(0xFFCBD5E1),
    accentEmerald = Color(0xFF047857),
    accentCyan = Color(0xFF0369A1),
    accentAmber = Color(0xFF92400E),
    accentDanger = Color(0xFFDC2626),
    textPrimary = Color(0xFF0F172A),
    textSecondary = Color(0xFF475569),
    onAccentDark = Color(0xFFFFFFFF),
    lockButtonBg = Color(0xFFFEE2E2)
)

internal val LocalVaultPalette = staticCompositionLocalOf { DarkVaultPalette }

internal object VaultThemeColors {
    val isDark: Boolean @Composable get() = LocalVaultPalette.current.isDark
    val BgDeep: Color @Composable get() = LocalVaultPalette.current.bgDeep
    val BgSurface: Color @Composable get() = LocalVaultPalette.current.bgSurface
    val BgElevated: Color @Composable get() = LocalVaultPalette.current.bgElevated
    val BorderSubtle: Color @Composable get() = LocalVaultPalette.current.borderSubtle
    val AccentEmerald: Color @Composable get() = LocalVaultPalette.current.accentEmerald
    val AccentCyan: Color @Composable get() = LocalVaultPalette.current.accentCyan
    val AccentAmber: Color @Composable get() = LocalVaultPalette.current.accentAmber
    val AccentDanger: Color @Composable get() = LocalVaultPalette.current.accentDanger
    val TextPrimary: Color @Composable get() = LocalVaultPalette.current.textPrimary
    val TextSecondary: Color @Composable get() = LocalVaultPalette.current.textSecondary
    val OnAccentDark: Color @Composable get() = LocalVaultPalette.current.onAccentDark
    val LockButtonBg: Color @Composable get() = LocalVaultPalette.current.lockButtonBg
}

internal val VaultMonoStyle: TextStyle
    @Composable get() = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 14.sp,
        lineHeight = 22.sp,
        letterSpacing = 0.5.sp,
        color = LocalVaultPalette.current.textPrimary
    )

private fun vaultTypography(palette: VaultPalette) = Typography(
    headlineMedium = TextStyle(
        fontSize = 22.sp,
        lineHeight = 30.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.2).sp
    ),
    headlineSmall = TextStyle(
        fontSize = 19.sp,
        lineHeight = 27.sp,
        fontWeight = FontWeight.Bold
    ),
    titleMedium = TextStyle(
        fontSize = 16.sp,
        lineHeight = 24.sp,
        fontWeight = FontWeight.SemiBold
    ),
    titleSmall = TextStyle(
        fontSize = 14.sp,
        lineHeight = 21.sp,
        fontWeight = FontWeight.SemiBold
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 22.sp
    ),
    bodySmall = TextStyle(
        fontSize = 13.sp,
        lineHeight = 19.sp,
        color = palette.textSecondary
    ),
    labelLarge = TextStyle(
        fontSize = 13.sp,
        lineHeight = 19.sp,
        fontWeight = FontWeight.SemiBold
    ),
    labelSmall = TextStyle(
        fontSize = 11.sp,
        lineHeight = 15.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.6.sp,
        color = palette.textSecondary
    )
)

@Composable
internal fun VaultTheme(
    themeMode: ThemeMode,
    content: @Composable () -> Unit
) {
    val useDark = when (themeMode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
    }
    val palette = if (useDark) DarkVaultPalette else LightVaultPalette
    val colorScheme = if (useDark) {
        darkColorScheme(
            primary = palette.accentEmerald,
            onPrimary = palette.onAccentDark,
            secondary = palette.accentCyan,
            onSecondary = palette.bgDeep,
            tertiary = palette.accentAmber,
            background = palette.bgDeep,
            onBackground = palette.textPrimary,
            surface = palette.bgSurface,
            onSurface = palette.textPrimary,
            surfaceVariant = palette.bgElevated,
            onSurfaceVariant = palette.textSecondary,
            outline = palette.borderSubtle,
            error = palette.accentDanger
        )
    } else {
        lightColorScheme(
            primary = palette.accentEmerald,
            onPrimary = palette.onAccentDark,
            secondary = palette.accentCyan,
            onSecondary = Color.White,
            tertiary = palette.accentAmber,
            background = palette.bgDeep,
            onBackground = palette.textPrimary,
            surface = palette.bgSurface,
            onSurface = palette.textPrimary,
            surfaceVariant = palette.bgElevated,
            onSurfaceVariant = palette.textSecondary,
            outline = palette.borderSubtle,
            error = palette.accentDanger
        )
    }
    CompositionLocalProvider(LocalVaultPalette provides palette) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = vaultTypography(palette),
            content = content
        )
    }
}

@Composable
internal fun vaultFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = VaultThemeColors.AccentEmerald,
    unfocusedBorderColor = VaultThemeColors.BorderSubtle,
    focusedLabelColor = VaultThemeColors.AccentEmerald,
    unfocusedLabelColor = VaultThemeColors.TextSecondary,
    cursorColor = VaultThemeColors.AccentEmerald,
    focusedTextColor = VaultThemeColors.TextPrimary,
    unfocusedTextColor = VaultThemeColors.TextPrimary,
    focusedContainerColor = VaultThemeColors.BgElevated,
    unfocusedContainerColor = VaultThemeColors.BgSurface
)

@Composable
internal fun ShieldBadgeIcon(
    modifier: Modifier = Modifier,
    accent: Color = VaultThemeColors.AccentEmerald
) {
    Canvas(modifier = modifier.size(36.dp)) {
        val w = size.width
        val h = size.height
        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.08f)
            lineTo(w * 0.86f, h * 0.22f)
            lineTo(w * 0.86f, h * 0.52f)
            cubicTo(w * 0.86f, h * 0.72f, w * 0.70f, h * 0.86f, w * 0.50f, h * 0.94f)
            cubicTo(w * 0.30f, h * 0.86f, w * 0.14f, h * 0.72f, w * 0.14f, h * 0.52f)
            lineTo(w * 0.14f, h * 0.22f)
            close()
        }
        drawPath(path = shield, color = accent.copy(alpha = 0.14f))
        drawPath(
            path = shield,
            color = accent,
            style = Stroke(width = w * 0.075f, join = StrokeJoin.Round)
        )
        drawCircle(
            color = accent,
            radius = w * 0.105f,
            center = Offset(w * 0.50f, h * 0.45f)
        )
        drawLine(
            color = accent,
            start = Offset(w * 0.50f, h * 0.50f),
            end = Offset(w * 0.50f, h * 0.68f),
            strokeWidth = w * 0.11f,
            cap = StrokeCap.Round
        )
    }
}

@Composable
internal fun PadlockIcon(
    modifier: Modifier = Modifier,
    color: Color = VaultThemeColors.AccentDanger
) {
    Canvas(modifier = modifier.size(18.dp)) {
        val w = size.width
        val h = size.height
        drawArc(
            color = color,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(w * 0.27f, h * 0.10f),
            size = Size(w * 0.46f, h * 0.44f),
            style = Stroke(width = w * 0.12f, cap = StrokeCap.Round)
        )
        drawLine(
            color = color,
            start = Offset(w * 0.27f, h * 0.32f),
            end = Offset(w * 0.27f, h * 0.43f),
            strokeWidth = w * 0.12f,
            cap = StrokeCap.Round
        )
        drawLine(
            color = color,
            start = Offset(w * 0.73f, h * 0.32f),
            end = Offset(w * 0.73f, h * 0.43f),
            strokeWidth = w * 0.12f,
            cap = StrokeCap.Round
        )
        drawRoundRect(
            color = color.copy(alpha = 0.20f),
            topLeft = Offset(w * 0.16f, h * 0.42f),
            size = Size(w * 0.68f, h * 0.48f),
            cornerRadius = CornerRadius(w * 0.14f, w * 0.14f)
        )
        drawRoundRect(
            color = color,
            topLeft = Offset(w * 0.16f, h * 0.42f),
            size = Size(w * 0.68f, h * 0.48f),
            cornerRadius = CornerRadius(w * 0.14f, w * 0.14f),
            style = Stroke(width = w * 0.10f)
        )
        drawCircle(
            color = color,
            radius = w * 0.08f,
            center = Offset(w * 0.50f, h * 0.61f)
        )
        drawLine(
            color = color,
            start = Offset(w * 0.50f, h * 0.64f),
            end = Offset(w * 0.50f, h * 0.77f),
            strokeWidth = w * 0.09f,
            cap = StrokeCap.Round
        )
    }
}

@Composable
internal fun LockVaultButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    label: String = "Lock Vault",
    compact: Boolean = false
) {
    Surface(
        modifier = modifier
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(role = Role.Button, onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        color = VaultThemeColors.BgElevated,
        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
    ) {
        Row(
            modifier = Modifier.padding(
                horizontal = if (compact) 11.dp else 16.dp,
                vertical = if (compact) 8.dp else 12.dp
            ),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            PadlockIcon(
                modifier = Modifier.size(if (compact) 16.dp else 18.dp),
                color = VaultThemeColors.TextSecondary
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                color = VaultThemeColors.TextSecondary,
                maxLines = 1
            )
        }
    }
}

@Composable
internal fun SecurityPill(
    text: String,
    color: Color = VaultThemeColors.AccentCyan,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.13f))
            .border(1.dp, color.copy(alpha = 0.38f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color
        )
    }
}

@Composable
internal fun SectionCard(
    title: String,
    subtitle: String? = null,
    badgeText: String? = null,
    badgeColor: Color = VaultThemeColors.AccentEmerald,
    borderColor: Color = VaultThemeColors.BorderSubtle,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = VaultThemeColors.BgSurface,
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    if (!subtitle.isNullOrBlank()) {
                        Text(subtitle, style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (!badgeText.isNullOrBlank()) {
                    SecurityPill(badgeText, badgeColor)
                }
            }
            content()
        }
    }
}

@Composable
internal fun SettingsNavCard(
    title: String,
    subtitle: String,
    statusText: String,
    statusColor: Color,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .clickable(role = Role.Button, onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        color = VaultThemeColors.BgSurface,
        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
    ) {
        Row(
            modifier = Modifier.padding(18.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(subtitle, style = MaterialTheme.typography.bodySmall)
                Text(statusText.lowercase().replaceFirstChar { it.uppercase() }, style = MaterialTheme.typography.bodySmall, color = statusColor)
            }
            Text(
                text = "›",
                fontSize = 24.sp,
                fontWeight = FontWeight.Medium,
                color = VaultThemeColors.TextSecondary
            )
        }
    }
}

@Composable
internal fun ThemeModeSelector(
    selected: ThemeMode,
    onSelect: (ThemeMode) -> Unit
) {
    val options = listOf(
        ThemeMode.SYSTEM to "System",
        ThemeMode.DARK to "Dark",
        ThemeMode.LIGHT to "Light"
    )
    Row(
        modifier = Modifier.fillMaxWidth().selectableGroup(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        options.forEach { (mode, label) ->
            val isSelected = selected == mode
            Surface(
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = 48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .selectable(selected = isSelected, role = Role.RadioButton, onClick = { onSelect(mode) }),
                shape = RoundedCornerShape(12.dp),
                color = if (isSelected) VaultThemeColors.AccentEmerald.copy(alpha = 0.16f) else VaultThemeColors.BgElevated,
                border = BorderStroke(
                    if (isSelected) 1.5.dp else 1.dp,
                    if (isSelected) VaultThemeColors.AccentEmerald else VaultThemeColors.BorderSubtle
                )
            ) {
                Box(
                    modifier = Modifier.padding(vertical = 10.dp, horizontal = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (isSelected) VaultThemeColors.AccentEmerald else VaultThemeColors.TextSecondary,
                        maxLines = 1
                    )
                }
            }
        }
    }
}

@Composable
internal fun SelectableOptionCard(
    selected: Boolean,
    title: String,
    description: String,
    badgeText: String,
    badgeColor: Color,
    onClick: () -> Unit
) {
    val border = if (selected) VaultThemeColors.AccentEmerald else VaultThemeColors.BorderSubtle
    val bg = if (selected) VaultThemeColors.BgElevated else VaultThemeColors.BgSurface
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .selectable(selected = selected, role = Role.RadioButton, onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = bg,
        border = BorderStroke(if (selected) 1.5.dp else 1.dp, border)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SecurityPill(badgeText, badgeColor)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(16.dp)
                            .clip(CircleShape)
                            .background(if (selected) VaultThemeColors.AccentEmerald else Color.Transparent)
                            .border(
                                2.dp,
                                if (selected) VaultThemeColors.AccentEmerald else VaultThemeColors.TextSecondary,
                                CircleShape
                            )
                    )
                    Text(title, style = MaterialTheme.typography.titleSmall)
                }
            }
            Text(description, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun FeatureHighlightRow(
    badgeText: String,
    title: String,
    description: String,
    badgeColor: Color = VaultThemeColors.AccentCyan
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(VaultThemeColors.BgElevated)
            .border(1.dp, VaultThemeColors.BorderSubtle, RoundedCornerShape(12.dp))
            .padding(14.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        SecurityPill(badgeText, badgeColor)
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(description, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun VaultTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String = "",
    singleLine: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Text,
    error: String? = null,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = if (placeholder.isNotEmpty()) {
            { Text(placeholder, color = VaultThemeColors.TextSecondary.copy(alpha = 0.7f)) }
        } else {
            null
        },
        singleLine = singleLine,
        isError = error != null,
        supportingText = error?.let { message -> { Text(message) } },
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = vaultFieldColors(),
        keyboardOptions = KeyboardOptions(
            keyboardType = keyboardType,
            autoCorrectEnabled = false
        )
    )
}

@Composable
internal fun VaultSecretField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    visible: Boolean = false,
    onToggleVisible: (() -> Unit)? = null,
    placeholder: String = "",
    useMonoWhenVisible: Boolean = true,
    singleLine: Boolean = true
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = if (placeholder.isNotEmpty()) {
            { Text(placeholder, color = VaultThemeColors.TextSecondary.copy(alpha = 0.7f)) }
        } else {
            null
        },
        singleLine = singleLine,
        minLines = if (singleLine) 1 else 3,
        maxLines = if (singleLine) 1 else 5,
        textStyle = if (visible && useMonoWhenVisible) VaultMonoStyle else MaterialTheme.typography.bodyMedium,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = if (onToggleVisible != null) {
            {
                TextButton(onClick = onToggleVisible) {
                    Text(
                        if (visible) "Hide" else "Show",
                        color = VaultThemeColors.AccentCyan
                    )
                }
            }
        } else {
            null
        },
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = vaultFieldColors(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            autoCorrectEnabled = false
        )
    )
}

@Composable
internal fun OnboardingGuide(
    onFinish: () -> Unit,
    onSkip: () -> Unit,
    isReturningUser: Boolean = false
) {
    var step by remember { mutableIntStateOf(0) }
    androidx.activity.compose.BackHandler { if (step > 0) step-- else onSkip() }
    Column(
        modifier = Modifier.fillMaxSize().background(VaultThemeColors.BgDeep)
            .systemBarsPadding().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            ShieldBadgeIcon()
            Spacer(Modifier.width(10.dp))
            Text("Password Protection", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onSkip) { Text(if (isReturningUser) "Close" else "Skip") }
        }
        Column(
            modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            Text(if (step == 0) "LESS TO REMEMBER" else "A WAY BACK IN", style = MaterialTheme.typography.labelSmall)
            Text(
                if (step == 0) "Your passwords,\nwithout the mental load." else "A lost phone shouldn’t mean lost passwords.",
                style = MaterialTheme.typography.headlineMedium
            )
            Text(
                if (step == 0) "Email, banking, Wi-Fi. Every account needs a different password. Keep them together in a private vault — a locked space on your phone — so you don’t have to remember them all."
                else "A backup is a locked copy of your vault. Your recovery phrase is the key that opens that copy on a new phone. You need both.",
                style = MaterialTheme.typography.bodyMedium
            )
            GuideBenefit(
                if (step == 0) "Save it once. Find it when you need it." else "Save a copy somewhere you can reach.",
                if (step == 0) "Keep passwords and private notes together. Search for an account, then copy what you need."
                else "Choose a file on another device or in Drive. Copies stored only on this phone won’t help if you lose it."
            )
            GuideBenefit(
                if (step == 0) "Make a different password for every account." else "Keep the recovery phrase separately.",
                if (step == 0) "Let the app create a random password or a phrase made of words. Reusing one password puts more accounts at risk."
                else "Write the 33 words down and keep them somewhere safe. Anyone with the backup and its phrase can open it."
            )
            GuideBenefit(
                if (step == 0) "No account to create. Works offline." else "Check that your backup opens.",
                if (step == 0) "Your vault is stored encrypted on your phone: its contents are scrambled until you unlock it. Saving an encrypted copy to Drive is optional."
                else "Use Test backup in Settings to check the file and phrase together. We can’t email you a password reset."
            )
            if (step == 0) {
                Text("Unlock with your phone’s screen lock. Add a separate vault passphrase if you want an extra lock.", style = MaterialTheme.typography.bodySmall)
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            if (step > 0) {
                OutlinedButton(onClick = { step-- }) { Text("Back") }
            }
            Button(onClick = { if (step == 0) step++ else onFinish() }, modifier = Modifier.weight(1f)) {
                Text(if (step == 0) "How to keep a backup" else if (isReturningUser) "Done" else "Set up my vault")
            }
        }
    }
}

@Composable
private fun GuideBenefit(title: String, description: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(description, style = MaterialTheme.typography.bodyMedium, color = VaultThemeColors.TextSecondary)
    }
}
