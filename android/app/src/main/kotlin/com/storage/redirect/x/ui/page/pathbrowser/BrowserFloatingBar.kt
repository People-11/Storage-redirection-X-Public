package com.storage.redirect.x.ui.page.pathbrowser

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.storage.redirect.x.R
import com.storage.redirect.x.data.model.RealPathRuleMode
import com.storage.redirect.x.ui.component.BottomFloatingBar
import com.storage.redirect.x.ui.component.FLOATING_BAR_ITEM_HEIGHT
import com.storage.redirect.x.ui.component.PillButton
import com.storage.redirect.x.ui.icon.AppIcons
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.theme.MiuixTheme

private val BAR_CHIP_HORIZONTAL_PADDING = 14.dp
private val BAR_CHIP_ICON_SIZE = 18.dp

// 规则模式切换（仅规则浏览器）与确认按钮；单选时确认按钮固定为“选择”
@Composable
internal fun BoxScope.BrowserFloatingBar(state: PathBrowserState, onSpaceChange: (Dp) -> Unit, onConfirm: () -> Unit) {
    BottomFloatingBar(
        isVisible = true,
        onSpaceChange = onSpaceChange,
        modifier = Modifier.testTag("browser_floating_bar"),
    ) {
        val colors = browserColors()
        val accent = state.accentColor()
        if (state.allowExclude) {
            val modeLabel = when (state.ruleMode) {
                RealPathRuleMode.Allow -> R.string.browser_allow_access
                RealPathRuleMode.Exclude -> R.string.browser_exclude_directory
                RealPathRuleMode.ReadOnly -> R.string.browser_readonly_directory
            }
            val isAllowMode = state.ruleMode == RealPathRuleMode.Allow
            BarChip(
                text = stringResource(modeLabel),
                color = if (isAllowMode) colors.text else accent,
                background = if (isAllowMode) MiuixTheme.colorScheme.secondaryVariant else state.selectedRowColor(),
                onClick = { state.ruleMode = state.ruleMode.next() },
                modifier = Modifier.testTag("browser_rule_mode"),
                leadingIcon = AppIcons.Swap,
            )
        }
        PillButton(
            text = stringResource(
                when {
                    !state.multiSelect -> R.string.browser_confirm_select
                    state.ruleMode == RealPathRuleMode.Allow -> R.string.browser_confirm_add
                    state.ruleMode == RealPathRuleMode.Exclude -> R.string.browser_confirm_exclude
                    else -> R.string.browser_confirm_readonly
                },
            ),
            onClick = onConfirm,
            modifier = Modifier.testTag("browser_confirm"),
            enabled = state.canConfirm,
            colors = ButtonDefaults.textButtonColorsPrimary(color = accent),
        )
    }
}

@Composable
private fun BarChip(
    text: String,
    color: Color,
    background: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    leadingIcon: ImageVector? = null,
) {
    Row(
        modifier
            .height(FLOATING_BAR_ITEM_HEIGHT)
            .clip(CircleShape)
            .background(background)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = BAR_CHIP_HORIZONTAL_PADDING),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        leadingIcon?.let { Icon(it, null, Modifier.size(BAR_CHIP_ICON_SIZE), tint = color) }
        BrowserText(text, color = color, fontSize = 15.sp, maxLines = 1)
    }
}
