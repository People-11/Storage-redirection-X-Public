package com.storage.redirect.x.ui.page

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.sp
import com.storage.redirect.x.data.model.StoragePathMapping
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.window.WindowDialog
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import com.storage.redirect.x.R
import com.storage.redirect.x.data.model.RedirectTemplate
import com.storage.redirect.x.ui.icon.AppIcons
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.preference.RadioButtonPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

// 规则配置页、模板编辑页与应用页共用的对话框组件
private val TEMPLATE_PICKER_MAX_HEIGHT = 360.dp
private val MAPPING_DIALOG_BOTTOM_SPACING = 16.dp
private val MAPPING_DIALOG_BUTTON_SPACING = 12.dp

// 映射对话框状态：两个路径只能经目录浏览器选择，选择时已排除受限、重复与链式映射的目录
@Stable
internal class MappingDialogState {
    var isOpen by mutableStateOf(false)
    var requestPath by mutableStateOf("")
    var finalPath by mutableStateOf("")

    fun open() {
        requestPath = ""
        finalPath = ""
        isOpen = true
    }

    fun close() {
        isOpen = false
    }

    // 浏览器返回后回到对话框
    fun pick(path: String, isRequest: Boolean) {
        if (isRequest) requestPath = path else finalPath = path
        isOpen = true
    }
}

// 规则配置页与模板编辑页共用的添加映射对话框；show 由页面决定，浏览期间需隐藏
@Composable
internal fun AddMappingDialog(
    show: Boolean,
    state: MappingDialogState,
    onPickRequest: () -> Unit,
    onPickFinal: () -> Unit,
    onConfirm: (StoragePathMapping) -> Unit,
    tagPrefix: String,
) {
    WindowDialog(
        show = show,
        title = stringResource(R.string.rule_config_add_mapping),
        summary = stringResource(R.string.rule_config_mapping_hint),
        onDismissRequest = state::close,
    ) {
        MappingPathPicker(
            label = stringResource(R.string.rule_config_mapping_request_path),
            path = state.requestPath,
            onClick = onPickRequest,
            modifier = Modifier.testTag("${tagPrefix}_request_picker"),
        )
        MappingDirectionArrow()
        MappingPathPicker(
            label = stringResource(R.string.rule_config_mapping_final_path),
            path = state.finalPath,
            onClick = onPickFinal,
            modifier = Modifier.testTag("${tagPrefix}_final_picker"),
        )
        Spacer(Modifier.height(MAPPING_DIALOG_BOTTOM_SPACING))
        Row {
            TextButton(
                text = stringResource(R.string.common_cancel),
                onClick = state::close,
                modifier = Modifier.weight(1f).testTag("${tagPrefix}_cancel"),
            )
            Spacer(Modifier.width(MAPPING_DIALOG_BUTTON_SPACING))
            TextButton(
                text = stringResource(R.string.common_ok),
                colors = ButtonDefaults.textButtonColorsPrimary(),
                enabled = state.requestPath.isNotEmpty() && state.finalPath.isNotEmpty(),
                onClick = {
                    onConfirm(StoragePathMapping(state.requestPath, state.finalPath))
                    state.close()
                },
                modifier = Modifier.weight(1f).testTag("${tagPrefix}_confirm"),
            )
        }
    }
}

// 路径选择行：点击整行进入浏览器选择，未选时显示占位提示
@Composable
private fun MappingPathPicker(label: String, path: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.fillMaxWidth(),
        cornerRadius = 12.dp,
        insideMargin = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.secondaryVariant),
        onClick = onClick,
        pressFeedbackType = PressFeedbackType.Sink,
        showIndication = true,
    ) {
        Column {
            Text(label, color = MiuixTheme.colorScheme.onSurfaceVariantSummary, fontSize = 12.sp)
            Text(
                text = path.ifEmpty { stringResource(R.string.rule_config_mapping_choose_folder) },
                color = if (path.isEmpty()) {
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                } else {
                    MiuixTheme.colorScheme.onSurface
                },
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

// 映射方向：上方请求路径指向下方最终路径
@Composable
internal fun MappingDirectionArrow() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = AppIcons.ArrowDown,
            contentDescription = null,
            tint = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.size(20.dp),
        )
    }
}

// 模板单选列表：照 only_player 的 OptionsDialog，点选即进入下一步，只保留取消
@Composable
internal fun TemplatePickerContent(
    templates: List<RedirectTemplate>,
    testTag: String,
    onPick: (RedirectTemplate) -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier
            .semantics { testTagsAsResourceId = true }
            .testTag(testTag),
    ) {
        if (templates.isEmpty()) {
            Text(
                text = stringResource(R.string.apps_template_empty),
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = TEMPLATE_PICKER_MAX_HEIGHT)
                    .selectableGroup(),
            ) {
                items(templates, key = { it.id }) { template ->
                    RadioButtonPreference(
                        title = template.name,
                        selected = false,
                        onClick = { onPick(template) },
                        modifier = Modifier.testTag("${testTag}_item_${template.id}"),
                    )
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        TextButton(
            text = stringResource(R.string.common_cancel),
            onClick = onCancel,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("${testTag}_cancel"),
        )
    }
}
