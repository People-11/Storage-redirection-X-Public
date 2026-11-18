package com.storage.redirect.x.ui.page

import android.content.ContentResolver
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.storage.redirect.x.data.repository.BackupExportResult
import com.storage.redirect.x.data.repository.BackupRestoreRepository
import com.storage.redirect.x.data.repository.ConfigRepository
import com.storage.redirect.x.data.repository.RestoreResult
import com.storage.redirect.x.data.service.MonitorService
import com.storage.redirect.x.data.service.RootService
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SettingsUiState(
    val hasRoot: Boolean? = null,
    val isWorking: Boolean = false,
    val isFuseFixerEnabled: Boolean = false,
    val isFileMonitorEnabled: Boolean = true,
    val fileMonitorRetentionSeconds: Long = 604800L,
)

sealed class SettingsUiEvent {
    data object SaveFailed : SettingsUiEvent()
    data class BackupFinished(val result: BackupExportResult) : SettingsUiEvent()
    data class RestoreFinished(val result: RestoreResult) : SettingsUiEvent()
}

// 设置页状态管理，统一处理 Root 状态和备份还原任务。
class SettingsViewModel(
    private val backupRestoreRepo: BackupRestoreRepository = BackupRestoreRepository(),
    private val configRepo: ConfigRepository = ConfigRepository(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<SettingsUiEvent>()
    val events: SharedFlow<SettingsUiEvent> = _events.asSharedFlow()

    init {
        refreshRootStatus()
        viewModelScope.launch {
            ConfigRepository.monitorEnabled.filterNotNull().collect { isEnabled ->
                _uiState.update { it.copy(isFileMonitorEnabled = isEnabled) }
            }
        }
    }

    // 刷新当前 Root 可用性。
    fun refreshRootStatus() {
        viewModelScope.launch {
            val hasRoot = RootService.isRootAvailable()
            _uiState.update { it.copy(hasRoot = hasRoot) }
            if (hasRoot) {
                val isFuseFixerEnabled = configRepo.readFuseFixerEnabled()
                configRepo.readFileMonitorEnabled()
                val retention = configRepo.readFileMonitorRetention()
                _uiState.update {
                    it.copy(isFuseFixerEnabled = isFuseFixerEnabled, fileMonitorRetentionSeconds = retention)
                }
            }
        }
    }

    fun exportPackageConfigsZip(contentResolver: ContentResolver, outputUri: Uri) = launchRootTask {
        SettingsUiEvent.BackupFinished(backupRestoreRepo.exportPackageConfigsZip(contentResolver, outputUri))
    }

    fun restorePackageConfigs() = launchRootTask {
        SettingsUiEvent.RestoreFinished(backupRestoreRepo.restorePackageConfigs())
    }

    fun restorePackageConfigsFromUri(contentResolver: ContentResolver, inputUri: Uri) = launchRootTask {
        SettingsUiEvent.RestoreFinished(backupRestoreRepo.restorePackageConfigsFromUri(contentResolver, inputUri))
    }

    fun setFuseFixerEnabled(isEnabled: Boolean) = launchRootTask {
        val previous = _uiState.value.isFuseFixerEnabled
        _uiState.update { it.copy(isFuseFixerEnabled = isEnabled) }
        val redirectApps = configRepo.load(0).redirectApps
        val isSaved = configRepo.setFuseFixerEnabled(isEnabled)
        if (isSaved) {
            RootService.restartMediaProvider(redirectApps)
        }
        _uiState.update { it.copy(isFuseFixerEnabled = if (isSaved) isEnabled else previous) }
        null
    }

    // 开关状态由 ConfigRepository.monitorEnabled 在保存成功后推送
    fun setFileMonitorEnabled(isEnabled: Boolean) = launchRootTask {
        if (!configRepo.setFileMonitorEnabled(isEnabled)) return@launchRootTask SettingsUiEvent.SaveFailed
        if (!isEnabled) MonitorService.clear()
        null
    }

    fun setFileMonitorRetention(seconds: Long) = launchRootTask {
        if (!configRepo.setFileMonitorRetention(seconds)) return@launchRootTask SettingsUiEvent.SaveFailed
        _uiState.update { it.copy(fileMonitorRetentionSeconds = seconds) }
        null
    }

    // Root 操作串行执行：无 Root 或已有任务时忽略；任务结束清除忙碌状态后再发出它返回的事件
    private fun launchRootTask(task: suspend () -> SettingsUiEvent?) {
        if (_uiState.value.hasRoot != true || _uiState.value.isWorking) return
        viewModelScope.launch {
            _uiState.update { it.copy(isWorking = true) }
            val event = task()
            _uiState.update { it.copy(isWorking = false) }
            event?.let { _events.emit(it) }
        }
    }
}
