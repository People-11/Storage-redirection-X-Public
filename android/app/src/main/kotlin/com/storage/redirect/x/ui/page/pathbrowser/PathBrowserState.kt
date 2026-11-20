package com.storage.redirect.x.ui.page.pathbrowser

import android.annotation.SuppressLint
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.storage.redirect.x.data.model.PathValidationResult
import com.storage.redirect.x.data.model.RealPathRuleMode
import com.storage.redirect.x.data.model.RedirectConfig
import com.storage.redirect.x.data.repository.PathBrowserRepository

// Covered 表示祖先目录已选中，此目录随祖先一起生效
internal enum class DirectorySelection { None, Partial, Selected, Covered }

@Stable
internal class PathBrowserState(
    val userId: Int,
    val packageName: String?,
    val multiSelect: Boolean,
    val allowExclude: Boolean,
    // 单选映射路径时，与这些路径重叠的目录会形成重复或链式映射
    val blockedPaths: List<String> = emptyList(),
) {
    var currentPath by mutableStateOf("")
        private set
    var query by mutableStateOf("")
    var directories by mutableStateOf<List<String>>(emptyList())
        private set
    var selectedPaths by mutableStateOf<Set<String>>(emptySet())
        private set
    var isLoading by mutableStateOf(true)
        private set
    var hasLoadError by mutableStateOf(false)
        private set
    var showHidden by mutableStateOf(true)
    var isDescending by mutableStateOf(false)
    var ruleMode by mutableStateOf(RealPathRuleMode.Allow)
    var reloadKey by mutableIntStateOf(0)
    var isSearchActive by mutableStateOf(false)
    var isPathPanelExpanded by mutableStateOf(false)
    private var loadGeneration = 0

    // 目标可能属于其他用户或应用私有挂载点，不能使用当前用户的存储目录。
    @get:SuppressLint("SdCardPath")
    val rootPath: String
        get() = if (packageName == null) "/storage/emulated/$userId"
        else "/storage/emulated/$userId/Android/data/$packageName/sdcard"

    val absolutePath: String
        get() = if (currentPath.isEmpty()) rootPath else "$rootPath/$currentPath"

    val currentName: String
        get() = currentPath.substringAfterLast('/')

    val visibleDirectories: List<String>
        get() = directories.filter { path ->
            val name = path.substringAfterLast('/')
            (showHidden || !name.startsWith('.')) && name.contains(query.trim(), ignoreCase = true)
        }.let { if (isDescending) it.reversed() else it }

    val canConfirm: Boolean
        get() = confirmablePaths.isNotEmpty()

    // 切换模式后，已选目录可能变为始终允许，不再生成规则
    private val confirmablePaths: List<String>
        get() = selectedPaths.filterNot(::isAlwaysAllowed)

    // 多选按规则校验，单选按映射路径校验；受限目录仍可进入，只是不能勾选
    fun canSelect(path: String): Boolean {
        if (path.isEmpty()) return false
        if (multiSelect) return RedirectConfig.validateRealPathRule(ruleMode.prefix + path) is PathValidationResult.Valid
        return RedirectConfig.validateMappingPath(path, packageName) is PathValidationResult.Valid &&
            blockedPaths.none { RedirectConfig.isPathOverlapping(it, path) }
    }

    fun navigateTo(path: String) {
        // 在新协程启动前失效旧请求，同一路径的往返也不能复用旧结果。
        loadGeneration += 1
        currentPath = path
        query = ""
        isSearchActive = false
        isPathPanelExpanded = false
        directories = emptyList()
        isLoading = true
        hasLoadError = false
        reloadKey++
    }

    fun selectionOf(path: String): DirectorySelection = when {
        isAlwaysAllowed(path) -> DirectorySelection.Covered
        path in selectedPaths -> DirectorySelection.Selected
        !multiSelect -> DirectorySelection.None
        selectedPaths.any { isAncestor(it, path) } -> DirectorySelection.Covered
        selectedPaths.any { isAncestor(path, it) } -> DirectorySelection.Partial
        else -> DirectorySelection.None
    }

    // 单选只保留最后一次勾选；多选时选中父目录会移除已选子目录，祖先已选中时子目录不再单独加入
    fun togglePath(path: String) {
        if (!canSelect(path)) return
        if (!multiSelect) {
            selectedPaths = if (path in selectedPaths) emptySet() else setOf(path)
            return
        }
        selectedPaths = when (selectionOf(path)) {
            DirectorySelection.Selected -> selectedPaths - path
            DirectorySelection.Covered -> return
            DirectorySelection.None, DirectorySelection.Partial ->
                selectedPaths.filterNot { isAncestor(path, it) }.toSet() + path
        }
    }

    // 后端始终恢复 Android 目录，界面显示为已选，不生成规则
    private fun isAlwaysAllowed(path: String): Boolean = allowExclude &&
        RedirectConfig.validateRealPathRule(ruleMode.prefix + path) is PathValidationResult.AndroidAlwaysAllowed

    private fun isAncestor(ancestor: String, path: String): Boolean = path.startsWith("$ancestor/")

    fun closeSearch() {
        isSearchActive = false
        query = ""
    }

    fun confirmedPaths(): List<String> {
        if (!canConfirm) return emptyList()
        val prefix = ruleMode.prefix
        return confirmablePaths.map { prefix + it }
    }

    suspend fun load(repository: PathBrowserRepository) {
        loadGeneration += 1
        val generation = loadGeneration
        val path = currentPath
        isLoading = true
        hasLoadError = false
        directories = emptyList()
        val result = if (packageName == null) {
            repository.listRelativeDirectories(userId, path)
        } else {
            repository.listAppPrivateDirectories(userId, packageName, path)
        }
        if (generation != loadGeneration) return
        directories = result.orEmpty()
        hasLoadError = result == null
        isLoading = false
    }
}
