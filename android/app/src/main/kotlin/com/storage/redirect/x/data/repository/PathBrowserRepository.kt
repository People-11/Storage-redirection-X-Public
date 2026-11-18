package com.storage.redirect.x.data.repository

import android.annotation.SuppressLint
import com.storage.redirect.x.data.model.PathValidationResult
import com.storage.redirect.x.data.model.RedirectConfig
import com.storage.redirect.x.data.service.RootService

// 目录浏览数据源，读取当前用户存储目录并转为相对路径
class PathBrowserRepository {

    private companion object {
        const val ANDROID_DIR = "Android"
    }

    // 列出相对目录，默认根目录为 /storage/emulated/{userId}
    suspend fun listRelativeDirectories(userId: Int, relativePath: String): List<String>? {
        val normalized = normalizeRelativePath(relativePath) ?: return null
        val baseDir = "/storage/emulated/$userId"
        val currentDir = if (normalized.isEmpty()) baseDir else "$baseDir/$normalized"

        // -A 列出点前缀目录；仅列目录并保留一层名称，避免文件与额外元信息干扰
        val command = "ls -1 -A -p ${quotePath(currentDir)} 2>/dev/null"
        val result = RootService.runCommand(command)
        if (!result.isSuccess) {
            return null
        }

        return result.stdout
            .lineSequence()
            .map { it.trim() }
            .filter { it.endsWith("/") }
            .map { it.removeSuffix("/") }
            .filter { it.isNotEmpty() }
            .mapNotNull { child ->
                val candidate = if (normalized.isEmpty()) child else "$normalized/$child"
                RedirectConfig.normalizeAllowedPath(candidate)
            }
            .sorted()
            .toList()
    }

    // 私有挂载点属于目标用户和包，不能使用调用方的存储目录。
    // 应用视角的 Android 目录是恢复后的真实目录，只展开到该应用自己的私有目录
    @SuppressLint("SdCardPath")
    suspend fun listAppPrivateDirectories(
        userId: Int,
        packageName: String,
        relativePath: String
    ): List<String>? {
        val normalized = normalizeSimpleRelativePath(relativePath) ?: return null
        val privateRoot = "$ANDROID_DIR/data/$packageName"
        return when {
            normalized.isEmpty() -> {
                val sandboxDir = "/storage/emulated/$userId/$privateRoot/sdcard"
                val children = listChildDirectories(sandboxDir, normalized) ?: return null
                (children + ANDROID_DIR).distinct().sorted()
            }
            normalized == ANDROID_DIR -> listOf("$ANDROID_DIR/data")
            normalized == "$ANDROID_DIR/data" -> listOf(privateRoot)
            normalized == privateRoot || normalized.startsWith("$privateRoot/") -> {
                // 沙盒本身即浏览根目录，不再从私有目录重复进入
                listChildDirectories("/data/media/$userId/$normalized", normalized)
                    ?.filterNot { it == "$privateRoot/sdcard" }
            }
            normalized.startsWith("$ANDROID_DIR/") -> emptyList()
            else -> listChildDirectories("/storage/emulated/$userId/$privateRoot/sdcard/$normalized", normalized)
        }
    }

    private suspend fun listChildDirectories(directory: String, relativeBase: String): List<String>? {
        val command = "ls -1 -A -p ${quotePath(directory)} 2>/dev/null"
        val result = RootService.runCommand(command)
        if (!result.isSuccess) return null

        return result.stdout
            .lineSequence()
            .map { it.trim() }
            .filter { it.endsWith("/") }
            .map { it.removeSuffix("/") }
            .filter { it.isNotEmpty() }
            .map { child -> if (relativeBase.isEmpty()) child else "$relativeBase/$child" }
            .sorted()
            .toList()
    }

    private fun normalizeRelativePath(raw: String): String? {
        if (raw.isBlank()) return ""
        val validated = RedirectConfig.validateAllowedPath(raw)
        return when (validated) {
            is PathValidationResult.Valid -> validated.normalized
            else -> null
        }
    }

    private fun quotePath(path: String): String = "'" + path.replace("'", "'\\''") + "'"

    // 私有路径仅拒绝独立的遍历段，不误拒绝名称中的连续点。
    private fun normalizeSimpleRelativePath(raw: String): String? {
        if (raw.isBlank()) return ""
        val trimmed = raw.trim().trimEnd('/')
        if (trimmed.startsWith("/") || trimmed.split('/').any { it == "." || it == ".." }) return null
        return trimmed
    }
}
