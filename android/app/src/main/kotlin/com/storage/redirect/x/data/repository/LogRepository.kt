package com.storage.redirect.x.data.repository

import com.storage.redirect.x.data.service.RootService
import com.storage.redirect.x.util.Paths

// 日志仓库：读取/清空运行日志
class LogRepository {

    suspend fun load(lineCount: Int): String? {
        if (!RootService.isRootAvailable()) return null
        val result = RootService.runCommand(
            "tail -n $lineCount ${Paths.RUNNING_LOG} 2>/dev/null"
        )
        return if (result.isSuccess) result.stdout else null
    }

    suspend fun clear(): Boolean {
        if (!RootService.isRootAvailable()) return false
        return RootService.runCommand(
            "for binary in ${Paths.MODULE_DIR}/bin/*/srx_logd; do " +
                "[ -x \"\$binary\" ] || continue; " +
                "\"\$binary\" control clear-running || exit \$?; " +
                ": > ${Paths.RUNNING_LOG}; exit \$?; done; exit 1"
        ).isSuccess
    }
}
