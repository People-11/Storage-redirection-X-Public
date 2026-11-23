#ifndef SRX_INLINE_HOOK_H
#define SRX_INLINE_HOOK_H

#include <stdbool.h>

#define SRX_INLINE_HOOK_VERSION "1.0.0"

#ifdef __cplusplus
extern "C" {
#endif

// 幂等；每个函数地址只允许一个 hook。成功返回 0，失败返回错误码
int srx_inline_hook_init(bool debuggable);

// orig_addr 可为 NULL；成功返回 stub，失败返回 NULL
void *srx_inline_hook_hook_func_addr(void *func_addr, void *new_addr, void **orig_addr);

// 成功返回 0，失败返回 -1
int srx_inline_hook_unhook(void *stub);

#ifdef __cplusplus
}
#endif

#endif
