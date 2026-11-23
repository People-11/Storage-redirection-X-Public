#ifndef SRX_INLINE_HOOK_H
#define SRX_INLINE_HOOK_H

#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SRX_INLINE_HOOK_VERSION "1.0.0"

#define SRX_INLINE_HOOK_ERRNO_OK                     0
#define SRX_INLINE_HOOK_ERRNO_PENDING                1
#define SRX_INLINE_HOOK_ERRNO_UNINIT                 2
#define SRX_INLINE_HOOK_ERRNO_INVALID_ARG            3
#define SRX_INLINE_HOOK_ERRNO_OOM                    4
#define SRX_INLINE_HOOK_ERRNO_MPROT                  5
#define SRX_INLINE_HOOK_ERRNO_WRITE_CRASH            6
#define SRX_INLINE_HOOK_ERRNO_INIT_ERRNO             7
#define SRX_INLINE_HOOK_ERRNO_INIT_SIGSEGV           8
#define SRX_INLINE_HOOK_ERRNO_INIT_SIGBUS            9
#define SRX_INLINE_HOOK_ERRNO_INTERCEPT_DUP          10
#define SRX_INLINE_HOOK_ERRNO_INIT_SAFE              11
#define SRX_INLINE_HOOK_ERRNO_INIT_LINKER            12
#define SRX_INLINE_HOOK_ERRNO_INIT_HUB               13
#define SRX_INLINE_HOOK_ERRNO_HUB_CREAT              14
#define SRX_INLINE_HOOK_ERRNO_MONITOR_DLOPEN         15
#define SRX_INLINE_HOOK_ERRNO_HOOK_UNIQUE_DUP        16
#define SRX_INLINE_HOOK_ERRNO_HOOK_DLOPEN_CRASH      17
#define SRX_INLINE_HOOK_ERRNO_HOOK_DLSYM             18
#define SRX_INLINE_HOOK_ERRNO_HOOK_DLSYM_CRASH       19
#define SRX_INLINE_HOOK_ERRNO_HOOK_DUP               20
#define SRX_INLINE_HOOK_ERRNO_HOOK_DLADDR_CRASH      21
#define SRX_INLINE_HOOK_ERRNO_HOOK_DLINFO            22
#define SRX_INLINE_HOOK_ERRNO_HOOK_SYMSZ             23
#define SRX_INLINE_HOOK_ERRNO_HOOK_ENTER             24
#define SRX_INLINE_HOOK_ERRNO_HOOK_REWRITE_CRASH     25
#define SRX_INLINE_HOOK_ERRNO_HOOK_REWRITE_FAILED    26
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_NOTFOUND        27
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_CMP_CRASH       28
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_TRAMPO_MISMATCH 29
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_EXIT_MISMATCH   30
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_EXIT_CRASH      31
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_ON_ERROR        32
#define SRX_INLINE_HOOK_ERRNO_UNHOOK_ON_UNFINISHED   33
#define SRX_INLINE_HOOK_ERRNO_ELF_ARCH_MISMATCH      34
#define SRX_INLINE_HOOK_ERRNO_LINKER_ARCH_MISMATCH   35
#define SRX_INLINE_HOOK_ERRNO_DUP                    36
#define SRX_INLINE_HOOK_ERRNO_NOT_FOUND              37
#define SRX_INLINE_HOOK_ERRNO_NOT_SUPPORT            38
#define SRX_INLINE_HOOK_ERRNO_INIT_TASK              39
#define SRX_INLINE_HOOK_ERRNO_HOOK_ISLAND_EXIT       40
#define SRX_INLINE_HOOK_ERRNO_HOOK_ISLAND_ENTER      41
#define SRX_INLINE_HOOK_ERRNO_HOOK_ISLAND_REWRITE    42
#define SRX_INLINE_HOOK_ERRNO_MODE_CONFLICT          43
#define SRX_INLINE_HOOK_ERRNO_HOOK_MULTI_DUP         44
#define SRX_INLINE_HOOK_ERRNO_DISABLED               45
#define SRX_INLINE_HOOK_ERRNO_REWRITE_UNSUPPORTED    100
#define SRX_INLINE_HOOK_ERRNO_HOOK_OVERLAP           101
#define SRX_INLINE_HOOK_ERRNO_INIT_SIGILL            102

#ifdef __cplusplus
extern "C" {
#endif

const char *srx_inline_hook_get_version(void);

typedef enum {
  SRX_INLINE_HOOK_MODE_SHARED = 0,
  SRX_INLINE_HOOK_MODE_UNIQUE = 1,
  SRX_INLINE_HOOK_MODE_MULTI = 2
} srx_inline_hook_mode_t;

int srx_inline_hook_init(srx_inline_hook_mode_t default_mode, bool debuggable);
int srx_inline_hook_get_init_errno(void);

#define SRX_INLINE_HOOK_IS_SHARED_MODE (SRX_INLINE_HOOK_MODE_SHARED == srx_inline_hook_get_mode())
#define SRX_INLINE_HOOK_IS_UNIQUE_MODE (SRX_INLINE_HOOK_MODE_UNIQUE == srx_inline_hook_get_mode())
#define SRX_INLINE_HOOK_IS_MULTI_MODE  (SRX_INLINE_HOOK_MODE_MULTI == srx_inline_hook_get_mode())

srx_inline_hook_mode_t srx_inline_hook_get_mode(void);
bool srx_inline_hook_get_debuggable(void);
void srx_inline_hook_set_debuggable(bool debuggable);
bool srx_inline_hook_get_recordable(void);
void srx_inline_hook_set_recordable(bool recordable);
bool srx_inline_hook_get_disable(void);
void srx_inline_hook_set_disable(bool disable);

int srx_inline_hook_get_errno(void);
const char *srx_inline_hook_to_errmsg(int error_number);

typedef void (*srx_inline_hook_hooked_t)(int error_number, const char *lib_name, const char *sym_name,
                                    void *sym_addr, void *new_addr, void *orig_addr, void *arg);

void *srx_inline_hook_hook_func_addr(void *func_addr, void *new_addr, void **orig_addr);
void *srx_inline_hook_hook_sym_addr(void *sym_addr, void *new_addr, void **orig_addr);
void *srx_inline_hook_hook_sym_name(const char *lib_name, const char *sym_name, void *new_addr,
                               void **orig_addr);
void *srx_inline_hook_hook_sym_name_callback(const char *lib_name, const char *sym_name, void *new_addr,
                                        void **orig_addr, srx_inline_hook_hooked_t hooked,
                                        void *hooked_arg);
int srx_inline_hook_unhook(void *stub);

#define SRX_INLINE_HOOK_HOOK_DEFAULT          0
#define SRX_INLINE_HOOK_HOOK_WITH_SHARED_MODE 1
#define SRX_INLINE_HOOK_HOOK_WITH_UNIQUE_MODE 2
#define SRX_INLINE_HOOK_HOOK_WITH_MULTI_MODE  4
#define SRX_INLINE_HOOK_HOOK_RECORD           8

void *srx_inline_hook_hook_func_addr_2(void *func_addr, void *new_addr, void **orig_addr, uint32_t flags,
                                  ...);
void *srx_inline_hook_hook_sym_addr_2(void *sym_addr, void *new_addr, void **orig_addr, uint32_t flags,
                                 ...);
void *srx_inline_hook_hook_sym_name_2(const char *lib_name, const char *sym_name, void *new_addr,
                                 void **orig_addr, uint32_t flags);
void *srx_inline_hook_hook_sym_name_callback_2(const char *lib_name, const char *sym_name, void *new_addr,
                                          void **orig_addr, uint32_t flags,
                                          srx_inline_hook_hooked_t hooked, void *hooked_arg);

typedef union {
#if defined(__aarch64__)
  __uint128_t q;
#endif
  uint64_t d[2];
  uint32_t s[4];
  uint16_t h[8];
  uint8_t b[16];
} srx_inline_hook_vreg_t;

typedef struct {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
  srx_inline_hook_vreg_t vregs[32];
  uint64_t fpsr;
  uint64_t fpcr;
} srx_inline_hook_cpu_context_t;

#define SRX_INLINE_HOOK_INTERCEPT_DEFAULT                0
#define SRX_INLINE_HOOK_INTERCEPT_WITH_FPSIMD_READ_ONLY  1
#define SRX_INLINE_HOOK_INTERCEPT_WITH_FPSIMD_WRITE_ONLY 2
#define SRX_INLINE_HOOK_INTERCEPT_WITH_FPSIMD_READ_WRITE 3
#define SRX_INLINE_HOOK_INTERCEPT_RECORD                 4

typedef void (*srx_inline_hook_interceptor_t)(srx_inline_hook_cpu_context_t *cpu_context, void *data);
typedef void (*srx_inline_hook_intercepted_t)(int error_number, const char *lib_name, const char *sym_name,
                                         void *sym_addr, srx_inline_hook_interceptor_t pre, void *data,
                                         void *arg);

void *srx_inline_hook_intercept_instr_addr(void *instr_addr, srx_inline_hook_interceptor_t pre, void *data,
                                      uint32_t flags, ...);
void *srx_inline_hook_intercept_func_addr(void *func_addr, srx_inline_hook_interceptor_t pre, void *data,
                                     uint32_t flags, ...);
void *srx_inline_hook_intercept_sym_addr(void *sym_addr, srx_inline_hook_interceptor_t pre, void *data,
                                    uint32_t flags, ...);
void *srx_inline_hook_intercept_sym_name(const char *lib_name, const char *sym_name,
                                    srx_inline_hook_interceptor_t pre, void *data, uint32_t flags);
void *srx_inline_hook_intercept_sym_name_callback(const char *lib_name, const char *sym_name,
                                             srx_inline_hook_interceptor_t pre, void *data,
                                             uint32_t flags,
                                             srx_inline_hook_intercepted_t intercepted,
                                             void *intercepted_arg);
int srx_inline_hook_unintercept(void *stub);

#define SRX_INLINE_HOOK_RECORD_ITEM_ALL             0x7FF
#define SRX_INLINE_HOOK_RECORD_ITEM_TIMESTAMP       (1u << 0)
#define SRX_INLINE_HOOK_RECORD_ITEM_CALLER_LIB_NAME (1u << 1)
#define SRX_INLINE_HOOK_RECORD_ITEM_OP              (1u << 2)
#define SRX_INLINE_HOOK_RECORD_ITEM_LIB_NAME        (1u << 3)
#define SRX_INLINE_HOOK_RECORD_ITEM_SYM_NAME        (1u << 4)
#define SRX_INLINE_HOOK_RECORD_ITEM_SYM_ADDR        (1u << 5)
#define SRX_INLINE_HOOK_RECORD_ITEM_NEW_ADDR        (1u << 6)
#define SRX_INLINE_HOOK_RECORD_ITEM_BACKUP_LEN      (1u << 7)
#define SRX_INLINE_HOOK_RECORD_ITEM_ERRNO           (1u << 8)
#define SRX_INLINE_HOOK_RECORD_ITEM_STUB            (1u << 9)
#define SRX_INLINE_HOOK_RECORD_ITEM_FLAGS           (1u << 10)

char *srx_inline_hook_get_records(uint32_t item_flags);
void srx_inline_hook_dump_records(int fd, uint32_t item_flags);

void *srx_inline_hook_dlopen(const char *lib_name);
void srx_inline_hook_dlclose(void *handle);
void *srx_inline_hook_dlsym(void *handle, const char *sym_name);
void *srx_inline_hook_dlsym_dynsym(void *handle, const char *sym_name);
void *srx_inline_hook_dlsym_symtab(void *handle, const char *sym_name);

typedef void (*srx_inline_hook_dl_info_t)(struct dl_phdr_info *info, size_t size, void *data);
int srx_inline_hook_register_dl_init_callback(srx_inline_hook_dl_info_t pre, srx_inline_hook_dl_info_t post,
                                         void *data);
int srx_inline_hook_unregister_dl_init_callback(srx_inline_hook_dl_info_t pre, srx_inline_hook_dl_info_t post,
                                           void *data);
int srx_inline_hook_register_dl_fini_callback(srx_inline_hook_dl_info_t pre, srx_inline_hook_dl_info_t post,
                                         void *data);
int srx_inline_hook_unregister_dl_fini_callback(srx_inline_hook_dl_info_t pre, srx_inline_hook_dl_info_t post,
                                           void *data);

void *srx_inline_hook_get_prev_func(void *func);
void srx_inline_hook_pop_stack(void *return_address);
void srx_inline_hook_allow_reentrant(void *return_address);
void srx_inline_hook_disallow_reentrant(void *return_address);
void *srx_inline_hook_get_return_address(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#define SRX_INLINE_HOOK_CALL_PREV(func, ...) \
  ((decltype(&(func)))srx_inline_hook_get_prev_func((void *)(func)))(__VA_ARGS__)
#else
#define SRX_INLINE_HOOK_CALL_PREV(func, func_sig, ...) \
  ((func_sig)srx_inline_hook_get_prev_func((void *)(func)))(__VA_ARGS__)
#endif

#define SRX_INLINE_HOOK_POP_STACK() srx_inline_hook_pop_stack(__builtin_return_address(0))

#ifdef __cplusplus
class SrxInlineHookStackScope {
 public:
  explicit SrxInlineHookStackScope(void *return_address) : return_address_(return_address) {}
  ~SrxInlineHookStackScope() {
    srx_inline_hook_pop_stack(return_address_);
  }

 private:
  void *return_address_;
};
#define SRX_INLINE_HOOK_STACK_SCOPE() \
  SrxInlineHookStackScope srx_inline_hook_stack_scope_obj(__builtin_return_address(0))
#endif

#define SRX_INLINE_HOOK_ALLOW_REENTRANT() srx_inline_hook_allow_reentrant(__builtin_return_address(0))
#define SRX_INLINE_HOOK_DISALLOW_REENTRANT() srx_inline_hook_disallow_reentrant(__builtin_return_address(0))
#define SRX_INLINE_HOOK_RETURN_ADDRESS() srx_inline_hook_get_return_address()

#endif
