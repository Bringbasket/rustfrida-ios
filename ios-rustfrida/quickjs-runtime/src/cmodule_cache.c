#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#endif

/* Keep instruction-cache maintenance in the C target layer. Rust's libc
 * bindings do not expose one stable symbol across iOS SDK generations. */
void rf_cmodule_clear_cache(void *start, void *end) {
#if defined(__APPLE__)
    uintptr_t begin = (uintptr_t)start;
    uintptr_t limit = (uintptr_t)end;
    if (limit > begin) {
        sys_icache_invalidate(start, (size_t)(limit - begin));
    }
#else
    (void)start;
    (void)end;
#endif
}
