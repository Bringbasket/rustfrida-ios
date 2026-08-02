#include <stddef.h>

/* Keep instruction-cache maintenance in the C target layer. Rust's libc
 * bindings do not expose one stable symbol across iOS SDK generations. */
void rf_cmodule_clear_cache(void *start, void *end) {
#if defined(__APPLE__)
    __builtin___clear_cache((char *)start, (char *)end);
#else
    (void)start;
    (void)end;
#endif
}
