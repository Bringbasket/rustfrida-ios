/*
 * hook_engine.c - ARM64 Inline Hook Engine — Core
 *
 * Global state, logging, initialization, find_hook, cleanup.
 * Implementation details are split across:
 *   hook_engine_mem.c    — memory pool, alloc, wxshadow, relocate
 *   hook_engine_inline.c — inline hook install/attach/replace/remove
 *   hook_engine_redir.c  — redirect and native thunks
 *   hook_engine_art.c    — ART method router
 */

#include "hook_engine_internal.h"

/* Global engine state */
HookEngine g_engine = {0};
volatile uint64_t g_hook_active_thunks = 0;

/* --- Diagnostic log infrastructure --- */

HookLogFn g_log_fn = NULL;

void hook_engine_set_log_fn(HookLogFn fn) {
    g_log_fn = fn;
}

void hook_log(const char* fmt, ...) {
    if (!g_log_fn) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_fn(buf);
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    if (g_engine.initialized) {
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.retired_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (!g_engine.lock_initialized) {
        pthread_mutex_init(&g_engine.lock, NULL);
        g_engine.lock_initialized = 1;
    }
    __atomic_store_n(&g_hook_active_thunks, 0, __ATOMIC_RELEASE);
    g_engine.initialized = 1;

    return 0;
}

/* Find hook entry by target address */
HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

int hook_engine_wait_for_quiescence(uint32_t timeout_ms) {
    struct timespec start;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        if (__atomic_load_n(&g_hook_active_thunks, __ATOMIC_ACQUIRE) == 0) {
            /* A thread may already have fetched the branch into a thunk while
             * the target was being restored. Give that instruction pipeline a
             * short grace interval before the pool can be unmapped/reused. */
            struct timespec grace = {0, 1000000L};
            nanosleep(&grace, NULL);
            if (__atomic_load_n(&g_hook_active_thunks, __ATOMIC_ACQUIRE) == 0) {
                return 1;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t sec = (int64_t)now.tv_sec - (int64_t)start.tv_sec;
        int64_t nsec = (int64_t)now.tv_nsec - (int64_t)start.tv_nsec;
        if (nsec < 0) {
            sec--;
            nsec += 1000000000LL;
        }
        uint64_t elapsed_ns = (uint64_t)sec * 1000000000ULL + (uint64_t)nsec;
        if (elapsed_ns >= (uint64_t)timeout_ms * 1000000ULL) {
            return 0;
        }

        struct timespec pause = {0, 1000000L};
        nanosleep(&pause, NULL);
    }
}

/* Cleanup all hooks */
int hook_engine_cleanup(void) {
    if (!g_engine.initialized) return 0;
    if (!hook_engine_wait_for_quiescence(200)) {
        hook_log("hook_engine_cleanup: active generated thunks did not quiesce");
        return -1;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Count hooks on both lists for diagnostics */
    int hooks_count = 0, free_count = 0, retired_count = 0;
    int stealth_hooks = 0, stealth_free = 0, stealth_retired = 0;
    for (HookEntry* e = g_engine.hooks; e; e = e->next) {
        hooks_count++;
        if (e->stealth) stealth_hooks++;
    }
    for (HookEntry* e = g_engine.free_list; e; e = e->next) {
        free_count++;
        if (e->stealth) stealth_free++;
    }
    for (HookEntry* e = g_engine.retired_list; e; e = e->next) {
        retired_count++;
        if (e->stealth) stealth_retired++;
    }
    hook_log("hook_engine_cleanup: hooks=%d (stealth=%d), free_list=%d (stealth=%d), retired=%d (stealth=%d)",
             hooks_count, stealth_hooks, free_count, stealth_free, retired_count, stealth_retired);

    /* Restore each live hook individually. Stealth hooks must be released
     * using the exact patch start address passed during PATCH. */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->stealth) {
            int rc = wxshadow_release(entry->target);
            if (rc != 0) {
                hook_log("hook_engine_cleanup: wxshadow_release failed for %p", entry->target);
            }
        } else {
            uintptr_t page_start = (uintptr_t)entry->target & ~0xFFF;
            mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(entry->target, entry->original_bytes, entry->original_size);
            restore_page_rx(page_start);
            hook_flush_cache(entry->target, entry->original_size);
        }
        entry = entry->next;
    }

    /* HookEntry lifetime note:
     * All HookEntry structs (including trampoline and thunk memory) live inside
     * g_engine.exec_mem (the executable pool). The pool is a single mmap'd region
     * that is released via munmap by the caller after hook_engine_cleanup() returns.
     * Therefore we do NOT iterate the list to free individual entries here — the
     * munmap in the caller frees the entire pool at once.
     *
     * WARNING: Do NOT add malloc()/free() fallback paths for alloc_entry(). If pool
     * allocations ever fall back to malloc, those pointers would be invalid after a
     * munmap and would require explicit free() here. Keep all hook memory in the pool. */

    /* Reset state — the list pointers are now dangling (pool about to be unmapped) */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.retired_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.initialized = 0;

    pthread_mutex_unlock(&g_engine.lock);

    /* Do not destroy the global mutex here. A late cleanup/reclaim caller may
     * have observed the old initialized state and still be about to lock it. */
    return 0;
}
