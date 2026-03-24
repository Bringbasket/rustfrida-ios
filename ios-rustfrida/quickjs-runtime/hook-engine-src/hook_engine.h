/*
 * hook_engine.h - ARM64 Inline Hook Engine
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses MOVZ/MOVK + BR X16 jump sequences (up to 20 bytes).
 */

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define HOOK_OK                     0
#define HOOK_ERROR_NOT_INITIALIZED  -1
#define HOOK_ERROR_INVALID_PARAM    -2
#define HOOK_ERROR_ALREADY_HOOKED   -3
#define HOOK_ERROR_ALLOC_FAILED     -4
#define HOOK_ERROR_MPROTECT_FAILED  -5
#define HOOK_ERROR_NOT_FOUND        -6
#define HOOK_ERROR_BUFFER_TOO_SMALL -7
#define HOOK_ERROR_WXSHADOW_FAILED  -8

/* Hook context - contains all ARM64 registers */
typedef struct {
    uint64_t x[31];     /* x0-x30: 0-247 */
    uint64_t sp;        /* Stack pointer: 248 */
    uint64_t pc;        /* Program counter (original): 256 */
    uint64_t nzcv;      /* Condition flags: 264 */
    void* trampoline;   /* Trampoline for callOriginal (NULL if N/A): 272 */
    uint64_t d[8];      /* d0-d7 FP registers: 280-343 */
} HookContext;           /* 344 bytes, fits in 352-byte stack alloc (16-byte aligned) */

/* Callback function types */
typedef void (*HookCallback)(HookContext* ctx, void* user_data);

/* Hook entry structure */
typedef struct HookEntry {
    void* target;                   /* Original function address */
    void* trampoline;               /* Trampoline to call original */
    void* replacement;              /* Replacement function (for replace mode) */
    HookCallback on_enter;          /* Enter callback (for attach mode) */
    HookCallback on_leave;          /* Leave callback (for attach mode) */
    void* user_data;                /* User data for callbacks */
    uint8_t original_bytes[24];     /* Saved original bytes (up to 20 needed) */
    size_t original_size;           /* Number of bytes saved */
    int stealth;                    /* 1 if installed via wxshadow stealth mode */
    void* thunk;                    /* Thunk code pointer (attach mode) */
    size_t trampoline_alloc;        /* Trampoline allocated size */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookEntry* next;         /* Next entry in list */
} HookEntry;

/* Redirect entry — replaces a function pointer (e.g. ArtMethod entry_point)
 * rather than patching inline code.  No instruction relocation needed. */
typedef struct HookRedirectEntry {
    uint64_t key;                   /* Unique identifier (e.g. ArtMethod* address) */
    void* original_entry;           /* Original entry point (for restore on unhook) */
    void* thunk;                    /* Generated redirect thunk */
    size_t thunk_alloc;             /* Thunk allocated size */
    struct HookRedirectEntry* next; /* Next entry in list */
} HookRedirectEntry;

/* Global hook engine state */
typedef struct {
    void* exec_mem;                 /* Executable memory pool */
    size_t exec_mem_size;           /* Total pool size */
    size_t exec_mem_used;           /* Used bytes */
    HookEntry* hooks;               /* Linked list of hooks */
    HookEntry* free_list;           /* Freed entries for reuse */
    HookRedirectEntry* redirects;   /* Linked list of redirect hooks */
    pthread_mutex_t lock;           /* Thread safety lock */
    size_t exec_mem_page_size;      /* Page size for mprotect */
    int initialized;                /* Initialization flag */
} HookEngine;

/*
 * Initialize the hook engine
 *
 * @param exec_mem      Pointer to executable memory region (RWX)
 * @param size          Size of the memory region
 * @return              0 on success, -1 on failure
 */
int hook_engine_init(void* exec_mem, size_t size);

/*
 * Install a simple replacement hook
 *
 * @param target        Address to hook
 * @param replacement   Replacement function address
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              Pointer to trampoline (to call original), NULL on failure
 */
void* hook_install(void* target, void* replacement, int stealth);

/*
 * Install a Frida-style hook with callbacks
 *
 * @param target        Address to hook
 * @param on_enter      Callback called before the function (can be NULL)
 * @param on_leave      Callback called after the function (can be NULL)
 * @param user_data     User data passed to callbacks
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              0 on success, -1 on failure
 */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data, int stealth);

/*
 * Remove a hook
 *
 * @param target        Address that was hooked
 * @return              0 on success, -1 on failure
 */
int hook_remove(void* target);

/*
 * Get the trampoline for a hooked function
 *
 * @param target        Original function address
 * @return              Trampoline address, NULL if not found
 */
void* hook_get_trampoline(void* target);

/*
 * Cleanup and free all hooks
 */
void hook_engine_cleanup(void);

/* Internal functions - exposed for advanced use */

/*
 * Allocate memory from the executable pool
 *
 * @param size          Number of bytes to allocate
 * @return              Pointer to allocated memory, NULL on failure
 */
void* hook_alloc(size_t size);

/*
 * Relocate ARM64 instruction(s) to dst.
 *
 * src_buf  - pointer to a pre-read copy of the original bytes (may differ from
 *            the live address; typically entry->original_bytes read via
 *            /proc/self/mem to bypass XOM pages)
 * src_pc   - original PC of the first instruction (used for PC-relative fixups)
 * dst      - destination address in the executable pool
 * min_bytes - number of bytes to relocate
 * out_written_regs - if non-NULL, receives bitmask of GPRs written by
 *                    relocated instructions (bit N = XN written)
 *
 * Returns number of bytes written to dst.
 */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc,
                                   void* dst, size_t min_bytes,
                                   uint32_t* out_written_regs);

/*
 * Generate an absolute jump (MOVZ/MOVK + BR, up to 20 bytes)
 *
 * @param dst           Where to write the jump
 * @param target        Jump target address
 * @return              Number of bytes written on success, or negative error code
 */
int hook_write_jump(void* dst, void* target);

/*
 * Clear instruction cache for modified code
 *
 * @param start         Start address
 * @param size          Size of region
 */
void hook_flush_cache(void* start, size_t size);

/*
 * Log function type: receives a null-terminated message string.
 * Set via hook_engine_set_log_fn() to route diagnostic output to Rust/socket.
 */
typedef void (*HookLogFn)(const char* msg);

/*
 * Set the log callback.  Call after hook_engine_init().
 * Pass NULL to disable logging.
 */
void hook_engine_set_log_fn(HookLogFn fn);

/*
 * Create a redirect thunk for pointer-based hooking (e.g. ArtMethod entry_point).
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores registers → tail-calls original_entry via BR x16.
 *
 * Unlike hook_attach(), this does NOT patch target code or create a trampoline.
 * The caller is responsible for writing the returned thunk address to the
 * function pointer slot (e.g. ArtMethod->entry_point_from_quick_compiled_code_).
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param original_entry Original function entry point (for tail-call after callback)
 * @param on_enter       Callback called before the original function
 * @param user_data      User data passed to callback
 * @return               Thunk address on success, NULL on failure
 */
void* hook_create_redirect(uint64_t key, void* original_entry,
                           HookCallback on_enter, void* user_data);

/*
 * Remove a redirect hook and return the original entry point.
 *
 * @param key            The key used when creating the redirect
 * @return               Original entry point, NULL if not found
 */
void* hook_remove_redirect(uint64_t key);

/*
 * Create a native hook trampoline for ART "replace with native" hooking.
 *
 * Generates a thunk that: saves context → calls on_enter(ctx, user_data) →
 * restores x0 (return value) → returns to caller (RET).
 *
 * This thunk is designed to be called by ART's JNI trampoline as a native
 * method implementation. The callback receives x0=JNIEnv*, x1=jobject/jclass,
 * x2-x7=Java args via HookContext.
 *
 * @param key            Unique identifier (e.g. ArtMethod* address)
 * @param on_enter       Callback invoked when the method is called
 * @param user_data      User data passed to callback
 * @return               Thunk address (to store in ArtMethod.data_), NULL on failure
 */
void* hook_create_native_trampoline(uint64_t key, HookCallback on_enter, void* user_data);

/*
 * ART router lookup table — inline C-side table for O(N) scan in generated thunk.
 * Eliminates per-call Mutex+HashMap overhead: thunk reads table directly via LDR,
 * no BLR/function call needed.
 */
#define ART_ROUTER_TABLE_MAX 256
typedef struct {
    uint64_t original;      /* Original ArtMethod* (0 = sentinel / end marker) */
    uint64_t replacement;   /* Replacement ArtMethod* */
} ArtRouterEntry;

/*
 * Add an entry to the ART router lookup table.
 * Thread safety: caller must hold g_engine.lock (called during hook setup).
 *
 * @param original      Original ArtMethod* address
 * @param replacement   Replacement ArtMethod* address
 * @return              0 on success, -1 if table full
 */
int hook_art_router_table_add(uint64_t original, uint64_t replacement);

/*
 * Remove an entry from the ART router lookup table.
 *
 * @param original      Original ArtMethod* address to remove
 * @return              0 on success, -1 if not found
 */
int hook_art_router_table_remove(uint64_t original);

/*
 * Clear all entries from the ART router lookup table.
 */
void hook_art_router_table_clear(void);

/*
 * Dump all entries in the ART router lookup table (via hook_log).
 */
void hook_art_router_table_dump(void);

/*
 * Debug: simulate the thunk's table scan for a given ArtMethod* address.
 * Returns 1 if found, 0 if not found. Logs the result via hook_log.
 */
int hook_art_router_debug_scan(uint64_t x0);

/*
 * Debug: hex dump code at given address (via hook_log).
 */
void hook_dump_code(void* addr, size_t size);

/*
 * Debug: get last X0 seen in not_found path and miss count.
 * The ART router thunk stores X0 to a global on every not_found scan.
 */
void hook_art_router_get_debug(uint64_t* last_x0, uint64_t* miss_count);

/*
 * Debug: reset the not_found X0 capture and miss counter.
 */
void hook_art_router_reset_debug(void);

/*
 * Install an ART method router hook with inline table lookup.
 *
 * Generates a routing trampoline that:
 *   1. Saves X16/X17 (IPC scratch registers)
 *   2. Scans g_art_router_table inline (no function call)
 *   3. If found: x0 = replacement, jump to replacement.quickCode
 *   4. If not found: restore, execute relocated original, jump back
 *
 * Uses the HookEntry infrastructure (inline patches target with MOVZ/MOVK+BR).
 *
 * @param target            Address to hook (quickCode entry point)
 * @param quickcode_offset  Offset of entry_point_from_quick_compiled_code_ in ArtMethod
 * @param stealth           1 to use wxshadow stealth mode, 0 for normal mode
 * @param jni_env           JNIEnv* for resolving tiny ART trampolines
 * @param out_hooked_target If non-NULL, receives the actual hooked address (may differ
 *                          from target if resolve_art_trampoline resolved a tiny trampoline)
 * @return                  Trampoline address (relocated original instructions), NULL on failure
 */
void* hook_install_art_router(void* target, uint32_t quickcode_offset,
                               int stealth, void* jni_env,
                               void** out_hooked_target);

/*
 * Create a standalone ART method router stub (no inline patching).
 *
 * Allocates executable memory and generates a thunk that:
 *   1. Saves X16/X17 (IPC scratch registers)
 *   2. Scans g_art_router_table inline for X0 match
 *   3. If found: X0 = replacement, jump to replacement.quickCode
 *   4. If not found: restore scratch, jump to fallback_target
 *
 * Unlike hook_install_art_router(), this does NOT patch any existing code.
 * The caller should set ArtMethod.entry_point_ to the returned address.
 * This avoids the interpreter-to-interpreter fast path that bypasses
 * inline-hooked assembly bridges.
 *
 * Thread-safe: the stub is shared across all hooked methods that use the
 * same fallback_target.
 *
 * @param fallback_target   Address to jump to when X0 is not in table
 *                          (e.g., original interpreter_bridge address)
 * @param quickcode_offset  Offset of entry_point_ in ArtMethod
 * @return                  Stub address, NULL on failure
 */
void* hook_create_art_router_stub(uint64_t fallback_target,
                                   uint32_t quickcode_offset);

/*
 * Install a replace-mode hook (save ctx → callback → restore x0 → RET)
 *
 * Unlike hook_attach(), the thunk does NOT automatically call the original
 * function. The callback can invoke the original via hook_invoke_trampoline().
 *
 * @param target        Address to hook
 * @param on_enter      Callback called when the function is entered
 * @param user_data     User data passed to callback
 * @param stealth       1 to use wxshadow stealth mode, 0 for normal mode
 * @return              Trampoline address (for callOriginal), NULL on failure
 */
void* hook_replace(void* target, HookCallback on_enter, void* user_data, int stealth);

/*
 * Restore registers from HookContext and call trampoline (original function).
 * Returns x0 (the original function's return value).
 *
 * Implemented in assembly. Restores x0-x15 from ctx, calls trampoline via BLR,
 * and returns the result. For float/double returns, d0 is NOT captured.
 *
 * @param ctx           Pointer to HookContext with saved registers
 * @param trampoline    Trampoline address (relocated original instructions)
 * @return              x0 result from the original function
 */
uint64_t hook_invoke_trampoline(HookContext* ctx, void* trampoline);

#ifdef __cplusplus
}
#endif

#endif /* HOOK_ENGINE_H */
