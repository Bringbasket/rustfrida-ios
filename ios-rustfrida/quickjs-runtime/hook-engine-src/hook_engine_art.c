/*
 * hook_engine_art.c - ART method router: table, thunk generation, router hooks
 *
 * Contains: ART router lookup table management, debug functions,
 * FP instruction helpers, generate_art_router_thunk, resolve_art_trampoline,
 * hook_install_art_router, hook_create_art_router_stub.
 */

#include "hook_engine_internal.h"

/* --- ART router lookup table (inline scan from generated thunk) --- */

ArtRouterEntry g_art_router_table[ART_ROUTER_TABLE_MAX];

/* Debug: last X0 seen in not_found path + miss counter */
volatile uint64_t g_art_router_last_x0 = 0;
volatile uint64_t g_art_router_miss_count = 0;

/* ============================================================================
 * ART router table management
 * ============================================================================ */

int hook_art_router_table_add(uint64_t original, uint64_t replacement) {
    /* Find first empty slot (original == 0 is sentinel) */
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == original) {
            /* Already exists — update replacement */
            g_art_router_table[i].replacement = replacement;
            return 0;
        }
        if (g_art_router_table[i].original == 0) {
            g_art_router_table[i].original = original;
            g_art_router_table[i].replacement = replacement;
            return 0;
        }
    }
    hook_log("[art_router] table full (max %d)", ART_ROUTER_TABLE_MAX);
    return -1;
}

int hook_art_router_table_remove(uint64_t original) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0)
            break; /* hit sentinel — not found */
        if (g_art_router_table[i].original == original) {
            /* Shift remaining entries down to keep table compact */
            int j = i;
            while (j + 1 < ART_ROUTER_TABLE_MAX && g_art_router_table[j + 1].original != 0) {
                g_art_router_table[j] = g_art_router_table[j + 1];
                j++;
            }
            g_art_router_table[j].original = 0;
            g_art_router_table[j].replacement = 0;
            return 0;
        }
    }
    return -1;
}

void hook_art_router_table_clear(void) {
    memset(g_art_router_table, 0, sizeof(g_art_router_table));
}

void hook_art_router_table_dump(void) {
    hook_log("[art_router] table dump (addr=%p):", (void*)g_art_router_table);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router]   [%d] <end> (total %d entries)", i, i);
            return;
        }
        hook_log("[art_router]   [%d] original=%llx -> replacement=%llx",
                 i,
                 (unsigned long long)g_art_router_table[i].original,
                 (unsigned long long)g_art_router_table[i].replacement);
    }
    hook_log("[art_router]   table full (%d entries)", ART_ROUTER_TABLE_MAX);
}

int hook_art_router_debug_scan(uint64_t x0) {
    hook_log("[art_router] debug_scan: searching for x0=%llx", (unsigned long long)x0);
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0) {
            hook_log("[art_router] debug_scan: NOT FOUND after %d entries", i);
            return 0;
        }
        if (g_art_router_table[i].original == x0) {
            hook_log("[art_router] debug_scan: FOUND at [%d] -> replacement=%llx",
                     i, (unsigned long long)g_art_router_table[i].replacement);
            return 1;
        }
    }
    hook_log("[art_router] debug_scan: NOT FOUND (table full)");
    return 0;
}

void hook_dump_code(void* addr, size_t size) {
    if (!addr || size == 0) return;
    hook_log("[dump_code] %p (%zu bytes):", addr, size);

    const uint8_t* p = (const uint8_t*)addr;
    for (size_t i = 0; i < size; i += 4) {
        if (i + 4 <= size) {
            uint32_t insn = *(const uint32_t*)(p + i);
            hook_log("  +%03zx: %08x", i, insn);
        } else {
            /* Partial last word */
            hook_log("  +%03zx: (partial)", i);
        }
    }
}

void hook_art_router_get_debug(uint64_t* last_x0, uint64_t* miss_count) {
    if (last_x0)    *last_x0    = g_art_router_last_x0;
    if (miss_count) *miss_count = g_art_router_miss_count;
}

void hook_art_router_reset_debug(void) {
    g_art_router_last_x0 = 0;
    g_art_router_miss_count = 0;
}

/* ============================================================================
 * ART router thunk helpers — shared code blocks for generate_art_router_thunk
 * and hook_create_art_router_stub.
 * ============================================================================ */

/* Save X16/X17 to stack, save d0-d7, load g_art_router_table into X16 */
static void emit_art_router_prologue(Arm64Writer* w) {
    arm64_writer_put_stp_reg_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17,
                                             ARM64_REG_SP, -16, ARM64_INDEX_PRE_ADJUST);
    arm64_writer_put_sub_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 64);
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_stp_offset(w, i, i + 1, ARM64_REG_SP, i * 8);
    }
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)g_art_router_table);
}

/* Emit inline scan loop: LDR/CBZ/CMP/B.EQ/ADD/B.
 * Returns found and not_found label IDs via out-pointers. */
static void emit_art_router_scan_loop(Arm64Writer* w,
                                       uint64_t* lbl_found_out,
                                       uint64_t* lbl_not_found_out) {
    uint64_t lbl_loop = arm64_writer_new_label_id(w);
    uint64_t lbl_found = arm64_writer_new_label_id(w);
    uint64_t lbl_not_found = arm64_writer_new_label_id(w);

    arm64_writer_put_label(w, lbl_loop);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_cbz_reg_label(w, ARM64_REG_X17, lbl_not_found);
    arm64_writer_put_cmp_reg_reg(w, ARM64_REG_X17, ARM64_REG_X0);
    arm64_writer_put_b_cond_label(w, ARM64_COND_EQ, lbl_found);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X16, ARM64_REG_X16, 16);
    arm64_writer_put_b_label(w, lbl_loop);

    *lbl_found_out = lbl_found;
    *lbl_not_found_out = lbl_not_found;
}

/* Restore d0-d7 + deallocate 64-byte FP stack space */
static void emit_art_router_restore_fp(Arm64Writer* w) {
    for (int i = 0; i < 8; i += 2) {
        arm64_writer_put_fp_ldp_offset(w, i, i + 1, ARM64_REG_SP, i * 8);
    }
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 64);
}

/* Debug: store X0 to g_art_router_last_x0, increment g_art_router_miss_count */
static void emit_art_router_debug_counters(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_last_x0);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 0);
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_art_router_miss_count);
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_X17, ARM64_REG_X17, 1);
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X16, 0);
}

/* Found path: load replacement into X0, sync declaring_class_ from original,
 * load quickCode, restore d0-d7, discard saved X16/X17, BR X17 to replacement.quickCode.
 *
 * declaring_class_ sync: GC updates the original ArtMethod's declaring_class_
 * (offset 0, 4-byte GcRoot) but our heap-allocated replacement is NOT tracked
 * by the GC.  Copying it inline here eliminates the race window between GC
 * moving the class object and our on_gc_sync_leave callback. */
static void emit_art_router_found_path(Arm64Writer* w, uint64_t lbl_found,
                                        uint32_t quickcode_offset) {
    arm64_writer_put_label(w, lbl_found);
    /* At this point: X17 = original ArtMethod* (from scan), X16 = &table[i] */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X0, ARM64_REG_X16, 8);   /* X0 = replacement */
    /* Sync declaring_class_ (4 bytes at offset 0): original → replacement.
     * X17 still holds the original ArtMethod*; W16 is free after loading replacement. */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_W16, ARM64_REG_X17, 0);  /* W16 = original.declaring_class_ */
    arm64_writer_put_str_reg_reg_offset(w, ARM64_REG_W16, ARM64_REG_X0, 0);   /* replacement.declaring_class_ = W16 */
    arm64_writer_put_ldr_reg_reg_offset(w, ARM64_REG_X17, ARM64_REG_X0, (int64_t)quickcode_offset);
    emit_art_router_restore_fp(w);
    arm64_writer_put_add_reg_reg_imm(w, ARM64_REG_SP, ARM64_REG_SP, 16);
    arm64_writer_put_mov_reg_reg(w, ARM64_REG_X16, ARM64_REG_X17);
    emit_thunk_activity_leave_and_branch(w);
}

/* Not-found path: label → debug counters → restore FP → restore X16/X17 →
 * load fallback target into X17 → BR X17.
 * Shared by generate_art_router_thunk and hook_create_art_router_stub. */
static void emit_art_router_not_found_path(Arm64Writer* w, uint64_t lbl_not_found,
                                            uint64_t fallback_target) {
    fallback_target = hook_normalize_code_u64(fallback_target);

    arm64_writer_put_label(w, lbl_not_found);
    emit_art_router_debug_counters(w);
    emit_art_router_restore_fp(w);

    /* Restore X16/X17 */
    arm64_writer_put_ldp_reg_reg_reg_offset(w, ARM64_REG_X16, ARM64_REG_X17,
                                             ARM64_REG_SP, 16, ARM64_INDEX_POST_ADJUST);

    /* Jump to fallback target (X16/X17 are IPC scratch registers). */
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, fallback_target);
    emit_thunk_activity_leave_and_branch(w);
}

/* ============================================================================
 * ART router thunk generation (uses helpers above)
 *
 * not_found path: jump to trampoline_target (relocated original instructions).
 * X16/X17 are NOT restored (clobbered by thunk, caller uses X17 for jump-back).
 * ============================================================================ */

static size_t generate_art_router_thunk(void* thunk_mem, size_t thunk_alloc,
                                         void* trampoline_target,
                                         uint32_t quickcode_offset) {
    trampoline_target = hook_normalize_code_ptr(trampoline_target);

    Arm64Writer w;
    arm64_writer_init(&w, thunk_mem, (uint64_t)thunk_mem, thunk_alloc);

    emit_thunk_activity_enter(&w);
    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);
    emit_art_router_found_path(&w, lbl_found, quickcode_offset);

    /* === not_found path: fall through to trampoline === */
    emit_art_router_not_found_path(&w, lbl_not_found, (uint64_t)trampoline_target);

    arm64_writer_flush(&w);
    size_t thunk_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    return thunk_size;
}

/* ============================================================================
 * Tiny ART trampoline resolver
 *
 * Some ART entry points (e.g. quick_generic_jni_trampoline) are tiny 8-byte
 * trampolines:
 *   LDR Xt, [X19, #imm]
 *   BR Xt
 *
 * X19 holds the Thread* pointer (current ART thread).  We resolve the actual
 * target by reading Thread*->field at the given offset.
 *
 * jni_env: JNIEnv* pointer.  On Android, JNIEnv* == Thread* + some offset.
 *          Typically Thread* = JNIEnv* - 0 (JNIEnv is the first field).
 * ============================================================================ */

static void* resolve_art_trampoline(void* target, void* jni_env) {
    target = hook_normalize_code_ptr(target);

    if (!target || !jni_env) return target;

    /* Read first two instructions */
    uint8_t buf[8];
    if (read_target_safe(target, buf, 8) != 0)
        return target;

    uint32_t insn0 = *(uint32_t*)buf;
    uint32_t insn1 = *(uint32_t*)(buf + 4);

    /* Check pattern: LDR Xt, [X19, #imm]  = 1111 1001 01 imm12 10011 Rt
     * Mask: 0xFFC003E0, expect: 0xF9400260 (base=X19, any Rt, any imm12) */
    if ((insn0 & 0xFFC003E0) != 0xF9400260)
        return target;

    /* Check: BR Xt — 1101 0110 0001 1111 0000 00 Rn 00000
     * Mask: 0xFFFFFC1F, expect: 0xD61F0000 */
    uint32_t rt_ldr = insn0 & 0x1F;
    uint32_t rn_br  = (insn1 >> 5) & 0x1F;
    if ((insn1 & 0xFFFFFC1F) != 0xD61F0000)
        return target;
    if (rt_ldr != rn_br)
        return target;

    /* Extract unsigned imm12 (scaled by 8 for 64-bit LDR) */
    uint32_t imm12 = (insn0 >> 10) & 0xFFF;
    uint64_t offset = (uint64_t)imm12 * 8;

    /* JNIEnvExt layout: [0]=JNINativeInterface*, [8]=self_ (Thread*)
     * We need Thread*, not JNIEnv* itself. */
    uint64_t thread = *(uint64_t*)((uint64_t)jni_env + 8);
    uint64_t resolved = *(uint64_t*)(thread + offset);

    hook_log("[art_router] resolve_art_trampoline: %p → LDR X%d,[X19,#%llu]; BR X%d → %llx",
             target, rt_ldr, (unsigned long long)offset, rn_br,
             (unsigned long long)resolved);

    return hook_normalize_code_ptr((void*)resolved);
}

/* ============================================================================
 * hook_install_art_router — inline hook with ART router thunk
 *
 * Similar to hook_install() but instead of a simple replacement, installs a
 * router thunk that scans g_art_router_table inline.
 * ============================================================================ */

void* hook_install_art_router(void* target, uint32_t quickcode_offset,
                               int stealth, void* jni_env,
                               void** out_hooked_target) {
    target = hook_normalize_code_ptr(target);

    if (!g_engine.initialized || !target) {
        return NULL;
    }

    /* Resolve tiny ART trampolines (LDR+BR 8 bytes) to actual target */
    void* resolved = resolve_art_trampoline(target, jni_env);
    if (resolved != target) {
        hook_log("[art_router] resolved %p → %p", target, resolved);
        target = resolved;
    }

    /* Report the actual hooked address back to the caller for cleanup */
    if (out_hooked_target) {
        *out_hooked_target = target;
    }

    pthread_mutex_lock(&g_engine.lock);

    /* Check if already hooked — return existing trampoline */
    HookEntry* existing = find_hook(target);
    if (existing) {
        void* trampoline = existing->trampoline;
        pthread_mutex_unlock(&g_engine.lock);
        return trampoline;
    }

    HookEntry* entry = setup_hook_entry(target);
    if (!entry) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Allocate thunk (router code — larger than default) */
    size_t art_thunk_alloc = 1024;
    if (!entry->thunk || entry->thunk_alloc < art_thunk_alloc) {
        entry->thunk = hook_alloc(art_thunk_alloc);
        entry->thunk_alloc = art_thunk_alloc;
    }
    if (!entry->thunk) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    if (build_trampoline(entry) < 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Generate router thunk — not_found path jumps to trampoline */
    size_t thunk_size = generate_art_router_thunk(
        entry->thunk, art_thunk_alloc,
        entry->trampoline, quickcode_offset);
    if (thunk_size == 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    /* Patch target to jump to router thunk */
    if (patch_target(target, entry->thunk, stealth, entry) != 0) {
        free_entry(entry);
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    finalize_hook(entry, entry->thunk, thunk_size);

    void* trampoline = entry->trampoline;
    pthread_mutex_unlock(&g_engine.lock);

    hook_log("[art_router] installed: target=%p, thunk=%p, trampoline=%p",
             target, entry->thunk, trampoline);

    return trampoline;
}

/* ============================================================================
 * hook_create_art_router_stub — standalone ART router (no inline patching)
 *
 * Creates a thunk that scans g_art_router_table for X0, and if not found,
 * jumps to fallback_target.  The caller writes the returned address into
 * ArtMethod.entry_point_ directly.
 * ============================================================================ */

void* hook_create_art_router_stub(uint64_t fallback_target,
                                   uint32_t quickcode_offset) {
    fallback_target = hook_normalize_code_u64(fallback_target);

    if (!g_engine.initialized || !fallback_target) {
        return NULL;
    }

    pthread_mutex_lock(&g_engine.lock);

    size_t stub_alloc = 1024;
    void* stub_mem = hook_alloc(stub_alloc);
    if (!stub_mem) {
        pthread_mutex_unlock(&g_engine.lock);
        return NULL;
    }

    Arm64Writer w;
    arm64_writer_init(&w, stub_mem, (uint64_t)stub_mem, stub_alloc);

    emit_thunk_activity_enter(&w);
    emit_art_router_prologue(&w);

    uint64_t lbl_found, lbl_not_found;
    emit_art_router_scan_loop(&w, &lbl_found, &lbl_not_found);
    emit_art_router_found_path(&w, lbl_found, quickcode_offset);

    /* === not_found path: jump to fallback === */
    emit_art_router_not_found_path(&w, lbl_not_found, fallback_target);

    arm64_writer_flush(&w);
    size_t stub_size = arm64_writer_offset(&w);
    arm64_writer_clear(&w);

    hook_flush_cache(stub_mem, stub_size);

    pthread_mutex_unlock(&g_engine.lock);

    hook_log("[art_router] stub created: %p (fallback=%llx, size=%zu)",
             stub_mem, (unsigned long long)fallback_target, stub_size);

    return stub_mem;
}
