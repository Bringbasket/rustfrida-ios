/*
 * hook_engine_mem.c - Memory pool management, XOM-safe read, wxshadow, cache flush
 *
 * Contains: pool permission management, entry allocation/free, wxshadow patching,
 * write_jump_back, hook_write_jump, hook_alloc, hook_relocate_instructions,
 * hook_flush_cache.
 */

#include "hook_engine_internal.h"

/* --- Page permission helpers --- */

/*
 * Check if the page containing addr has read permission.
 * Parses /proc/self/maps to find the VMA and check perms[0] == 'r'.
 * Returns 1 if readable, 0 otherwise.
 */
int page_has_read_perm(uintptr_t addr) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int readable = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                readable = (perms[0] == 'r');
                break;
            }
        }
    }
    fclose(f);
    return readable;
}

/*
 * Safely read bytes from a target address.
 *
 * Strategy:
 *   1. Check VMA permission — if readable, direct memcpy.
 *   2. Otherwise mprotect to add read bit, memcpy, then restore.
 *
 * Returns 0 on success, -1 on failure.
 */
int read_target_safe(void* target, void* buf, size_t len) {
    /* If page is already readable, just memcpy */
    if (page_has_read_perm((uintptr_t)target)) {
        memcpy(buf, target, len);
        return 0;
    }

    /* Page not readable (XOM / --x) — mprotect to add read, then memcpy */
    uintptr_t page_start = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) == 0) {
        memcpy(buf, target, len);
        /* restore to original r-x (mprotect already set it to r-x) */
        return 0;
    }

    hook_log("read_target_safe: mprotect failed errno=%d", errno);
    return -1;
}

/* --- Pool permission management --- */

/*
 * Restore a target code page to R-X after patching.
 * Try 0x2000 (two pages) first in case the hook spans a page boundary.
 * Fall back to two separate 0x1000 calls when the range crosses a VMA
 * boundary (mprotect returns EINVAL for the 2-page span but succeeds per page).
 */
void restore_page_rx(uintptr_t page_start) {
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_EXEC) != 0) {
        mprotect((void*)page_start, 0x1000, PROT_READ | PROT_EXEC);
        mprotect((void*)(page_start + 0x1000), 0x1000, PROT_READ | PROT_EXEC);
    }
}

/* --- Entry free list management --- */

HookEntry* alloc_entry(void) {
    HookEntry* entry = NULL;

    if (g_engine.free_list) {
        /* Reuse from free list, preserving pool memory allocations */
        entry = g_engine.free_list;
        g_engine.free_list = entry->next;

        void* saved_trampoline = entry->trampoline;
        size_t saved_trampoline_alloc = entry->trampoline_alloc;
        void* saved_thunk = entry->thunk;
        size_t saved_thunk_alloc = entry->thunk_alloc;

        memset(entry, 0, sizeof(HookEntry));

        entry->trampoline = saved_trampoline;
        entry->trampoline_alloc = saved_trampoline_alloc;
        entry->thunk = saved_thunk;
        entry->thunk_alloc = saved_thunk_alloc;
    } else {
        entry = (HookEntry*)hook_alloc(sizeof(HookEntry));
        if (entry) memset(entry, 0, sizeof(HookEntry));
    }

    return entry;
}

void free_entry(HookEntry* entry) {
    entry->next = g_engine.free_list;
    g_engine.free_list = entry;
}

/* --- Cache flush --- */

void hook_flush_cache(void* start, size_t size) {
    __builtin___clear_cache((char*)start, (char*)start + size);
}

/* --- wxshadow (two-step shadow page patching) --- */

/*
 * Find the VMA containing addr by parsing /proc/self/maps.
 * Returns the VMA start in *vma_start and size in *vma_size.
 * Only matches VMAs with the given permission prefix (e.g., "r-x").
 * Returns 0 on success, -1 if not found.
 */
static int find_containing_vma(uintptr_t addr, uintptr_t* vma_start, size_t* vma_size) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            if (addr >= start && addr < end) {
                *vma_start = start;
                *vma_size = end - start;
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/*
 * Split a PMD (2MB section) mapping into PTE-level pages without
 * causing a VMA split in /proc/self/maps.
 *
 * Strategy: mprotect the ENTIRE containing VMA to rwx, write one byte
 * (triggers COW on the target page, splitting the PMD at kernel level),
 * then restore the entire VMA to its original permissions.  Because we
 * operate on the full VMA boundary, the kernel never splits the VMA
 * into sub-regions — the VMA count in /proc/self/maps stays the same.
 *
 * Returns 0 on success, -1 on failure.
 */
static int pmd_split_cow(void* addr) {
    uintptr_t vma_start = 0;
    size_t vma_size = 0;

    if (find_containing_vma((uintptr_t)addr, &vma_start, &vma_size) != 0) {
        hook_log("pmd_split_cow: VMA not found for addr=%p", addr);
        return -1;
    }

    hook_log("pmd_split_cow: VMA=%p-%p (size=%zu) for addr=%p",
             (void*)vma_start, (void*)(vma_start + vma_size), vma_size, addr);

    /* mprotect the entire VMA to rwx — no VMA split */
    if (mprotect((void*)vma_start, vma_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        hook_log("pmd_split_cow: mprotect(rwx) failed errno=%d", errno);
        return -1;
    }

    /* Write original byte back to trigger COW on the target page.
     * This creates a private anonymous page, splitting the PMD. */
    *(volatile uint8_t*)addr = *(volatile uint8_t*)addr;

    /* Restore entire VMA to r-x — no VMA split */
    mprotect((void*)vma_start, vma_size, PROT_READ | PROT_EXEC);

    return 0;
}

/*
 * Stealth-patch target address using wxshadow shadow pages:
 *   PATCH — one-step: create shadow + write buf + activate (--x)
 *
 * prctl(PR_WXSHADOW_PATCH, pid, addr, buf, len)
 * Tries pid=0 first, then getpid() as fallback.
 * Returns 0 on success, HOOK_ERROR_WXSHADOW_FAILED on failure.
 */
int wxshadow_patch(void* addr, const void* buf, size_t len) {
    int ret;

    ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
    }

    if (ret != 0) {
        /* PATCH failed — likely 2MB section (PMD) mapping.
         * wxshadow only supports 4KB PTE-mapped pages.
         *
         * Split the PMD by triggering COW on the target page.  We must
         * mprotect the ENTIRE containing VMA (not just the target page)
         * to avoid creating a VMA split visible in /proc/self/maps.
         * V-OS detection scans /proc/self/maps for unexpected VMA splits
         * in libart.so — mprotecting a sub-range would fragment the VMA. */
        hook_log("wxshadow PATCH failed (errno=%d), trying PMD split + COW for addr=%p", errno, addr);

        if (pmd_split_cow(addr) == 0) {
            ret = prctl(PR_WXSHADOW_PATCH, 0, (uintptr_t)addr, (uintptr_t)buf, len);
            if (ret != 0) {
                ret = prctl(PR_WXSHADOW_PATCH, getpid(), (uintptr_t)addr, (uintptr_t)buf, len);
            }
        }

        if (ret != 0) {
            hook_log("wxshadow PATCH failed after COW: addr=%p errno=%d", addr, errno);
            return HOOK_ERROR_WXSHADOW_FAILED;
        }
        hook_log("wxshadow PATCH succeeded after PMD split: addr=%p", addr);
    }

    hook_log("wxshadow stealth patch OK: addr=%p len=%zu", addr, len);
    return 0;
}

/*
 * Release a wxshadow patch by its exact patch start address.
 * The supplied address must match the addr argument previously passed to PATCH.
 */
int wxshadow_release(void* addr) {
    int ret = prctl(PR_WXSHADOW_RELEASE, 0, (uintptr_t)addr, 0, 0);
    if (ret != 0) {
        ret = prctl(PR_WXSHADOW_RELEASE, getpid(), (uintptr_t)addr, 0, 0);
    }
    if (ret != 0) {
        hook_log("wxshadow_release: failed for addr=%p (errno=%d)", addr, errno);
        return HOOK_ERROR_WXSHADOW_FAILED;
    }
    return 0;
}

/* --- Jump writing and allocation --- */

/* BRK 填充 + 清理 writer，返回写入字节数 */
static int finalize_jump_writer(Arm64Writer* w) {
    while (arm64_writer_offset(w) < MIN_HOOK_SIZE && arm64_writer_can_write(w, 4)) {
        arm64_writer_put_brk_imm(w, 0xFFFF);
    }
    int bytes_written = (int)arm64_writer_offset(w);
    arm64_writer_clear(w);
    return bytes_written;
}

/*
 * Write a trampoline jump-back using a dynamically chosen scratch register.
 *
 * Analyzes which GPRs are written by the relocated instructions (via
 * written_regs bitmask) and picks a scratch register that won't be
 * clobbered:
 *   - Prefer X17 (IP1, intra-procedure-call scratch)
 *   - Fall back to X16 (IP0) if X17 is written
 *   - If both are written, still use X17 (extremely rare edge case)
 */
int write_jump_back(void* dst, void* target, uint32_t written_regs) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    target = hook_normalize_code_ptr(target);

    Arm64Reg scratch;
    if (!(written_regs & (1u << 17))) {
        scratch = ARM64_REG_X17;    /* Prefer X17 */
    } else if (!(written_regs & (1u << 16))) {
        scratch = ARM64_REG_X16;    /* Fall back to X16 */
    } else {
        scratch = ARM64_REG_X17;    /* Both written — use X17, log warning */
        hook_log("[hook] WARNING: both X16 and X17 written by relocated code, "
                 "X17 may be clobbered");
    }

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_mov_reg_imm(&w, scratch, hook_normalize_code_u64((uint64_t)(uintptr_t)target));
    arm64_writer_put_br_reg(&w, scratch);

    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    return finalize_jump_writer(&w);
}

/* Write an absolute jump using arm64_writer (MOVZ/MOVK + BR sequence) */
int hook_write_jump(void* dst, void* target) {
    if (!dst || !target) {
        return HOOK_ERROR_INVALID_PARAM;
    }

    target = hook_normalize_code_ptr(target);

    Arm64Writer w;
    arm64_writer_init(&w, dst, (uint64_t)dst, MIN_HOOK_SIZE);
    arm64_writer_put_branch_address(&w, hook_normalize_code_u64((uint64_t)(uintptr_t)target));

    /* Check if branch_address exceeded our buffer */
    if (arm64_writer_offset(&w) > MIN_HOOK_SIZE) {
        arm64_writer_clear(&w);
        return HOOK_ERROR_BUFFER_TOO_SMALL;
    }

    return finalize_jump_writer(&w);
}

/* Allocate from executable memory pool */
void* hook_alloc(size_t size) {
    if (!g_engine.initialized) return NULL;

    /* Align to 8 bytes */
    size = (size + 7) & ~7;

    if (g_engine.exec_mem_used + size > g_engine.exec_mem_size) {
        return NULL;
    }

    void* ptr = (uint8_t*)g_engine.exec_mem + g_engine.exec_mem_used;
    g_engine.exec_mem_used += size;
    return ptr;
}

/* --- Instruction relocation --- */

/* Relocate instructions from a pre-read buffer (src_buf) to dst, using
 * src_pc as the original PC for PC-relative fixups.
 *
 * Separating src_buf from src_pc lets the caller read the original bytes
 * safely (e.g., via /proc/self/mem to bypass XOM) and then pass that buffer
 * here, while still computing correct relocations against the real address.
 *
 * Within-region branch fix: before the write loop we pre-create one writer
 * label per source instruction and record them in the relocator's region_labels
 * table.  Just before writing each instruction we place its label at the current
 * writer PC.  This allows arm64_relocator_write_one() to emit label-based
 * branches (rather than absolute branches to the now-overwritten original code)
 * for any PC-relative branch whose target lies inside [src_pc, src_pc+min_bytes). */
size_t hook_relocate_instructions(const void* src_buf, uint64_t src_pc, void* dst, size_t min_bytes, uint32_t* out_written_regs) {
    Arm64Writer w;
    Arm64Relocator r;

    arm64_writer_init(&w, dst, (uint64_t)dst, 256);
    arm64_relocator_init(&r, src_buf, src_pc, &w);

    /* Pre-create one label per source instruction in the hook region. */
    int n = (int)(min_bytes / INSN_SIZE);
    if (n > ARM64_RELOC_MAX_REGION) n = ARM64_RELOC_MAX_REGION;
    r.region_end = src_pc + min_bytes;
    r.region_label_count = n;
    for (int i = 0; i < n; i++) {
        r.region_labels[i].src_pc = src_pc + (uint64_t)(i * INSN_SIZE);
        r.region_labels[i].label_id = arm64_writer_new_label_id(&w);
    }

    size_t src_offset = 0;
    int insn_idx = 0;
    while (src_offset < min_bytes) {
        /* Place this instruction's label at the current write position BEFORE
         * emitting the instruction so that backward references work immediately
         * and forward references are resolved during flush. */
        if (insn_idx < n)
            arm64_writer_put_label(&w, r.region_labels[insn_idx].label_id);

        if (arm64_relocator_read_one(&r) == 0) break;
        arm64_relocator_write_one(&r);
        src_offset += INSN_SIZE;
        insn_idx++;
    }

    /* Place labels for any instructions that were not reached (e.g. early EOI)
     * so that forward label references created before the loop exits are always
     * resolved to a valid (if imprecise) position. */
    for (int i = insn_idx; i < n; i++)
        arm64_writer_put_label(&w, r.region_labels[i].label_id);

    /* Flush pending label references (CBZ forward refs etc.) */
    arm64_writer_flush(&w);

    size_t written = arm64_writer_offset(&w);

    if (out_written_regs)
        *out_written_regs = r.written_regs;

    arm64_writer_clear(&w);
    arm64_relocator_clear(&r);

    return written;
}

/* --- Hook installation helpers --- */

HookEntry* setup_hook_entry(void* target) {
    /* Caller must hold g_engine.lock */

    target = hook_normalize_code_ptr(target);

    /* Check if already hooked */
    if (find_hook(target)) {
        return NULL;
    }

    /* Allocate hook entry (reuse from free list if possible) */
    HookEntry* entry = alloc_entry();
    if (!entry) {
        return NULL;
    }

    entry->target = target;

    /* Allocate trampoline space (reuse if available and large enough) */
    if (!entry->trampoline || entry->trampoline_alloc < TRAMPOLINE_ALLOC_SIZE) {
        entry->trampoline = hook_alloc(TRAMPOLINE_ALLOC_SIZE);
        entry->trampoline_alloc = TRAMPOLINE_ALLOC_SIZE;
    }
    if (!entry->trampoline) {
        free_entry(entry);
        return NULL;
    }

    /* Save original bytes — use XOM-safe read */
    if (read_target_safe(target, entry->original_bytes, MIN_HOOK_SIZE) != 0) {
        hook_log("setup_hook_entry: target %p is not readable, aborting", target);
        free_entry(entry);
        return NULL;
    }
    entry->original_size = MIN_HOOK_SIZE;

    return entry;
}

int build_trampoline(HookEntry* entry) {
    entry->target = hook_normalize_code_ptr(entry->target);

    /* Relocate original instructions to trampoline */
    uint32_t written_regs = 0;
    size_t relocated_size = hook_relocate_instructions(
        entry->original_bytes, (uint64_t)entry->target,
        entry->trampoline, MIN_HOOK_SIZE, &written_regs);

    /* Write jump back to original code after the relocated instructions */
    void* jump_back_target = (uint8_t*)entry->target + MIN_HOOK_SIZE;
    int jump_result = write_jump_back(
        (uint8_t*)entry->trampoline + relocated_size,
        jump_back_target, written_regs);

    return jump_result;
}

int patch_target(void* target, void* jump_dest, int stealth, HookEntry* entry) {
    target = hook_normalize_code_ptr(target);
    jump_dest = hook_normalize_code_ptr(jump_dest);

    int jump_result;

    if (stealth) {
        /* Stealth mode: wxshadow one-step PATCH.
         * Kernel creates shadow page, copies buf, activates (--x) in one prctl.
         * If wxshadow fails, fall through to mprotect. */
        uint8_t jump_buf[MIN_HOOK_SIZE];
        jump_result = hook_write_jump(jump_buf, jump_dest);
        if (jump_result < 0) {
            return jump_result;
        }
        if (wxshadow_patch(target, jump_buf, jump_result) == 0) {
            entry->stealth = 1;
            return 0;
        }
        hook_log("patch_target: wxshadow failed, falling back to mprotect");
    }

    /* Normal mode (or wxshadow fallback): mprotect + direct write */
    uintptr_t page_start = (uintptr_t)target & ~0xFFF;
    if (mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return HOOK_ERROR_MPROTECT_FAILED;
    }
    jump_result = hook_write_jump(target, jump_dest);
    if (jump_result < 0) {
        restore_page_rx(page_start);
        return jump_result;
    }
    entry->stealth = 0;
    restore_page_rx(page_start);

    return 0;
}

void finalize_hook(HookEntry* entry, void* thunk, size_t thunk_size) {
    /* Flush caches */
    if (!entry->stealth) {
        hook_flush_cache(entry->target, MIN_HOOK_SIZE);
    }
    hook_flush_cache(entry->trampoline, TRAMPOLINE_ALLOC_SIZE);
    if (thunk && thunk_size > 0) {
        hook_flush_cache(thunk, thunk_size);
    }

    /* Add to hook list */
    entry->next = g_engine.hooks;
    g_engine.hooks = entry;
}
