#ifndef RF_ARM64_RELOCATOR_BRIDGE_H
#define RF_ARM64_RELOCATOR_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t kind;
    uint64_t target;
    int32_t pc_relative;
    int32_t condition;
    int32_t reg;
    uint32_t bit;
    int32_t dst_reg;
    int32_t is_signed;
    int32_t fp_size;
} RfArm64RelocationInfo;

int rf_arm64_relocator_analyze(uint64_t pc, uint32_t instruction, RfArm64RelocationInfo* output);
int rf_arm64_relocator_relocate_direct(
    uint64_t source_pc,
    uint64_t destination_pc,
    uint32_t instruction,
    uint32_t* relocated_instruction
);

int rf_arm64_relocator_emit_fallback(
    uint64_t source_pc,
    uint64_t destination_pc,
    uint32_t instruction,
    uint64_t island_pc,
    uint32_t* emitted_instruction,
    uint8_t* island_output,
    size_t island_capacity,
    size_t* island_size
);

#endif
