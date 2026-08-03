#include "arm64_relocator_bridge.h"
#include "arm64_relocator.h"

int rf_arm64_relocator_analyze(uint64_t pc, uint32_t instruction, RfArm64RelocationInfo* output) {
    if (output == 0) {
        return -1;
    }

    Arm64InsnInfo info = arm64_relocator_analyze_insn(pc, instruction);
    output->kind = (uint32_t)info.type;
    output->target = info.target;
    output->pc_relative = info.is_pc_relative;
    output->condition = (int32_t)info.cond;
    output->reg = (int32_t)info.reg;
    output->bit = info.bit;
    output->dst_reg = (int32_t)info.dst_reg;
    output->is_signed = info.is_signed;
    output->fp_size = info.fp_size;
    return 0;
}

int rf_arm64_relocator_relocate_direct(
    uint64_t source_pc,
    uint64_t destination_pc,
    uint32_t instruction,
    uint32_t* relocated_instruction
) {
    if (relocated_instruction == 0) {
        return ARM64_RELOC_ERROR;
    }

    return (int)arm64_relocator_relocate_insn(
        source_pc,
        destination_pc,
        instruction,
        relocated_instruction
    );
}
