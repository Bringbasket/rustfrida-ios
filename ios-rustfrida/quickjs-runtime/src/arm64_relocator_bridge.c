#include "arm64_relocator_bridge.h"
#include "arm64_relocator.h"
#include <limits.h>

static int rf_arm64_encode_b(uint64_t from, uint64_t to, uint32_t* output) {
    int64_t offset;
    int64_t immediate;

    if (output == 0 || from > INT64_MAX || to > INT64_MAX ||
        (from & 3) != 0 || (to & 3) != 0) {
        return -1;
    }
    offset = (int64_t)to - (int64_t)from;
    immediate = offset >> 2;
    if (immediate < -(1LL << 25) || immediate >= (1LL << 25)) {
        return -1;
    }
    *output = 0x14000000u | ((uint32_t)immediate & 0x03ffffffu);
    return 0;
}

static void rf_arm64_put_b_safe(Arm64Writer* writer, uint64_t target) {
    if (arm64_writer_put_b_imm(writer, target) != 0) {
        arm64_writer_put_branch_address_reg(writer, target, ARM64_REG_X16);
    }
}

static int rf_arm64_emit_trampoline(
    Arm64Writer* writer,
    const Arm64InsnInfo* info,
    uint32_t instruction,
    uint64_t return_address
) {
    uint64_t skip;
    Arm64Reg destination;

    switch (info->type) {
    case ARM64_INSN_B:
        arm64_writer_put_branch_address_reg(writer, info->target, ARM64_REG_X16);
        break;
    case ARM64_INSN_BL:
        arm64_writer_put_mov_reg_imm(writer, ARM64_REG_X30, return_address);
        arm64_writer_put_branch_address_reg(writer, info->target, ARM64_REG_X16);
        break;
    case ARM64_INSN_B_COND:
        skip = arm64_writer_new_label_id(writer);
        arm64_writer_put_b_cond_label(writer, (Arm64Cond)(info->cond ^ 1), skip);
        arm64_writer_put_branch_address_reg(writer, info->target, ARM64_REG_X16);
        arm64_writer_put_label(writer, skip);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ:
        skip = arm64_writer_new_label_id(writer);
        if (info->type == ARM64_INSN_CBZ) {
            arm64_writer_put_cbnz_reg_label(writer, info->reg, skip);
        } else {
            arm64_writer_put_cbz_reg_label(writer, info->reg, skip);
        }
        arm64_writer_put_branch_address_reg(writer, info->target, ARM64_REG_X16);
        arm64_writer_put_label(writer, skip);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ:
        skip = arm64_writer_new_label_id(writer);
        if (info->type == ARM64_INSN_TBZ) {
            arm64_writer_put_tbnz_reg_imm_label(writer, info->reg, info->bit, skip);
        } else {
            arm64_writer_put_tbz_reg_imm_label(writer, info->reg, info->bit, skip);
        }
        arm64_writer_put_branch_address_reg(writer, info->target, ARM64_REG_X16);
        arm64_writer_put_label(writer, skip);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_ADR:
    case ARM64_INSN_ADRP:
        arm64_writer_put_mov_reg_imm(writer, info->dst_reg, info->target);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_LDR_LITERAL:
        destination = info->dst_reg;
        arm64_writer_put_ldr_reg_address(writer, destination, info->target);
        if (((instruction >> 30) & 3) == 0) {
            arm64_writer_put_ldr_reg_reg_offset(writer, (Arm64Reg)(destination + 32), destination, 0);
        } else {
            arm64_writer_put_ldr_reg_reg_offset(writer, destination, destination, 0);
        }
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_LDRSW_LITERAL:
        destination = info->dst_reg;
        arm64_writer_put_ldr_reg_address(writer, destination, info->target);
        arm64_writer_put_ldrsw_reg_reg_offset(writer, destination, destination, 0);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_LDR_LITERAL_FP:
        arm64_writer_put_push_reg_reg(writer, ARM64_REG_X16, ARM64_REG_X17);
        arm64_writer_put_ldr_reg_address(writer, ARM64_REG_X16, info->target);
        arm64_writer_put_ldr_fp_reg_reg(writer, (uint32_t)info->dst_reg, ARM64_REG_X16, info->fp_size);
        arm64_writer_put_pop_reg_reg(writer, ARM64_REG_X16, ARM64_REG_X17);
        rf_arm64_put_b_safe(writer, return_address);
        break;
    case ARM64_INSN_PRFM_LITERAL:
        rf_arm64_put_b_safe(writer, return_address);
        break;
    default:
        return -1;
    }

    return 0;
}

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

int rf_arm64_relocator_emit_fallback(
    uint64_t source_pc,
    uint64_t destination_pc,
    uint32_t instruction,
    uint64_t island_pc,
    uint32_t* emitted_instruction,
    uint8_t* island_output,
    size_t island_capacity,
    size_t* island_size
) {
    Arm64InsnInfo info;
    Arm64Writer writer;
    uint32_t direct_output;
    size_t used;
    int result;

    if (emitted_instruction == 0 || island_output == 0 || island_size == 0 ||
        island_capacity < 64 || (source_pc & 3) != 0 ||
        (destination_pc & 3) != 0 || (island_pc & 3) != 0 ||
        source_pc > INT64_MAX - 4 || destination_pc > INT64_MAX - 4 ||
        island_pc > INT64_MAX) {
        return -1;
    }
    if (arm64_relocator_relocate_insn(source_pc, destination_pc, instruction, &direct_output) !=
        ARM64_RELOC_OUT_OF_RANGE) {
        return -2;
    }
    if (rf_arm64_encode_b(destination_pc, island_pc, emitted_instruction) != 0) {
        return -3;
    }

    info = arm64_relocator_analyze_insn(source_pc, instruction);
    arm64_writer_init(&writer, island_output, island_pc, island_capacity);
    result = rf_arm64_emit_trampoline(
        &writer,
        &info,
        instruction,
        destination_pc + 4
    );
    if (result == 0 && arm64_writer_flush(&writer) != 0) {
        result = -4;
    }
    used = arm64_writer_offset(&writer);
    arm64_writer_clear(&writer);
    if (result != 0 || used == 0 || used > island_capacity || (used & 3) != 0) {
        return result != 0 ? result : -5;
    }

    *island_size = used;
    return 0;
}
