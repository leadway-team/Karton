#include "karton.h"

#define GUEST_TO_HOST(builder, guest_val) \
    LLVMBuildAdd((builder), \
        LLVMBuildSub((builder), (guest_val), \
            LLVMConstInt(i64, base_vaddr, 0), "g2h_sub"), \
        LLVMConstInt(i64, (uint64_t)mem_image, 0), "g2h_add")

GElf_Phdr* find_phdr(ZyanUSize phnum, uint64_t addr) {
    for (ZyanUSize i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && addr >= phdrs[i].p_vaddr && addr < (phdrs[i].p_vaddr + phdrs[i].p_memsz)) {
            return &phdrs[i];
        }
    }
    return ZYAN_NULL;
}

void* access_quest(uint64_t guest_addr) {
    return (void*)(mem_image + guest_addr - base_vaddr);
}

LLVMValueRef guest_to_host_dynamic(LLVMBuilderRef builder, LLVMValueRef addr) {
    LLVMValueRef lo = LLVMConstInt(i64, base_vaddr, 0);
    LLVMValueRef hi = LLVMConstInt(i64, base_vaddr + image_size, 0);

    LLVMValueRef in_range = LLVMBuildAnd(builder,
        LLVMBuildICmp(builder, LLVMIntUGE, addr, lo, "above_lo"),
        LLVMBuildICmp(builder, LLVMIntULT, addr, hi, "below_hi"),
        "in_range");

    return LLVMBuildSelect(builder, in_range,
        GUEST_TO_HOST(builder, addr),
        addr,
        "host_addr");
}

LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx) {
    int num = 3; LLVMValueRef indices[3];
    if (reg_idx == 16) {
        indices[0] = LLVMConstInt(LLVMInt64Type(), 0, 0);
        indices[1] = LLVMConstInt(LLVMInt64Type(), 1, 0);
        num = 2;
    } else {
        indices[0] = LLVMConstInt(LLVMInt64Type(), 0, 0);
        indices[1] = LLVMConstInt(LLVMInt64Type(), 0, 0);
        indices[2] = LLVMConstInt(LLVMInt64Type(), reg_idx, 0);
    }
    return LLVMBuildInBoundsGEP2(builder, cpu_type, cpu_ptr, indices, num, "reg_ptr");
}

LLVMValueRef get_flag_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int field_idx) {
    LLVMValueRef indices[] = {
        LLVMConstInt(LLVMInt64Type(), 0, 0),
        LLVMConstInt(LLVMInt32Type(), field_idx, 0)
    };
    return LLVMBuildInBoundsGEP2(builder, cpu_type, cpu_ptr, indices, 2, "flag_ptr");
}

LLVMValueRef get_xmm_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx, int half) {
    LLVMValueRef indices[] = {
        LLVMConstInt(i64, 0, 0),
        LLVMConstInt(LLVMInt32Type(), 9, 0),
        LLVMConstInt(i64, reg_idx, 0),
        LLVMConstInt(i64, half, 0)
    };
    return LLVMBuildInBoundsGEP2(builder, cpu_type, cpu_ptr, indices, 4, "xmm_ptr");
}

LLVMValueRef get_fs_base_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type) {
    LLVMValueRef indices[] = {
        LLVMConstInt(i64, 0, 0),
        LLVMConstInt(LLVMInt32Type(), 8, 0)
    };
    return LLVMBuildInBoundsGEP2(builder, cpu_type, cpu_ptr, indices, 2, "fs_base_ptr");
}

int get_register_index(ZydisRegister reg) {
    if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_RDI)
        return reg - ZYDIS_REGISTER_RAX;
    if (reg >= ZYDIS_REGISTER_R8  && reg <= ZYDIS_REGISTER_R15)
        return 8 + (reg - ZYDIS_REGISTER_R8);
    if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_EDI)
        return reg - ZYDIS_REGISTER_EAX;
    if (reg >= ZYDIS_REGISTER_R8D && reg <= ZYDIS_REGISTER_R15D)
        return 8 + (reg - ZYDIS_REGISTER_R8D);
    if (reg >= ZYDIS_REGISTER_AX  && reg <= ZYDIS_REGISTER_DI)
        return reg - ZYDIS_REGISTER_AX;
    if (reg >= ZYDIS_REGISTER_R8W && reg <= ZYDIS_REGISTER_R15W)
        return 8 + (reg - ZYDIS_REGISTER_R8W);
    if (reg >= ZYDIS_REGISTER_AL  && reg <= ZYDIS_REGISTER_DIL)
        return reg - ZYDIS_REGISTER_AL;
    if (reg >= ZYDIS_REGISTER_R8B && reg <= ZYDIS_REGISTER_R15B)
        return 8 + (reg - ZYDIS_REGISTER_R8B);
    if (reg >= ZYDIS_REGISTER_AH  && reg <= ZYDIS_REGISTER_BH)
        return reg - ZYDIS_REGISTER_AH;
    if (reg == ZYDIS_REGISTER_EIP || reg == ZYDIS_REGISTER_RIP)
        return 16;
    return -1;
}

int get_xmm_index(ZydisRegister reg) {
    if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15)
        return reg - ZYDIS_REGISTER_XMM0;
    return -1;
}

LLVMValueRef get_xmm_lo(JITCtx *jcontext, int xmm_idx) {
    LLVMValueRef ptr = get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                                    jcontext->cpu_struct_type, xmm_idx, 0);
    return LLVMBuildLoad2(jcontext->builder, i64, ptr, "xmm_lo");
}

void set_xmm_lo(JITCtx *jcontext, int xmm_idx, LLVMValueRef val) {
    LLVMBuildStore(jcontext->builder, val,
        get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                    jcontext->cpu_struct_type, xmm_idx, 0));
    LLVMBuildStore(jcontext->builder, LLVMConstInt(i64, 0, 0),
        get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                    jcontext->cpu_struct_type, xmm_idx, 1));
}

void set_xmm_lo_without_zero(JITCtx *jcontext, int xmm_idx, LLVMValueRef val) {
    LLVMBuildStore(jcontext->builder, val,
        get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                    jcontext->cpu_struct_type, xmm_idx, 0));
}

LLVMValueRef get_xmm_hi(JITCtx *jcontext, int xmm_idx) {
    LLVMValueRef ptr = get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                                    jcontext->cpu_struct_type, xmm_idx, 1);
    return LLVMBuildLoad2(jcontext->builder, i64, ptr, "xmm_hi");
}

void set_xmm_hi(JITCtx *jcontext, int xmm_idx, LLVMValueRef val) {
    LLVMBuildStore(jcontext->builder, val,
        get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                    jcontext->cpu_struct_type, xmm_idx, 1));
}

LLVMValueRef get_jump_target(JITCtx *jcontext, ZydisCtx *zcontext, int64_t runtime_address, ZyanUSize phnum) {
    ZydisDecodedOperand *op = &zcontext->operands[0];
    
    if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t new_addr;
        ZydisCalcAbsoluteAddress(&zcontext->instruction, op, runtime_address, &new_addr);
        return LLVMConstInt(i64, new_addr, 0);
    } else {
        return get_operand_value(jcontext, zcontext, op, runtime_address, phnum);
    }
}

LLVMValueRef compute_mem_addr(JITCtx *jcontext, ZydisDecodedOperand *operand, ZydisDecodedInstruction instruction, int64_t runtime_address) {
    LLVMValueRef addr = LLVMConstInt(i64, 0, 0);
    
    if (operand->mem.base != ZYDIS_REGISTER_NONE &&
        operand->mem.base != ZYDIS_REGISTER_RIP) {
        int base_idx = get_register_index(operand->mem.base);
        LLVMValueRef base_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, base_idx);
        LLVMValueRef base_val = LLVMBuildLoad2(jcontext->builder, i64, base_ptr, "mem_base");
        addr = LLVMBuildAdd(jcontext->builder, addr, base_val, "addr_base");
    }
    
    if (operand->mem.base == ZYDIS_REGISTER_RIP) {
        uint64_t rip_target;
        ZydisCalcAbsoluteAddress(&instruction, operand, runtime_address, &rip_target);
        return LLVMConstInt(i64, rip_target, 0);
    }
    
    if (operand->mem.segment == ZYDIS_REGISTER_FS) {
        LLVMValueRef fs_ptr = get_fs_base_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type);
        LLVMValueRef fs_val = LLVMBuildLoad2(jcontext->builder, i64, fs_ptr, "fs_base");
        addr = LLVMBuildAdd(jcontext->builder, addr, fs_val, "fs_addr");
    }
    
    if (operand->mem.index != ZYDIS_REGISTER_NONE) {
        int index_idx = get_register_index(operand->mem.index);
        LLVMValueRef index_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, index_idx);
        LLVMValueRef index_val = LLVMBuildLoad2(jcontext->builder, i64, index_ptr, "mem_index");
        if (operand->mem.scale > 1) {
            index_val = LLVMBuildMul(jcontext->builder, index_val,
                LLVMConstInt(i64, operand->mem.scale, 0), "mem_scaled");
        }
        addr = LLVMBuildAdd(jcontext->builder, addr, index_val, "addr_indexed");
    }
    
    if (operand->mem.disp.value != 0) {
        addr = LLVMBuildAdd(jcontext->builder, addr,
            LLVMConstInt(i64, (uint64_t)operand->mem.disp.value, 0), "addr_disp");
    }
    
    return addr;
}

LLVMValueRef get_operand_value(JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address, ZyanUSize phnum) {
    switch (operand->type) {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
            return LLVMConstInt(i64, operand->imm.value.s, 0);
        }
        
        case ZYDIS_OPERAND_TYPE_MEMORY: {
            LLVMValueRef addr = compute_mem_addr(jcontext, operand, zcontext->instruction, runtime_address);
            
            LLVMTypeRef mem_type;
            switch (operand->size) {
                case 8:  mem_type = i8;              break;
                case 16: mem_type = LLVMInt16Type(); break;
                case 32: mem_type = LLVMInt32Type(); break;
                default: mem_type = i64;             break;
            }
            
            LLVMValueRef host_addr = guest_to_host_dynamic(jcontext->builder, addr);
            LLVMValueRef ptr = LLVMBuildIntToPtr(jcontext->builder, host_addr,
                                   LLVMPointerType(mem_type, 0), "mem_ptr");
            LLVMValueRef val = LLVMBuildLoad2(jcontext->builder, mem_type, ptr, "mem_val");
            
            return (mem_type != i64)
                ? LLVMBuildZExt(jcontext->builder, val, i64, "zext")
                : val;
        }
        
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int reg_idx = get_register_index(operand->reg.value);
            if (reg_idx < 0) return LLVMConstInt(i64, 0, 0);
            
            LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr,
                                               jcontext->cpu_struct_type, reg_idx);
            LLVMValueRef full = LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "reg_val");
            
            switch (operand->size) {
                case 8: {
                    int is_high = (operand->reg.value >= ZYDIS_REGISTER_AH &&
                                   operand->reg.value <= ZYDIS_REGISTER_BH);
                    if (is_high) {
                        LLVMValueRef shifted = LLVMBuildLShr(jcontext->builder, full,
                            LLVMConstInt(i64, 8, 0), "shr8");
                        return LLVMBuildAnd(jcontext->builder, shifted,
                            LLVMConstInt(i64, 0xFF, 0), "ah_mask");
                    }
                    return LLVMBuildAnd(jcontext->builder, full,
                        LLVMConstInt(i64, 0xFF, 0), "al_mask");
                }
                case 16:
                    return LLVMBuildAnd(jcontext->builder, full,
                        LLVMConstInt(i64, 0xFFFF, 0), "ax_mask");
                case 32: {
                    LLVMValueRef t = LLVMBuildTrunc(jcontext->builder, full, LLVMInt32Type(), "trunc32");
                    return LLVMBuildZExt(jcontext->builder, t, i64, "zext64");
                }
                default:
                    return full;
            }
        }
        
        default:
            return NULL;
    }
}

void set_operand_value(LLVMValueRef value, JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address) {
    switch (operand->type) {
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int reg_idx = get_register_index(operand->reg.value);
            if (reg_idx < 0) break;
            
            LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr,
                                               jcontext->cpu_struct_type, reg_idx);
            LLVMValueRef store_val;
            
            switch (operand->size) {
                case 8: {
                    LLVMValueRef old_val = LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "old_reg");
                    int is_high = (operand->reg.value >= ZYDIS_REGISTER_AH &&
                                   operand->reg.value <= ZYDIS_REGISTER_BH);
                    uint64_t shift = is_high ? 8 : 0;
                    uint64_t mask  = ~(0xFFULL << shift);
                    LLVMValueRef byte_val = LLVMBuildAnd(jcontext->builder, value,
                        LLVMConstInt(i64, 0xFF, 0), "byte_mask");
                    LLVMValueRef shifted  = LLVMBuildShl(jcontext->builder, byte_val,
                        LLVMConstInt(i64, shift, 0), "byte_shift");
                    LLVMValueRef cleared  = LLVMBuildAnd(jcontext->builder, old_val,
                        LLVMConstInt(i64, mask, 0), "clear_byte");
                    store_val = LLVMBuildOr(jcontext->builder, cleared, shifted, "merge_byte");
                    break;
                }
                case 16: {
                    LLVMValueRef old_val = LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "old_reg");
                    LLVMValueRef word_val = LLVMBuildAnd(jcontext->builder, value,
                        LLVMConstInt(i64, 0xFFFF, 0), "word_mask");
                    LLVMValueRef cleared  = LLVMBuildAnd(jcontext->builder, old_val,
                        LLVMConstInt(i64, ~0xFFFFULL, 0), "clear_word");
                    store_val = LLVMBuildOr(jcontext->builder, cleared, word_val, "merge_word");
                    break;
                }
                case 32: {
                    LLVMValueRef t = LLVMBuildTrunc(jcontext->builder, value, LLVMInt32Type(), "trunc32");
                    store_val = LLVMBuildZExt(jcontext->builder, t, i64, "zext64");
                    break;
                }
                default:
                    store_val = value;
                    break;
            }
            
            LLVMBuildStore(jcontext->builder, store_val, reg_ptr);
            break;
        }
        
        case ZYDIS_OPERAND_TYPE_MEMORY: {
            LLVMValueRef addr = compute_mem_addr(jcontext, operand, zcontext->instruction, runtime_address);
            
            LLVMTypeRef mem_type;
            switch (operand->size) {
                case 8:  mem_type = i8;              break;
                case 16: mem_type = LLVMInt16Type(); break;
                case 32: mem_type = LLVMInt32Type(); break;
                default: mem_type = i64;             break;
            }
            
            LLVMValueRef store_val = (mem_type != i64)
                ? LLVMBuildTrunc(jcontext->builder, value, mem_type, "trunc")
                : value;
            
            LLVMValueRef host_addr = guest_to_host_dynamic(jcontext->builder, addr);
            LLVMValueRef ptr = LLVMBuildIntToPtr(jcontext->builder, host_addr,
                                   LLVMPointerType(mem_type, 0), "mem_ptr");
            LLVMBuildStore(jcontext->builder, store_val, ptr);
            break;
        }
        
        default:
            break;
    }
}

void gen_ir(GElf_Phdr *phdr, ZyanUSize phnum, ZydisCtx *zcontext, JITCtx *jcontext) {
    ZyanU64 offset = 0;
    ZyanU64 runtime_address = cpu.rip;
    
    while (offset < phdr->p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zcontext->decoder, (ZyanU8*)access_quest(runtime_address), 
                                                                          phdr->p_filesz, &zcontext->instruction, zcontext->operands))) {
        #ifdef DEBUG
        printf("%016" PRIX64 "  ", runtime_address);
        char buffer[256];
        ZydisFormatterFormatInstruction(&zcontext->formatter, &zcontext->instruction, zcontext->operands, zcontext->instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
        puts(buffer);
        #endif
        
        LLVMValueRef value;
        
        if (zcontext->instruction.operand_count_visible == 1) {
            value = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
        } else if (zcontext->instruction.operand_count_visible >= 2) {
            value = get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
        }
        
        switch (zcontext->instruction.mnemonic) {
            case ZYDIS_MNEMONIC_NOP:
            case ZYDIS_MNEMONIC_ENDBR64: {
                break;
            }
            
            case ZYDIS_MNEMONIC_JMP: {
                LLVMValueRef new_addr = get_jump_target(jcontext, zcontext, runtime_address, phnum);
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_addr, jcontext, zcontext, &fake_operand, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JZ: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, zf, LLVMConstInt(i8, 0, 0), "je_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "je_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JS: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef sf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3), "sf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, sf, LLVMConstInt(i8, 0, 0), "js_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "js_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz;
                break;
            }
            
            case ZYDIS_MNEMONIC_JNZ: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, zf, LLVMConstInt(i8, 0, 0), "jnz_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "jnz_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JL: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef sf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3), "sf");
                LLVMValueRef of = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5), "of");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, sf, of, "jl_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "jl_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JBE: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef cf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4), "cf");
                LLVMValueRef cond = LLVMBuildOr(jcontext->builder, 
                              LLVMBuildICmp(jcontext->builder, LLVMIntNE, zf, LLVMConstInt(i8, 0, 0), "zf_cmp"),
                              LLVMBuildICmp(jcontext->builder, LLVMIntNE, cf, LLVMConstInt(i8, 0, 0), "cf_cmp"),
                              "jbe_cond"
                );
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "jbe_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JNBE: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef cf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4), "cf");
                LLVMValueRef cond = LLVMBuildAnd(jcontext->builder, 
                              LLVMBuildICmp(jcontext->builder, LLVMIntEQ, zf, LLVMConstInt(i8, 0, 0), "zf_cmp"),
                              LLVMBuildICmp(jcontext->builder, LLVMIntEQ, cf, LLVMConstInt(i8, 0, 0), "cf_cmp"),
                              "jnbe_cond"
                );
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "jnbe_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JB: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                LLVMValueRef cf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4), "cf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, cf, LLVMConstInt(i8, 0, 0), "cf_cmp");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "jb_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_JNLE: {
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                LLVMValueRef new_addr = get_jump_target(jcontext, zcontext, runtime_address, phnum);
                
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef sf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3), "sf");
                LLVMValueRef of = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5), "of");
                
                LLVMValueRef zf_clear = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, zf, LLVMConstInt(i8, 0, 0), "zf_clear");
                LLVMValueRef sf_eq_of = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, sf, of, "sf_eq_of");
                LLVMValueRef cond = LLVMBuildAnd(jcontext->builder, zf_clear, sf_eq_of, "jnle_cond");
                
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    new_addr, LLVMConstInt(i64, old_addr, 0), "jnle_rip");
                
                ZydisDecodedOperand fake_rip = {0};
                fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER;
                fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                offset = phdr->p_filesz;
                break;
            }
            
            case ZYDIS_MNEMONIC_JNS: {
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                LLVMValueRef new_addr = get_jump_target(jcontext, zcontext, runtime_address, phnum);
                
                LLVMValueRef sf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3), "sf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, sf,
                    LLVMConstInt(i8, 0, 0), "jns_cond");
                
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    new_addr, LLVMConstInt(i64, old_addr, 0), "jns_rip");
                
                ZydisDecodedOperand fake_rip = {0};
                fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER;
                fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                offset = phdr->p_filesz;
                break;
            }
            
            case ZYDIS_MNEMONIC_CMPXCHG: {
                LLVMValueRef dst = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef src = get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
                
                LLVMValueRef rax_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 0);
                LLVMValueRef rax     = LLVMBuildLoad2(jcontext->builder, i64, rax_ptr, "rax");
                
                uint64_t mask = (zcontext->operands[0].size == 32) ? 0xFFFFFFFFULL
                              : (zcontext->operands[0].size == 16) ? 0xFFFFULL
                              : (zcontext->operands[0].size == 8)  ? 0xFFULL
                              : 0xFFFFFFFFFFFFFFFFULL;
                LLVMValueRef m    = LLVMConstInt(i64, mask, 0);
                LLVMValueRef rax_m = LLVMBuildAnd(jcontext->builder, rax, m, "rax_m");
                LLVMValueRef dst_m = LLVMBuildAnd(jcontext->builder, dst, m, "dst_m");
                
                LLVMValueRef equal = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, rax_m, dst_m, "cmpxchg_eq");
                
                LLVMValueRef new_dst = LLVMBuildSelect(jcontext->builder, equal, src, dst, "new_dst");
                LLVMValueRef new_rax = LLVMBuildSelect(jcontext->builder, equal, rax, dst, "new_rax");
                
                set_operand_value(new_dst, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                LLVMBuildStore(jcontext->builder, new_rax, rax_ptr);
                
                LLVMValueRef zf = LLVMBuildZExt(jcontext->builder, equal, i8, "zf");
                LLVMBuildStore(jcontext->builder, zf,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                break;
            }
            
            case ZYDIS_MNEMONIC_SHR: {
                LLVMValueRef dst = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef cnt = value;
                
                if (LLVMGetIntTypeWidth(LLVMTypeOf(cnt)) < LLVMGetIntTypeWidth(LLVMTypeOf(dst))) {
                    cnt = LLVMBuildZExt(jcontext->builder, cnt, LLVMTypeOf(dst), "shr_cnt");
                } else if (LLVMGetIntTypeWidth(LLVMTypeOf(cnt)) > LLVMGetIntTypeWidth(LLVMTypeOf(dst))) {
                    cnt = LLVMBuildTrunc(jcontext->builder, cnt, LLVMTypeOf(dst), "shr_cnt");
                }
                
                LLVMValueRef result = LLVMBuildLShr(jcontext->builder, dst, cnt, "shr_res");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_SAR: {
                LLVMValueRef src = value;
                LLVMValueRef dst = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                
                LLVMValueRef masked = LLVMBuildAnd(jcontext->builder, src,
                    LLVMConstInt(i64, 63, 0), "sar_mask");
                
                LLVMValueRef result = LLVMBuildAShr(jcontext->builder, dst, masked, "sar_result");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_NEG: {
                LLVMValueRef result = LLVMBuildNeg(jcontext->builder, value, "neg_res");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                
                LLVMValueRef zero = LLVMConstInt(LLVMTypeOf(value), 0, 0);
                LLVMValueRef cf_val = LLVMBuildZExt(jcontext->builder,
                    LLVMBuildICmp(jcontext->builder, LLVMIntNE, value, zero, "neg_cf_cmp"),
                    i8, "neg_cf");
                LLVMBuildStore(jcontext->builder, cf_val,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4));
                
                LLVMValueRef zf_val = LLVMBuildZExt(jcontext->builder,
                    LLVMBuildICmp(jcontext->builder, LLVMIntEQ, result, zero, "neg_zf_cmp"),
                    i8, "neg_zf");
                LLVMBuildStore(jcontext->builder, zf_val,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                
                LLVMValueRef sf_val = LLVMBuildZExt(jcontext->builder,
                    LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result,
                        LLVMConstInt(LLVMTypeOf(result), 0, 0), "neg_sf_cmp"), i8, "neg_sf");
                LLVMBuildStore(jcontext->builder, sf_val,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                break;
            }
            
            case ZYDIS_MNEMONIC_LOOP: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                LLVMValueRef rcx = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phnum);
                LLVMValueRef rcx_dec = LLVMBuildSub(jcontext->builder, rcx, LLVMConstInt(i64, 1, 0), "loop_dec");
                set_operand_value(rcx_dec, jcontext, zcontext, &fake_rcx, runtime_address);
                
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, rcx_dec, LLVMConstInt(i64, 0, 0), "loop_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0), LLVMConstInt(i64, old_addr, 0), "loop_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_CALL: {
                LLVMValueRef new_addr = get_jump_target(jcontext, zcontext, runtime_address, phnum);
                
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                LLVMValueRef new_rsp = LLVMBuildSub(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                
                LLVMValueRef host_rsp = GUEST_TO_HOST(jcontext->builder, new_rsp);
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, host_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0), mem_ptr);
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_addr, jcontext, zcontext, &fake_operand, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_RET: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef host_rsp = GUEST_TO_HOST(jcontext->builder, rsp_val);
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, host_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMValueRef ret_val = LLVMBuildLoad2(jcontext->builder, i64, mem_ptr, "ret_val");
                
                LLVMValueRef new_rsp = LLVMBuildAdd(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(ret_val, jcontext, zcontext, &fake_operand, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_MOV: {
                set_operand_value(value, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVZX: {
                 uint64_t mask;
                 switch (zcontext->operands[1].size) {
                    case 8:  mask = 0xFF;   break;
                    case 16: mask = 0xFFFF; break;
                    default: mask = 0xFFFFFFFF; break;
                 }
                 
                 LLVMValueRef result = LLVMBuildAnd(jcontext->builder, value,
                                     LLVMConstInt(i64, mask, 0), "movzx_res");
                 set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                 break;
            }
            
            case ZYDIS_MNEMONIC_LEA: {
                LLVMValueRef addr = compute_mem_addr(jcontext, &zcontext->operands[1],
                                                     zcontext->instruction, runtime_address);
                set_operand_value(addr, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVSXD: {
                LLVMValueRef trunc = LLVMBuildTrunc(jcontext->builder, value, LLVMInt32Type(), "sxd_trunc");
                LLVMValueRef sext  = LLVMBuildSExt(jcontext->builder, trunc, i64, "sxd_sext");
                set_operand_value(sext, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVSX: {
                LLVMValueRef src = get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
                
                uint32_t src_size = zcontext->operands[1].size;
                uint32_t dst_size = zcontext->operands[0].size;
                
                LLVMTypeRef src_type, dst_type;
                switch (src_size) {
                    case 8:  src_type = i8;              break;
                    case 16: src_type = LLVMInt16Type(); break;
                    default: src_type = LLVMInt32Type(); break;
                }
                switch (dst_size) {
                    case 16: dst_type = LLVMInt16Type(); break;
                    case 32: dst_type = LLVMInt32Type(); break;
                    default: dst_type = i64;             break;
                }
                
                LLVMValueRef truncated = LLVMBuildTrunc(jcontext->builder, src, src_type, "movsx_trunc");
                LLVMValueRef extended  = LLVMBuildSExt(jcontext->builder, truncated, dst_type, "movsx_sext");
                LLVMValueRef result = (dst_type != i64)
                    ? LLVMBuildZExt(jcontext->builder, extended, i64, "movsx_zext64")
                    : extended;
                
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_CMOVNZ: {
                LLVMValueRef zf = LLVMBuildLoad2(jcontext->builder, i8,
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2), "zf");
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,
                    zf, LLVMConstInt(i8, 0, 0), "cmovnz_cond");
                LLVMValueRef dst = get_operand_value(jcontext, zcontext,
                    &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef result = LLVMBuildSelect(jcontext->builder, cond, value, dst, "cmovnz_res");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_CDQE: {
                LLVMValueRef eax_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 0);
                LLVMValueRef rax = LLVMBuildLoad2(jcontext->builder, i64, eax_ptr, "rax");
                LLVMValueRef trunc = LLVMBuildTrunc(jcontext->builder, rax, LLVMInt32Type(), "eax");
                LLVMValueRef sext  = LLVMBuildSExt(jcontext->builder, trunc, i64, "cdqe");
                LLVMBuildStore(jcontext->builder, sext, eax_ptr);
                break;
            }
            
            case ZYDIS_MNEMONIC_XOR: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildXor(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"),
                                               value, "xor_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_OR: {
                LLVMValueRef dst = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef result = LLVMBuildOr(jcontext->builder, dst, value, "or_tmp");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_PXOR: {
                int dst_xmm = get_xmm_index(zcontext->operands[0].reg.value);
                int src_xmm = get_xmm_index(zcontext->operands[1].reg.value);
                
                if (dst_xmm >= 0 && src_xmm >= 0) {
                    LLVMValueRef lo = LLVMBuildXor(jcontext->builder,
                        get_xmm_lo(jcontext, dst_xmm), get_xmm_lo(jcontext, src_xmm), "pxor_lo");
                    LLVMValueRef hi = LLVMBuildXor(jcontext->builder,
                        get_xmm_hi(jcontext, dst_xmm), get_xmm_hi(jcontext, src_xmm), "pxor_hi");
                    set_xmm_lo_without_zero(jcontext, dst_xmm, lo);
                    set_xmm_hi(jcontext, dst_xmm, hi);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_AND: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                LLVMValueRef result = LLVMBuildAnd(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), value, "and_tmp");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                
                LLVMValueRef is_zero = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,  result, LLVMConstInt(i64, 0, 0), "zf_and");
                LLVMValueRef is_neg  = LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result, LLVMConstInt(i64, 0, 0), "sf_and");
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_zero, i8, "zf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_neg, i8, "sf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4)); // CF = 0
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5)); // OF = 0
                break;
            }
            
            case ZYDIS_MNEMONIC_ADD: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildAdd(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"),
                                               value, "add_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_SUB: {
                LLVMValueRef dst = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef result = LLVMBuildSub(jcontext->builder, dst, value, "sub_tmp");
                set_operand_value(result, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                
                LLVMValueRef is_zero = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, result, LLVMConstInt(i64, 0, 0), "is_zero");
                LLVMValueRef zf_val  = LLVMBuildZExt(jcontext->builder, is_zero, i8, "zf_val");
                LLVMBuildStore(jcontext->builder, zf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                break;
            }
            
            case ZYDIS_MNEMONIC_DIV: {
                LLVMTypeRef i128 = LLVMInt128Type();
                ZydisDecodedOperand fake_rax = {0}; fake_rax.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rax.reg.value = ZYDIS_REGISTER_RAX;
                ZydisDecodedOperand fake_rdx = {0}; fake_rdx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdx.reg.value = ZYDIS_REGISTER_RDX;
                LLVMValueRef rax = get_operand_value(jcontext, zcontext, &fake_rax, runtime_address, phnum);
                LLVMValueRef rdx = get_operand_value(jcontext, zcontext, &fake_rdx, runtime_address, phnum);
                
                LLVMValueRef rdx128    = LLVMBuildZExt(jcontext->builder, rdx,   i128, "");
                LLVMValueRef rax128    = LLVMBuildZExt(jcontext->builder, rax,   i128, "");
                LLVMValueRef value128  = LLVMBuildZExt(jcontext->builder, value, i128, "");
                
                LLVMValueRef rdx128_shifted = LLVMBuildShl(jcontext->builder, rdx128, LLVMConstInt(i128, 64, 0), "");
                LLVMValueRef full128 = LLVMBuildOr(jcontext->builder, rdx128_shifted, rax128, "combined_128");
                
                LLVMValueRef dived   = LLVMBuildUDiv(jcontext->builder, full128, value128, "div_tmp");
                LLVMValueRef remed   = LLVMBuildURem(jcontext->builder, full128, value128, "rem_tmp");
                LLVMValueRef dived64 = LLVMBuildTrunc(jcontext->builder, dived, i64, "dived64_tmp");
                LLVMValueRef remed64 = LLVMBuildTrunc(jcontext->builder, remed, i64, "remed64_tmp");
                
                set_operand_value(dived64, jcontext, zcontext, &fake_rax, runtime_address);
                set_operand_value(remed64, jcontext, zcontext, &fake_rdx, runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_INC: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildAdd(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"),
                                  LLVMConstInt(i64, 1, 0), "inc_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_DEC: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildSub(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"),
                                  LLVMConstInt(i64, 1, 0), "dec_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_IMUL: {
                switch (zcontext->instruction.operand_count_visible) {
                    case 2: {
                        LLVMValueRef dst = get_operand_value(jcontext, zcontext,
                            &zcontext->operands[0], runtime_address, phnum);
                        LLVMValueRef result = LLVMBuildMul(jcontext->builder, dst, value, "imul2_res");
                        set_operand_value(result, jcontext, zcontext,
                            &zcontext->operands[0], runtime_address);
                        break;
                    }
                    case 3: {
                        LLVMValueRef src = get_operand_value(jcontext, zcontext,
                            &zcontext->operands[1], runtime_address, phnum);
                        LLVMValueRef imm = get_operand_value(jcontext, zcontext,
                            &zcontext->operands[2], runtime_address, phnum);
                        LLVMValueRef result = LLVMBuildMul(jcontext->builder, src, imm, "imul3_res");
                        set_operand_value(result, jcontext, zcontext,
                            &zcontext->operands[0], runtime_address);
                        break;
                    }
                    default: {
                        printf("PANIC!!!\nUnexpected use (imul)!\n");
                        break;
                    }
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_CMP: {
                LLVMValueRef lhs    = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef result = LLVMBuildSub(jcontext->builder, lhs, value, "cmp_result");
                
                LLVMValueRef is_eq  = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,  lhs, value, "zf_cmp");
                LLVMValueRef is_neg = LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result, LLVMConstInt(i64, 0, 0), "sf_cmp");
                LLVMValueRef is_ult = LLVMBuildICmp(jcontext->builder, LLVMIntULT, lhs, value, "cf_cmp");
                
                LLVMValueRef signs_diff       = LLVMBuildICmp(jcontext->builder, LLVMIntSLT,
                                                    LLVMBuildXor(jcontext->builder, lhs, value, "xor_signs"),
                                                    LLVMConstInt(i64, 0, 0), "signs_diff");
                LLVMValueRef result_sign_diff = LLVMBuildICmp(jcontext->builder, LLVMIntSLT,
                                                    LLVMBuildXor(jcontext->builder, result, lhs, "xor_res"),
                                                    LLVMConstInt(i64, 0, 0), "res_sign_diff");
                LLVMValueRef is_of = LLVMBuildAnd(jcontext->builder, signs_diff, result_sign_diff, "of_cmp");
                
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_eq,  i8, "zf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_neg, i8, "sf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_ult, i8, "cf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4));
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_of,  i8, "of_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5));
                break;
            }
            
            case ZYDIS_MNEMONIC_TEST: {
                LLVMValueRef lhs    = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef result = LLVMBuildAnd(jcontext->builder, lhs, value, "test_result");
                
                LLVMValueRef is_zero = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,  result, LLVMConstInt(i64, 0, 0), "zf_test");
                LLVMValueRef is_neg  = LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result, LLVMConstInt(i64, 0, 0), "sf_test");
                
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_zero, i8, "zf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_neg,  i8, "sf_i8"),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4));
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5));
                break;
            }
            
            case ZYDIS_MNEMONIC_CLD: {
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 6));
                break;
            }
            
            case ZYDIS_MNEMONIC_STD: {
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 1, 0),
                    get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 6));
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVSB: {
                ZydisDecodedOperand fake_rsi = {0}; fake_rsi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rsi.reg.value = ZYDIS_REGISTER_RSI;
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rsi_val = get_operand_value(jcontext, zcontext, &fake_rsi, runtime_address, phnum);
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phnum);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phnum);
                
                LLVMTypeRef i8ptr = LLVMPointerType(i8, 0);
                
                LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rsi_val), i8ptr, "src_ptr");
                LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rdi_val), i8ptr, "dst_ptr");
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REP) {
                    LLVMBuildMemMove(jcontext->builder, dst_ptr, 1, src_ptr, 1, rcx_val);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, rcx_val, "rsi_new"), jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, rcx_val, "rdi_new"), jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0),                                      jcontext, zcontext, &fake_rcx, runtime_address);
                } else {
                    LLVMValueRef byte = LLVMBuildLoad2(jcontext->builder, i8, src_ptr, "movsb_byte");
                    LLVMBuildStore(jcontext->builder, byte, dst_ptr);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, LLVMConstInt(i64, 1, 0), "rsi_inc"), jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, LLVMConstInt(i64, 1, 0), "rdi_inc"), jcontext, zcontext, &fake_rdi, runtime_address);
                }
                
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVQ: {
                ZydisRegister dst_reg = zcontext->operands[0].reg.value;
                ZydisRegister src_reg = zcontext->operands[1].reg.value;
                int dst_xmm = get_xmm_index(dst_reg);
                int src_xmm = get_xmm_index(src_reg);
                
                if (dst_xmm >= 0) {
                    LLVMValueRef src_val = (src_xmm >= 0)
                        ? get_xmm_lo(jcontext, src_xmm)
                        : get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
                    set_xmm_lo(jcontext, dst_xmm, src_val);
                } else {
                    LLVMValueRef src_val = get_xmm_lo(jcontext, src_xmm);
                    set_operand_value(src_val, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVSQ: {
                ZydisDecodedOperand fake_rsi = {0}; fake_rsi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rsi.reg.value = ZYDIS_REGISTER_RSI;
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rsi_val = get_operand_value(jcontext, zcontext, &fake_rsi, runtime_address, phnum);
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phnum);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phnum);
                
                LLVMTypeRef i64ptr = LLVMPointerType(i64, 0);
                LLVMTypeRef i8ptr = LLVMPointerType(i8, 0);
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REP) {
                    LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rsi_val), i8ptr, "src_ptr");
                    LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rdi_val), i8ptr, "dst_ptr");
                    LLVMValueRef byte_count = LLVMBuildMul(jcontext->builder, rcx_val,
                                              LLVMConstInt(i64, 8, 0), "movsq_bytes");
                    LLVMBuildMemMove(jcontext->builder, dst_ptr, 8, src_ptr, 8, byte_count);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, byte_count, "rsi_new"), jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, byte_count, "rdi_new"), jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0),                                         jcontext, zcontext, &fake_rcx, runtime_address);
                } else {
                    LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rsi_val), i64ptr, "src_ptr");
                    LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rdi_val), i64ptr, "dst_ptr");
                    LLVMValueRef qword = LLVMBuildLoad2(jcontext->builder, i64, src_ptr, "movsq_qword");
                    LLVMBuildStore(jcontext->builder, qword, dst_ptr);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, LLVMConstInt(i64, 8, 0), "rsi_inc"), jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, LLVMConstInt(i64, 8, 0), "rdi_inc"), jcontext, zcontext, &fake_rdi, runtime_address);
                }
                
                break;
            }
            
            case ZYDIS_MNEMONIC_STOSQ: {
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rax = {0}; fake_rax.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rax.reg.value = ZYDIS_REGISTER_RAX;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phnum);
                LLVMValueRef rax_val = get_operand_value(jcontext, zcontext, &fake_rax, runtime_address, phnum);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phnum);
                LLVMTypeRef  i64ptr  = LLVMPointerType(i64, 0);
                
                LLVMValueRef host_rdi = GUEST_TO_HOST(jcontext->builder, rdi_val);
                LLVMValueRef base_ptr = LLVMBuildIntToPtr(jcontext->builder, host_rdi, i64ptr, "stosq_ptr");
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REP) {
                    LLVMValueRef func = LLVMGetBasicBlockParent(LLVMGetInsertBlock(jcontext->builder));
                    LLVMBasicBlockRef pre_bb = LLVMGetInsertBlock(jcontext->builder);
                    
                    LLVMBasicBlockRef loop_bb = LLVMAppendBasicBlock(func, "stosq_loop");
                    LLVMBasicBlockRef exit_bb = LLVMAppendBasicBlock(func, "stosq_exit");
                    
                    LLVMValueRef entry_cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE,
                        rcx_val, LLVMConstInt(i64, 0, 0), "stosq_ne");
                    LLVMBuildCondBr(jcontext->builder, entry_cond, loop_bb, exit_bb);
                    
                    LLVMPositionBuilderAtEnd(jcontext->builder, loop_bb);
                    LLVMValueRef idx_phi = LLVMBuildPhi(jcontext->builder, i64, "stosq_idx");
                    
                    LLVMValueRef elem_ptr = LLVMBuildGEP2(jcontext->builder, i64, base_ptr,
                        &idx_phi, 1, "stosq_elem");
                    LLVMBuildStore(jcontext->builder, rax_val, elem_ptr);
                    
                    LLVMValueRef idx_next = LLVMBuildAdd(jcontext->builder, idx_phi,
                        LLVMConstInt(i64, 1, 0), "stosq_next");
                    LLVMValueRef loop_cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE,
                        idx_next, rcx_val, "stosq_cond");
                    LLVMBuildCondBr(jcontext->builder, loop_cond, loop_bb, exit_bb);
                    
                    LLVMBasicBlockRef loop_back = LLVMGetInsertBlock(jcontext->builder);
                    LLVMValueRef phi_vals[] = { LLVMConstInt(i64, 0, 0), idx_next };
                    LLVMBasicBlockRef phi_bbs[] = { pre_bb, loop_back };
                    LLVMAddIncoming(idx_phi, phi_vals, phi_bbs, 2);
                    
                    LLVMPositionBuilderAtEnd(jcontext->builder, exit_bb);
                    
                    LLVMValueRef byte_count = LLVMBuildMul(jcontext->builder, rcx_val,
                        LLVMConstInt(i64, 8, 0), "stosq_bytes");
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, byte_count, "rdi_new"),
                        jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0),
                        jcontext, zcontext, &fake_rcx, runtime_address);
                } else {
                    LLVMBuildStore(jcontext->builder, rax_val, base_ptr);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, LLVMConstInt(i64, 8, 0), "rdi_inc"),
                                                                   jcontext, zcontext, &fake_rdi, runtime_address);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_CMPSB: {
                ZydisDecodedOperand fake_rsi = {0}; fake_rsi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rsi.reg.value = ZYDIS_REGISTER_RSI;
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rsi_val = get_operand_value(jcontext, zcontext, &fake_rsi, runtime_address, phnum);
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phnum);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phnum);
                
                LLVMTypeRef i8ptr = LLVMPointerType(i8, 0);
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REPE) {
                    LLVMTypeRef memcmp_type = LLVMFunctionType(LLVMInt32Type(), (LLVMTypeRef[]){ i8ptr, i8ptr, i64 }, 3, 0);
                    LLVMValueRef memcmp_fn = LLVMGetNamedFunction(jcontext->mod, "memcmp");
                    if (!memcmp_fn)
                        memcmp_fn = LLVMAddFunction(jcontext->mod, "memcmp", memcmp_type);
                    
                    LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rsi_val), i8ptr, "cmp_src");
                    LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, GUEST_TO_HOST(jcontext->builder, rdi_val), i8ptr, "cmp_dst");
                    
                    LLVMValueRef result = LLVMBuildCall2(jcontext->builder, memcmp_type, memcmp_fn,
                        (LLVMValueRef[]){ src_ptr, dst_ptr, rcx_val }, 3, "memcmp_result");
                    
                    LLVMValueRef is_eq  = LLVMBuildICmp(jcontext->builder, LLVMIntEQ, result, LLVMConstInt(LLVMInt32Type(), 0, 0), "cmpsb_eq");
                    LLVMBuildStore(jcontext->builder, LLVMBuildZExt(jcontext->builder, is_eq, i8, "zf_i8"),
                        get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                    
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, rcx_val, "rsi_new"), jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, rcx_val, "rdi_new"), jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0), jcontext, zcontext, &fake_rcx, runtime_address);
                }
                
                break;
            }
            
            case ZYDIS_MNEMONIC_PUSH: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                LLVMValueRef new_rsp = LLVMBuildSub(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                
                LLVMValueRef host_rsp = GUEST_TO_HOST(jcontext->builder, new_rsp);
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, host_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMBuildStore(jcontext->builder, value, mem_ptr);
                break;
            }
            
            case ZYDIS_MNEMONIC_POP: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef host_rsp = GUEST_TO_HOST(jcontext->builder, rsp_val);
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, host_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMValueRef pop_val = LLVMBuildLoad2(jcontext->builder, i64, mem_ptr, "pop_val");
                
                LLVMValueRef new_rsp = LLVMBuildAdd(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                set_operand_value(pop_val, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_SYSCALL: {
                LLVMValueRef args[] = { jcontext->cpu_ptr };
                LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->syscall_handler, args, 1, "");
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0),
                                  jcontext, zcontext, &fake_operand, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_INT: {
                if (zcontext->operands[0].imm.value.u == 0x80) {
                    LLVMValueRef args[] = { jcontext->cpu_ptr };
                    LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->int80_handler, args, 1, "");
                    
                    ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_EIP;
                    set_operand_value(LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0),
                        jcontext, zcontext, &fake_operand, runtime_address);
                    offset = phdr->p_filesz; // break "while"
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_PUNPCKLQDQ: {
                int dst_idx = get_xmm_index(zcontext->operands[0].reg.value);
                int src_idx = get_xmm_index(zcontext->operands[1].reg.value);
                
                LLVMValueRef src_val = (src_idx >= 0)
                    ? get_xmm_lo(jcontext, src_idx)
                    : get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
                
                LLVMBuildStore(jcontext->builder, src_val,
                    get_xmm_ptr(jcontext->builder, jcontext->cpu_ptr,
                                jcontext->cpu_struct_type, dst_idx, 1));
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVUPS:
            case ZYDIS_MNEMONIC_MOVDQU:
            case ZYDIS_MNEMONIC_MOVDQA:
            case ZYDIS_MNEMONIC_MOVAPS: {
                int dst_xmm = get_xmm_index(zcontext->operands[0].reg.value);
                int src_xmm = get_xmm_index(zcontext->operands[1].reg.value);
                
                if (dst_xmm >= 0 && src_xmm >= 0) {
                    set_xmm_lo_without_zero(jcontext, dst_xmm, get_xmm_lo(jcontext, src_xmm));
                    set_xmm_hi(jcontext, dst_xmm, get_xmm_hi(jcontext, src_xmm));
                } 
                else if (dst_xmm >= 0) {
                    LLVMValueRef addr = compute_mem_addr(jcontext, &zcontext->operands[1], zcontext->instruction, runtime_address);
                    
                    LLVMValueRef host_addr = GUEST_TO_HOST(jcontext->builder, addr);
                    LLVMValueRef ptr_lo = LLVMBuildIntToPtr(jcontext->builder, host_addr, LLVMPointerType(i64, 0), "ptr_lo");
                    
                    LLVMValueRef host_addr_hi = LLVMBuildAdd(jcontext->builder, host_addr, LLVMConstInt(i64, 8, 0), "host_addr_hi");
                    LLVMValueRef ptr_hi = LLVMBuildIntToPtr(jcontext->builder, host_addr_hi, LLVMPointerType(i64, 0), "ptr_hi");
                    
                    set_xmm_lo_without_zero(jcontext, dst_xmm, LLVMBuildLoad2(jcontext->builder, i64, ptr_lo, "val_lo"));
                    set_xmm_hi(jcontext, dst_xmm, LLVMBuildLoad2(jcontext->builder, i64, ptr_hi, "val_hi"));
                } 
                else if (src_xmm >= 0) {
                    LLVMValueRef addr = compute_mem_addr(jcontext, &zcontext->operands[0], zcontext->instruction, runtime_address);
                    
                    LLVMValueRef host_addr = GUEST_TO_HOST(jcontext->builder, addr);
                    LLVMValueRef ptr_lo = LLVMBuildIntToPtr(jcontext->builder, host_addr, LLVMPointerType(i64, 0), "ptr_lo");
                    
                    LLVMValueRef host_addr_hi = LLVMBuildAdd(jcontext->builder, host_addr, LLVMConstInt(i64, 8, 0), "host_addr_hi");
                    LLVMValueRef ptr_hi = LLVMBuildIntToPtr(jcontext->builder, host_addr_hi, LLVMPointerType(i64, 0), "ptr_hi");
                    
                    LLVMBuildStore(jcontext->builder, get_xmm_lo(jcontext, src_xmm), ptr_lo);
                    LLVMBuildStore(jcontext->builder, get_xmm_hi(jcontext, src_xmm), ptr_hi);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_XCHG: {
                LLVMValueRef a = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phnum);
                LLVMValueRef b = get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phnum);
                set_operand_value(b, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                set_operand_value(a, jcontext, zcontext, &zcontext->operands[1], runtime_address);
                break;
            }
            
            default: {
                printf("PANIC!!!\nUnsupported instruction: %s\n", ZydisMnemonicGetString(zcontext->instruction.mnemonic));
                exit(189);
                break;
            }
        }
        
        runtime_address += zcontext->instruction.length;
    }
}
