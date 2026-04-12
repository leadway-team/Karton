#include "karton.h"

GElf_Phdr* find_phdr(ZyanUSize phnum, uint64_t addr) {
    for (ZyanUSize i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && addr >= phdrs[i].p_vaddr && addr < (phdrs[i].p_vaddr + phdrs[i].p_memsz)) {
            return &phdrs[i];
        }
    }
    return ZYAN_NULL;
}

void* access_quest(uint64_t guest_addr, GElf_Phdr *phdr, uint8_t *raw_bin) {
    uint64_t offset_in_segment = guest_addr - phdr->p_vaddr;
    uint64_t offset_in_file = phdr->p_offset + offset_in_segment;
    return (void*)(raw_bin + offset_in_file);
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

int get_register_index(ZydisRegister reg) {
    if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_RDI) {
        return reg - ZYDIS_REGISTER_RAX;
    }
    if (reg >= ZYDIS_REGISTER_R8 && reg <= ZYDIS_REGISTER_R15) {
        return 8 + (reg - ZYDIS_REGISTER_R8);
    }
    
    if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_EDI) {
        return reg - ZYDIS_REGISTER_EAX;
    }
    
    if (reg == ZYDIS_REGISTER_EIP || reg == ZYDIS_REGISTER_RIP) {
        return 16;
    }
    
    return -1; 
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

LLVMValueRef get_operand_value(JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address, GElf_Phdr *phdr, uint8_t *raw_bin) {
    switch (operand->type) {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
            uint64_t tmp = operand->imm.value.s;
            if (tmp >= phdr->p_vaddr && tmp < (phdr->p_vaddr + phdr->p_memsz)) {
                tmp = (uint64_t)access_quest(tmp, phdr, raw_bin);
            }
            return LLVMConstInt(i64, tmp, 0);
            break;
        }
        
        case ZYDIS_OPERAND_TYPE_MEMORY: {
            LLVMValueRef addr = compute_mem_addr(jcontext, operand, zcontext->instruction, runtime_address);
            LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, addr, LLVMPointerType(i64, 0), "mem_ptr");
            return LLVMBuildLoad2(jcontext->builder, i64, mem_ptr, "mem_val");
            break;
        }
        
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int reg_idx = get_register_index(operand->reg.value);
            LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
            return LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "reg_ptr");
            break;
        }
        
        default: {
            return NULL;
            break;
        }
    }
}

void set_operand_value(LLVMValueRef value, JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address) {
    switch (operand->type) {
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int reg_idx = get_register_index(operand->reg.value);
            LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
            LLVMBuildStore(jcontext->builder, value, reg_ptr);
            break;
        }
        
        case ZYDIS_OPERAND_TYPE_MEMORY: {
            LLVMValueRef addr = compute_mem_addr(jcontext, operand, zcontext->instruction, runtime_address);
            LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, addr, LLVMPointerType(i64, 0), "mem_ptr");
            LLVMBuildStore(jcontext->builder, value, mem_ptr);
            break;
        }
        
        default: {
            break;
        }
    }
}

void gen_ir(GElf_Phdr *phdr, ZyanUSize phnum, uint8_t *raw_bin, ZydisCtx *zcontext, JITCtx *jcontext) {
    ZyanU64 offset = 0;
    ZyanU64 runtime_address = cpu.rip;
    
    while (offset < phdr->p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zcontext->decoder, (ZyanU8*)runtime_address, phdr->p_filesz, &zcontext->instruction, zcontext->operands))) {
        #ifdef DEBUG
        printf("%016" PRIX64 "  ", runtime_address);
        
        char buffer[256];
        ZydisFormatterFormatInstruction(&zcontext->formatter, &zcontext->instruction, zcontext->operands, zcontext->instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
        puts(buffer);
        #endif
        
        LLVMValueRef value;
        
        if (zcontext->instruction.operand_count_visible == 1) {
            value = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phdr, raw_bin);
        } else if (zcontext->instruction.operand_count_visible >= 2) {
            value = get_operand_value(jcontext, zcontext, &zcontext->operands[1], runtime_address, phdr, raw_bin);
        }
                    
        switch (zcontext->instruction.mnemonic) {
            case ZYDIS_MNEMONIC_ENDBR64: {
                break; // security is for weak peoples, bozo
            }
            
            case ZYDIS_MNEMONIC_JMP: {
                uint64_t new_addr;
                
                ZydisCalcAbsoluteAddress(
                    &zcontext->instruction,
                    &zcontext->operands[0],
                    runtime_address,
                    &new_addr
                );
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(LLVMConstInt(i64, new_addr, 0), jcontext, zcontext, &fake_operand, runtime_address);
                
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
                    LLVMConstInt(i64, new_addr, 0),
                    LLVMConstInt(i64, old_addr, 0), "je_rip");

                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
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
                    LLVMConstInt(i64, new_addr, 0),
                    LLVMConstInt(i64, old_addr, 0), "jnz_rip");
                
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
                    LLVMConstInt(i64, new_addr, 0),
                    LLVMConstInt(i64, old_addr, 0), "jl_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_LOOP: {
                uint64_t new_addr;
                ZydisCalcAbsoluteAddress(&zcontext->instruction, &zcontext->operands[0], runtime_address, &new_addr);
                uint64_t old_addr = runtime_address + zcontext->instruction.length;
                
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                LLVMValueRef rcx = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phdr, raw_bin);
                LLVMValueRef rcx_dec = LLVMBuildSub(jcontext->builder, rcx, LLVMConstInt(i64, 1, 0), "loop_dec");
                set_operand_value(rcx_dec, jcontext, zcontext, &fake_rcx, runtime_address);
                
                LLVMValueRef cond = LLVMBuildICmp(jcontext->builder, LLVMIntNE, rcx_dec, LLVMConstInt(i64, 0, 0), "loop_cond");
                LLVMValueRef new_rip = LLVMBuildSelect(jcontext->builder, cond,
                    LLVMConstInt(i64, new_addr, 0),
                    LLVMConstInt(i64, old_addr, 0), "loop_rip");
                
                ZydisDecodedOperand fake_rip = {0}; fake_rip.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rip.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(new_rip, jcontext, zcontext, &fake_rip, runtime_address);
                offset = phdr->p_filesz;
                break;
            }
            
            case ZYDIS_MNEMONIC_CALL: {
                uint64_t new_addr;
                
                ZydisCalcAbsoluteAddress(
                    &zcontext->instruction,
                    &zcontext->operands[0],
                    runtime_address,
                    &new_addr
                );
                
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef new_rsp = LLVMBuildSub(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, new_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0), mem_ptr);
                
                ZydisDecodedOperand fake_operand = {0}; fake_operand.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_operand.reg.value = ZYDIS_REGISTER_RIP;
                set_operand_value(LLVMConstInt(i64, new_addr, 0), jcontext, zcontext, &fake_operand, runtime_address);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_RET: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, rsp_val, LLVMPointerType(i64, 0), "mem_ptr");
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
            
            case ZYDIS_MNEMONIC_LEA: {
                LLVMValueRef addr = compute_mem_addr(jcontext, &zcontext->operands[1], 
                                                     zcontext->instruction, runtime_address);
                set_operand_value(addr, jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_XOR: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildXor(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                   value, "xor_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
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
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildSub(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                    value, "sub_tmp"), jcontext, zcontext, &zcontext->operands[0], runtime_address);
                break;
            }
            
            case ZYDIS_MNEMONIC_DIV: {
                LLVMTypeRef i128 = LLVMInt128Type();
                ZydisDecodedOperand fake_rax; fake_rax.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rax.reg.value = ZYDIS_REGISTER_RAX;
                ZydisDecodedOperand fake_rdx; fake_rdx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdx.reg.value = ZYDIS_REGISTER_RDX;
                LLVMValueRef rax = get_operand_value(jcontext, zcontext, &fake_rax, runtime_address, phdr, raw_bin);
                LLVMValueRef rdx = get_operand_value(jcontext, zcontext, &fake_rdx, runtime_address, phdr, raw_bin);
                
                LLVMValueRef rdx128 = LLVMBuildZExt(jcontext->builder, rdx, i128, "");
                LLVMValueRef rax128  = LLVMBuildZExt(jcontext->builder, rax, i128, "");
                LLVMValueRef value128  = LLVMBuildZExt(jcontext->builder, value, i128, "");
                
                LLVMValueRef rdx128_shifted = LLVMBuildShl(jcontext->builder, rdx128, LLVMConstInt(i128, 64, 0), "");
                LLVMValueRef full128 = LLVMBuildOr(jcontext->builder, rdx128_shifted, rax128, "combined_128");

                LLVMValueRef dived = LLVMBuildUDiv(jcontext->builder, full128, value128, "div_tmp");
                LLVMValueRef remed = LLVMBuildURem(jcontext->builder, full128, value128, "rem_tmp");
                
                LLVMValueRef dived64 = LLVMBuildTrunc(jcontext->builder, dived, i64, "dived64_tmp");
                LLVMValueRef remed64  = LLVMBuildTrunc(jcontext->builder, remed, i64, "remed64_tmp");
                
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
            
            case ZYDIS_MNEMONIC_CMP: {
                LLVMValueRef lhs = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phdr, raw_bin);
                LLVMValueRef result = LLVMBuildSub(jcontext->builder, lhs, value, "cmp_result");
                
                LLVMValueRef is_eq  = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,  lhs, value, "zf_cmp");
                LLVMValueRef is_neg = LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result, LLVMConstInt(i64, 0, 0), "sf_cmp");
                LLVMValueRef is_ult = LLVMBuildICmp(jcontext->builder, LLVMIntULT, lhs, value, "cf_cmp");
                
                LLVMValueRef signs_diff = LLVMBuildICmp(jcontext->builder, LLVMIntSLT,
                                                LLVMBuildXor(jcontext->builder, lhs, value, "xor_signs"),
                                                LLVMConstInt(i64, 0, 0), "signs_diff");
                LLVMValueRef result_sign_diffs = LLVMBuildICmp(jcontext->builder, LLVMIntSLT,
                                                LLVMBuildXor(jcontext->builder, result, lhs, "xor_res"),
                                                LLVMConstInt(i64, 0, 0), "res_sign_diff");
                LLVMValueRef is_of = LLVMBuildAnd(jcontext->builder, signs_diff, result_sign_diffs, "of_cmp");
                
                LLVMValueRef zf_val = LLVMBuildZExt(jcontext->builder, is_eq,  i8, "zf_i8");
                LLVMValueRef sf_val = LLVMBuildZExt(jcontext->builder, is_neg, i8, "sf_i8");
                LLVMValueRef cf_val = LLVMBuildZExt(jcontext->builder, is_ult, i8, "cf_i8");
                LLVMValueRef of_val = LLVMBuildZExt(jcontext->builder, is_of,  i8, "of_i8");
                
                LLVMBuildStore(jcontext->builder, zf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                LLVMBuildStore(jcontext->builder, sf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                LLVMBuildStore(jcontext->builder, cf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4));
                LLVMBuildStore(jcontext->builder, of_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5));
                break;
            }
            
            case ZYDIS_MNEMONIC_TEST: {
                LLVMValueRef lhs = get_operand_value(jcontext, zcontext, &zcontext->operands[0], runtime_address, phdr, raw_bin);
                LLVMValueRef result = LLVMBuildAnd(jcontext->builder, lhs, value, "test_result");

                LLVMValueRef is_zero = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,  result, LLVMConstInt(i64, 0, 0), "zf_test");
                LLVMValueRef is_neg  = LLVMBuildICmp(jcontext->builder, LLVMIntSLT, result, LLVMConstInt(i64, 0, 0), "sf_test");

                LLVMValueRef zf_val = LLVMBuildZExt(jcontext->builder, is_zero, i8, "zf_i8");
                LLVMValueRef sf_val = LLVMBuildZExt(jcontext->builder, is_neg,  i8, "sf_i8");

                LLVMBuildStore(jcontext->builder, zf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                LLVMBuildStore(jcontext->builder, sf_val, get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 3));
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i64, 0, 0), get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4));
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i64, 0, 0), get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 5));
                break;
            }
            
            case ZYDIS_MNEMONIC_CLD: {
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 0, 0), get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 6));
                break;
            }
            
            case ZYDIS_MNEMONIC_STD: {
                LLVMBuildStore(jcontext->builder, LLVMConstInt(i8, 1, 0), get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 6));
                break;
            }
            
            case ZYDIS_MNEMONIC_MOVSB: {
                ZydisDecodedOperand fake_rsi = {0}; fake_rsi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rsi.reg.value = ZYDIS_REGISTER_RSI;
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rsi_val = get_operand_value(jcontext, zcontext, &fake_rsi, runtime_address, phdr, raw_bin);
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phdr, raw_bin);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phdr, raw_bin);
                
                LLVMTypeRef i8ptr = LLVMPointerType(LLVMInt8Type(), 0);
                LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, rsi_val, i8ptr, "src_ptr");
                LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, rdi_val, i8ptr, "dst_ptr");
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REP) {
                    LLVMBuildMemMove(jcontext->builder, dst_ptr, 1, src_ptr, 1, rcx_val);
                    
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, rcx_val, "rsi_new"),
                                      jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, rcx_val, "rdi_new"),
                                      jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0),
                                      jcontext, zcontext, &fake_rcx, runtime_address);
                } else {
                    LLVMValueRef byte = LLVMBuildLoad2(jcontext->builder, LLVMInt8Type(), src_ptr, "movsb_byte");
                    LLVMBuildStore(jcontext->builder, byte, dst_ptr);
                    
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, LLVMConstInt(i64, 1, 0), "rsi_inc"),
                                      jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, LLVMConstInt(i64, 1, 0), "rdi_inc"),
                                      jcontext, zcontext, &fake_rdi, runtime_address);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_CMPSB: {
                ZydisDecodedOperand fake_rsi = {0}; fake_rsi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rsi.reg.value = ZYDIS_REGISTER_RSI;
                ZydisDecodedOperand fake_rdi = {0}; fake_rdi.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rdi.reg.value = ZYDIS_REGISTER_RDI;
                ZydisDecodedOperand fake_rcx = {0}; fake_rcx.type = ZYDIS_OPERAND_TYPE_REGISTER; fake_rcx.reg.value = ZYDIS_REGISTER_RCX;
                
                LLVMValueRef rsi_val = get_operand_value(jcontext, zcontext, &fake_rsi, runtime_address, phdr, raw_bin);
                LLVMValueRef rdi_val = get_operand_value(jcontext, zcontext, &fake_rdi, runtime_address, phdr, raw_bin);
                LLVMValueRef rcx_val = get_operand_value(jcontext, zcontext, &fake_rcx, runtime_address, phdr, raw_bin);
                
                LLVMTypeRef i8ptr = LLVMPointerType(LLVMInt8Type(), 0);
                
                if (zcontext->instruction.attributes & ZYDIS_ATTRIB_HAS_REPE) {
                    LLVMTypeRef memcmp_type = LLVMFunctionType(
                        LLVMInt32Type(),
                        (LLVMTypeRef[]){ i8ptr, i8ptr, i64 },
                        3, 0
                    );
                    LLVMValueRef memcmp_fn = LLVMGetNamedFunction(jcontext->mod, "memcmp");
                    if (!memcmp_fn)
                        memcmp_fn = LLVMAddFunction(jcontext->mod, "memcmp", memcmp_type);
                    
                    LLVMValueRef src_ptr = LLVMBuildIntToPtr(jcontext->builder, rsi_val, i8ptr, "cmp_src");
                    LLVMValueRef dst_ptr = LLVMBuildIntToPtr(jcontext->builder, rdi_val, i8ptr, "cmp_dst");
                    
                    LLVMValueRef result = LLVMBuildCall2(jcontext->builder, memcmp_type, memcmp_fn,
                        (LLVMValueRef[]){ src_ptr, dst_ptr, rcx_val }, 3, "memcmp_result");
                    
                    LLVMValueRef is_eq = LLVMBuildICmp(jcontext->builder, LLVMIntEQ,
                        result, LLVMConstInt(LLVMInt32Type(), 0, 0), "cmpsb_eq");
                    LLVMValueRef zf_val = LLVMBuildZExt(jcontext->builder, is_eq, i8, "zf_i8");
                    
                    LLVMBuildStore(jcontext->builder, zf_val,
                        get_flag_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 2));
                    
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rsi_val, rcx_val, "rsi_new"),
                                      jcontext, zcontext, &fake_rsi, runtime_address);
                    set_operand_value(LLVMBuildAdd(jcontext->builder, rdi_val, rcx_val, "rdi_new"),
                                      jcontext, zcontext, &fake_rdi, runtime_address);
                    set_operand_value(LLVMConstInt(i64, 0, 0),
                                      jcontext, zcontext, &fake_rcx, runtime_address);
                }
                break;
            }
            
            case ZYDIS_MNEMONIC_PUSH: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef new_rsp = LLVMBuildSub(jcontext->builder, rsp_val, LLVMConstInt(i64, 8, 0), "new_rsp");
                LLVMBuildStore(jcontext->builder, new_rsp, rsp_ptr);
                
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, new_rsp, LLVMPointerType(i64, 0), "mem_ptr");
                LLVMBuildStore(jcontext->builder, value, mem_ptr);
                break;
            }
            
            case ZYDIS_MNEMONIC_POP: {
                LLVMValueRef rsp_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, 4);
                LLVMValueRef rsp_val = LLVMBuildLoad2(jcontext->builder, i64, rsp_ptr, "rsp_val");
                
                LLVMValueRef mem_ptr = LLVMBuildIntToPtr(jcontext->builder, rsp_val, LLVMPointerType(i64, 0), "mem_ptr");
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
            
            default: {
                  printf("PANIC!!!\nUnsupported instruction: %s\n", ZydisMnemonicGetString(zcontext->instruction.mnemonic));
                  break;
            }
        }
        
        runtime_address += zcontext->instruction.length;
    }
}
