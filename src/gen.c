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

LLVMValueRef get_operand_value(LLVMBuilderRef builder, ZydisDecodedOperand *operand, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, GElf_Phdr *phdr, uint8_t *raw_bin) {
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
            return LLVMConstInt(i64, (uint64_t)access_quest(operand->mem.disp.value, phdr, raw_bin), 0);
            break;
        }
        
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int reg_idx = get_register_index(operand->reg.value);
            LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
            return LLVMBuildLoad2(builder, i64, reg_ptr, "reg_ptr");
        }
        
        default: {
            return NULL;
            break;
        }
    }
}

void set_operand_value(LLVMValueRef value, LLVMBuilderRef builder, ZydisDecodedOperand *operand, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, CPUState *dcpu) {
    int reg_idx = get_register_index(operand->reg.value);
    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
    LLVMBuildStore(builder, value, reg_ptr);
    
    if (reg_idx < 16) {
        dcpu->gprs[reg_idx] = LLVMConstIntGetSExtValue(value);
    }
}

void gen_ir(ZyanU8*** data, GElf_Phdr *phdr, ZyanUSize phnum, uint8_t *raw_bin, CPUState *dcpu, ZydisCtx *zcontext, JITCtx *jcontext) {
    ZyanUSize offset = 0;
    ZyanU64 runtime_address = dcpu->rip;
    
    while (offset < phdr->p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zcontext->decoder, *data[0] + offset, phdr->p_filesz - offset, &zcontext->instruction, zcontext->operands))) {
        #ifdef DEBUG
        printf("%016" PRIX64 "  ", runtime_address);
        
        char buffer[256];
        ZydisFormatterFormatInstruction(&zcontext->formatter, &zcontext->instruction, zcontext->operands, zcontext->instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
        puts(buffer);
        #endif
        
        LLVMValueRef value;
        
        if (zcontext->instruction.operand_count_visible == 1) {
            value = get_operand_value(jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, phdr, raw_bin);
        } else if (zcontext->instruction.operand_count_visible >= 2) {
            value = get_operand_value(jcontext->builder, &zcontext->operands[1], jcontext->cpu_ptr, jcontext->cpu_struct_type, phdr, raw_bin);
        }
                    
        switch (zcontext->instruction.mnemonic) {
            case ZYDIS_MNEMONIC_JMP: {
                ZydisCalcAbsoluteAddress(
                    &zcontext->instruction,
                    &zcontext->operands[0],
                    runtime_address,
                    &dcpu->rip
                );
                
                phdr = find_phdr(phnum, dcpu->rip);
                uint64_t new_addr = (uint64_t)access_quest(dcpu->rip, phdr, raw_bin);
                
                vector_insert(data, 0, (ZyanU8*)new_addr);
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_MOV: {
                set_operand_value(value, jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, dcpu);
                break;
            }
            
            case ZYDIS_MNEMONIC_XOR: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildXor(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                   value, "xor_tmp"), jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, dcpu);
                break;
            }
            
            case ZYDIS_MNEMONIC_ADD: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildAdd(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                    value, "add_tmp"), jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, dcpu);
                break;
            }
            
            case ZYDIS_MNEMONIC_SUB: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildSub(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                    value, "sub_tmp"), jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, dcpu);
                break;
            }
              
            case ZYDIS_MNEMONIC_SYSCALL: {
                  LLVMValueRef args[] = { jcontext->cpu_ptr };
                  LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->syscall_handler, args, 1, "");
                  
                  if (dcpu->gprs[0] == 60) {   // sys_exit
                      offset = phdr->p_filesz; // break "while"
                  }
                  break;
            }
            
            case ZYDIS_MNEMONIC_INT: {
                  if (zcontext->operands[0].imm.value.u == 0x80) {
                      LLVMValueRef args[] = { jcontext->cpu_ptr };
                      LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->int80_handler, args, 1, "");
                      
                      if (dcpu->gprs[0] == 1) {   // sys_exit
                          offset = phdr->p_filesz; // break "while"
                      }
                  }
                  break;
            }
            
            default: {
                  printf("PANIC!!!\nUnsupported instruction: %s\n", ZydisMnemonicGetString(zcontext->instruction.mnemonic));
                  break;
            }
        }
        
        offset += zcontext->instruction.length;
        runtime_address += zcontext->instruction.length;
    }
    
    if (vector_size(*data) > 1) {
        vector_remove(*data, 1);
    } else {
        vector_remove(*data, 0);
    }
}
