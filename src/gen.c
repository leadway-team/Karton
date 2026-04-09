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

void set_operand_value(LLVMValueRef value, LLVMBuilderRef builder, int reg, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type) {
    int reg_idx = get_register_index(reg);
    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
    LLVMBuildStore(builder, value, reg_ptr);
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
            value = get_operand_value(jcontext->builder, &zcontext->operands[0], jcontext->cpu_ptr, jcontext->cpu_struct_type, phdr, raw_bin);
        } else if (zcontext->instruction.operand_count_visible >= 2) {
            value = get_operand_value(jcontext->builder, &zcontext->operands[1], jcontext->cpu_ptr, jcontext->cpu_struct_type, phdr, raw_bin);
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
                
                set_operand_value(LLVMConstInt(i64, new_addr, 0), jcontext->builder, ZYDIS_REGISTER_RIP, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                
                offset = phdr->p_filesz; // break "while"
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
                
                set_operand_value(LLVMConstInt(i64, new_addr, 0), jcontext->builder, ZYDIS_REGISTER_RIP, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                
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
                set_operand_value(ret_val, jcontext->builder, ZYDIS_REGISTER_RIP, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                
                offset = phdr->p_filesz; // break "while"
                break;
            }
            
            case ZYDIS_MNEMONIC_MOV: {
                set_operand_value(value, jcontext->builder, zcontext->operands[0].reg.value, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                break;
            }
            
            case ZYDIS_MNEMONIC_XOR: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildXor(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                   value, "xor_tmp"), jcontext->builder, zcontext->operands[0].reg.value, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                break;
            }
            
            case ZYDIS_MNEMONIC_ADD: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildAdd(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                    value, "add_tmp"), jcontext->builder, zcontext->operands[0].reg.value, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                break;
            }
            
            case ZYDIS_MNEMONIC_SUB: {
                int reg_idx = get_register_index(zcontext->operands[0].reg.value);
                LLVMValueRef reg_ptr = get_reg_ptr(jcontext->builder, jcontext->cpu_ptr, jcontext->cpu_struct_type, reg_idx);
                set_operand_value(LLVMBuildSub(jcontext->builder, LLVMBuildLoad2(jcontext->builder, i64, reg_ptr, "load_tmp"), 
                                                    value, "sub_tmp"), jcontext->builder, zcontext->operands[0].reg.value, jcontext->cpu_ptr, jcontext->cpu_struct_type);
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
                set_operand_value(pop_val, jcontext->builder, zcontext->operands[0].reg.value, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                break;
            }
              
            case ZYDIS_MNEMONIC_SYSCALL: {
                  LLVMValueRef args[] = { jcontext->cpu_ptr };
                  LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->syscall_handler, args, 1, "");
                  
                  set_operand_value(LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0), 
                      jcontext->builder, ZYDIS_REGISTER_RIP, jcontext->cpu_ptr, jcontext->cpu_struct_type);
                  
                  offset = phdr->p_filesz; // break "while"
                  break;
            }
            
            case ZYDIS_MNEMONIC_INT: {
                  if (zcontext->operands[0].imm.value.u == 0x80) {
                      LLVMValueRef args[] = { jcontext->cpu_ptr };
                      LLVMBuildCall2(jcontext->builder, jcontext->func_type, jcontext->int80_handler, args, 1, "");
                      
                      set_operand_value(LLVMConstInt(i64, runtime_address + zcontext->instruction.length, 0), 
                          jcontext->builder, ZYDIS_REGISTER_EIP, jcontext->cpu_ptr, jcontext->cpu_struct_type);
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
