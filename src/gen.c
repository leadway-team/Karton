#include "karton.h"

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
