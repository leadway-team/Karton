#include "karton.h"

struct json_object *jsoncalls;
LLVMTypeRef i64;

LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx) {
    LLVMValueRef indices[] = {
        LLVMConstInt(LLVMInt32Type(), 0, 0),
        LLVMConstInt(LLVMInt32Type(), 0, 0),
        LLVMConstInt(LLVMInt32Type(), reg_idx, 0)
    };
    return LLVMBuildInBoundsGEP2(builder, cpu_type, cpu_ptr, indices, 3, "reg_ptr");
}

int get_register_index(ZydisRegister reg) {
    if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_RDI) {
        return reg - ZYDIS_REGISTER_RAX;
    }
    if (reg >= ZYDIS_REGISTER_R8 && reg <= ZYDIS_REGISTER_R15) {
        return 8 + (reg - ZYDIS_REGISTER_R8);
    }
    
    return -1; 
}

void helper_syscall(CPUState *cpu) {
    uint64_t rax = cpu->gprs[0];
    uint64_t rdx = cpu->gprs[2];
    uint64_t rsi = cpu->gprs[6];
    uint64_t rdi = cpu->gprs[7];
    uint64_t r8  = cpu->gprs[8];
    uint64_t r9  = cpu->gprs[9];
    uint64_t r10 = cpu->gprs[10];
    
    char rax_char[4];
    snprintf(rax_char, sizeof(rax_char), "%" PRIu64, rax);
    struct json_object *entry;
    if (json_object_object_get_ex(jsoncalls, rax_char, &entry)) {
        struct json_object *native, *argc, *args;
        
        json_object_object_get_ex(entry, "native", &native);
        json_object_object_get_ex(entry, "argc", &argc);
        json_object_object_get_ex(entry, "args", &args);
        
        // TODO: REMOVE THIS SHIT
        #ifdef DEBUG
        printf("DEBUG - x86_64: %ld\n", rax);
        #endif
        rax = json_object_get_int(native);
        #ifdef DEBUG
        printf("      - arm64 : %ld\n", rax);
        printf("      - argc  : %d\n", json_object_get_int(argc));
        #endif
        
        int n_args = json_object_array_length(args);
        uint64_t sargs[6] = {0, 0, 0, 0, 0, 0};
        for (int i = 0; i < n_args; i++) {
            struct json_object *arg = json_object_array_get_idx(args, i);
            const char* string_arg = json_object_get_string(arg);
                   if (strcmp("rdx", string_arg) == 0) {
                sargs[i] = rdx;
            } else if (strcmp("rsi", string_arg) == 0) {
                sargs[i] = rsi;
            } else if (strcmp("rdi", string_arg) == 0) {
                sargs[i] = rdi;
            } else if (strcmp("r8", string_arg) == 0) {
                sargs[i] = r8;
            } else if (strcmp("r9", string_arg) == 0) {
                sargs[i] = r9;
            } else if (strcmp("r10", string_arg) == 0) {
                sargs[i] = r10;
            } else {
                char *endptr;
                sargs[i] = (uint64_t)strtoull(string_arg, &endptr, 10);
            }
        }
        
        syscall(rax, sargs[0], sargs[1], sargs[2], sargs[3], sargs[4], sargs[5]);
    } else {
        printf("JSON file doesn't contain required syscall!\n");
        printf("Internal error code 7\n");
        exit(7);
    }
}

void* access_quest(uint64_t guest_addr, GElf_Phdr *phdr, uint8_t *raw_bin) {
    uint64_t offset_in_segment = guest_addr - phdr->p_vaddr;
    uint64_t offset_in_file = phdr->p_offset + offset_in_segment;
    return (void*)(raw_bin + offset_in_file);
}

LLVMValueRef get_operand_value(LLVMBuilderRef builder, ZydisDecodedOperand *operand, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, GElf_Phdr *phdr, uint8_t *raw_bin) {
    switch (operand->type) {
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            ; // Compatibility with C11
            uint64_t tmp = operand->imm.value.s;
            if (tmp >= phdr->p_vaddr && tmp < (phdr->p_vaddr + phdr->p_memsz)) {
                tmp = (uint64_t)access_quest(tmp, phdr, raw_bin);
            }
            return LLVMConstInt(i64, tmp, 0);
            break;
        
        case ZYDIS_OPERAND_TYPE_MEMORY:
            return LLVMConstInt(i64, (uint64_t)access_quest(operand->mem.disp.value, phdr, raw_bin), 0);
            break;
        
        case ZYDIS_OPERAND_TYPE_REGISTER:
            ; // Compatibility with C11
            int reg_idx = get_register_index(operand->reg.value);
            LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
            return LLVMBuildLoad2(builder, i64, reg_ptr, "reg_ptr");
        
        default:
            return NULL;
            break;
    }
}

void set_operand_value(LLVMValueRef value, LLVMBuilderRef builder, ZydisDecodedOperand *operand, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, CPUState *dcpu) {
    int reg_idx = get_register_index(operand->reg.value);
    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
    LLVMBuildStore(builder, value, reg_ptr);
    dcpu->gprs[reg_idx] = LLVMConstIntGetSExtValue(value);
}
