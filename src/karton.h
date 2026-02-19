#pragma once
#define _GNU_SOURCE

#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <json-c/json.h>
#include <json-c/json_util.h>

#include <Zydis/Zydis.h>
#include <libelf.h>
#include <gelf.h>

#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>

typedef struct {
    uint64_t gprs[16]; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15 | eax, ecx, ..etc
    uint64_t rip;
} CPUState;

/* see karton.c */
extern LLVMTypeRef i64;
extern struct json_object *jsoncalls;
extern struct json_object *jsonints;
void helper_syscall(CPUState *cpu);
void helper_int80(CPUState *cpu);
int get_register_index(ZydisRegister reg);
LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx);
void* access_quest(uint64_t guest_addr, GElf_Phdr *phdr, uint8_t *raw_bin);
LLVMValueRef get_operand_value(LLVMBuilderRef builder, ZydisDecodedOperand *operands, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, GElf_Phdr *phdr, uint8_t *raw_bin);
void set_operand_value(LLVMValueRef value, LLVMBuilderRef builder, ZydisDecodedOperand *operands, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, CPUState *dcpu);
