#pragma once
#define _GNU_SOURCE

#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include <json-c/json.h>
#include <json-c/json_util.h>

#include <Zydis/Zydis.h>
#include <libelf.h>
#include <gelf.h>

#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>

typedef struct {
    uint64_t gprs[16]; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15
    uint64_t rip;
} CPUState;

/* see karton.c */
extern struct json_object *jsoncalls;
void helper_syscall(CPUState *cpu);
int get_register_index(ZydisRegister reg);
LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx);
