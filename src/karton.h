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

#include "vec.h"

#include <Zydis/Zydis.h>
#include <libelf.h>
#include <gelf.h>

#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Orc.h>
#include <llvm-c/LLJIT.h>

typedef struct {
    uint64_t gprs[16]; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15 | eax, ecx, ..etc
    uint64_t rip;
} CPUState;

typedef struct {
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
} ZydisCtx;

typedef struct {
    LLVMOrcLLJITRef JIT;
    LLVMOrcJITDylibRef MainJD;
    LLVMValueRef cpu_ptr;
    LLVMTypeRef cpu_struct_type;
    LLVMTypeRef cpu_ptr_type;
    LLVMModuleRef mod;
    LLVMBuilderRef builder;
    LLVMValueRef syscall_handler;
    LLVMValueRef int80_handler;
    LLVMTypeRef func_type;
    LLVMOrcThreadSafeContextRef TSCtx;
} JITCtx;

/* see main.c */
extern LLVMTypeRef i64;
extern GElf_Phdr* phdrs;
extern CPUState cpu;

/* see exec.c */
extern struct json_object *jsoncalls;
extern struct json_object *jsonints;
void helper_syscall(CPUState *cpu);
void helper_int80(CPUState *cpu);
void init_llir(JITCtx *jcontext, char* func_name);
void run_ir(JITCtx *jcontext, char* func_name);

/* see gen.c */
GElf_Phdr* find_phdr(ZyanUSize phnum, uint64_t addr);
void* access_quest(uint64_t guest_addr, GElf_Phdr *phdr, uint8_t *raw_bin);
LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx);
int get_register_index(ZydisRegister reg);
LLVMValueRef get_operand_value(LLVMBuilderRef builder, ZydisDecodedOperand *operand, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type, GElf_Phdr *phdr, uint8_t *raw_bin);
void set_operand_value(LLVMValueRef value, LLVMBuilderRef builder, int reg, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_struct_type);
void gen_ir(GElf_Phdr *phdr, ZyanUSize phnum, uint8_t *raw_bin, ZydisCtx *zcontext, JITCtx *jcontext);

