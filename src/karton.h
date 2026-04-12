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
#include <libgen.h> 

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
    uint64_t gprs[16];
    uint64_t rip;
    uint8_t zf;
    uint8_t sf;
    uint8_t cf;
    uint8_t of;
    uint8_t df;
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
    uint8_t  *mem_image;
    uint64_t  base_vaddr;
} JITCtx;

typedef struct {
    uint64_t rip;
    void (*fn)(CPUState*);
} Cache;

/* see main.c */
extern LLVMTypeRef i64;
extern LLVMTypeRef i8;
extern GElf_Phdr* phdrs;
extern CPUState cpu;
extern Cache block_cache[65536];

/* see exec.c */
extern struct json_object *jsoncalls;
extern struct json_object *jsonints;
void helper_syscall(CPUState *cpu);
void helper_int80(CPUState *cpu);
Cache* cache_lookup(uint64_t rip);
void init_llir(JITCtx *jcontext, char* func_name);
void run_ir(JITCtx *jcontext, char* func_name, Cache *cache_entry);

/* see gen.c */
GElf_Phdr* find_phdr(ZyanUSize phnum, uint64_t addr);
void* access_quest(uint64_t guest_addr, uint8_t *mem_image, uint64_t base_vaddr);
LLVMValueRef get_reg_ptr(LLVMBuilderRef builder, LLVMValueRef cpu_ptr, LLVMTypeRef cpu_type, int reg_idx);
int get_register_index(ZydisRegister reg);
LLVMValueRef get_operand_value(JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address, ZyanUSize phnum, uint8_t *mem_image, uint64_t base_vaddr);
void set_operand_value(LLVMValueRef value, JITCtx *jcontext, ZydisCtx *zcontext, ZydisDecodedOperand *operand, int64_t runtime_address);
void gen_ir(GElf_Phdr *phdr, ZyanUSize phnum, uint8_t *mem_image, uint64_t base_vaddr, ZydisCtx *zcontext, JITCtx *jcontext);
