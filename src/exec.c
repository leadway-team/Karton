#include "karton.h"

struct json_object *jsoncalls;
struct json_object *jsonints;

void helper_syscall(CPUState *cpu) {
    uint64_t rax = cpu->gprs[0];
    uint64_t rdi = cpu->gprs[7];
    uint64_t rsi = cpu->gprs[6];
    uint64_t rdx = cpu->gprs[2];
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
                sargs[i] = (uint64_t)strtoull(string_arg, NULL, 10);
            }
        }
        cpu->gprs[0] = syscall(rax, sargs[0], sargs[1], sargs[2], sargs[3], sargs[4], sargs[5]);
    } else {
        printf("JSON file doesn't contain required syscall!\n");
        printf("Internal error code 7\n");
        exit(7);
    }
}

void helper_int80(CPUState *cpu) {
    uint64_t eax = cpu->gprs[0];
    uint64_t ebx = cpu->gprs[3];
    uint64_t ecx = cpu->gprs[1];
    uint64_t edx = cpu->gprs[2];
    uint64_t esi  = cpu->gprs[6];
    uint64_t edi  = cpu->gprs[7];
    uint64_t ebp = cpu->gprs[5];
    
    char eax_char[4];
    snprintf(eax_char, sizeof(eax_char), "%" PRIu64, eax);
    struct json_object *entry;
    if (json_object_object_get_ex(jsonints, eax_char, &entry)) {
        struct json_object *native, *argc, *args;
        
        json_object_object_get_ex(entry, "native", &native);
        json_object_object_get_ex(entry, "argc", &argc);
        json_object_object_get_ex(entry, "args", &args);
        
        // TODO: REMOVE THIS SHIT
        #ifdef DEBUG
        printf("DEBUG - x86   : %ld\n", eax);
        #endif
        eax = json_object_get_int(native);
        #ifdef DEBUG
        printf("      - arm64 : %ld\n", eax);
        printf("      - argc  : %d\n", json_object_get_int(argc));
        #endif
        
        int n_args = json_object_array_length(args);
        uint64_t sargs[6] = {0, 0, 0, 0, 0, 0};
        for (int i = 0; i < n_args; i++) {
            struct json_object *arg = json_object_array_get_idx(args, i);
            const char* string_arg = json_object_get_string(arg);
                   if (strcmp("ebx", string_arg) == 0) {
                sargs[i] = ebx;
            } else if (strcmp("ecx", string_arg) == 0) {
                sargs[i] = ecx;
            } else if (strcmp("edx", string_arg) == 0) {
                sargs[i] = edx;
            } else if (strcmp("esi", string_arg) == 0) {
                sargs[i] = esi;
            } else if (strcmp("edi", string_arg) == 0) {
                sargs[i] = edi;
            } else if (strcmp("ebp", string_arg) == 0) {
                sargs[i] = ebp;
            } else {
                sargs[i] = (uint64_t)strtoull(string_arg, NULL, 10);
            }
        }
        cpu->gprs[0] = syscall(eax, sargs[0], sargs[1], sargs[2], sargs[3], sargs[4], sargs[5]);
    } else {
        printf("JSON file doesn't contain required (32-bit) syscall!\n");
        printf("Internal error code 7\n");
        exit(7);
    }
}

Cache* cache_lookup(uint64_t rip) {
    uint32_t idx = (rip >> 2) & (65536 - 1);
    while (block_cache[idx].rip != 0 && block_cache[idx].rip != rip) {
        idx = (idx + 1) & (65536 - 1);
    }
    return &block_cache[idx];
}

void init_llir(JITCtx *jcontext, char* func_name) {
    jcontext->mod = LLVMModuleCreateWithName("karton_module");
    LLVMTypeRef ret_type = LLVMFunctionType(LLVMVoidType(), &jcontext->cpu_ptr_type, 1, 0);
    LLVMValueRef func = LLVMAddFunction(jcontext->mod, func_name, ret_type);
    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(func, "entry");
    
    jcontext->builder = LLVMCreateBuilder();
    LLVMPositionBuilderAtEnd(jcontext->builder, entry);
    jcontext->cpu_ptr = LLVMGetParam(func, 0);
}

void run_ir(JITCtx *jcontext, char* func_name, Cache *cache_entry) {
    LLVMBuildRetVoid(jcontext->builder);
    LLVMDisposeBuilder(jcontext->builder);
    
    LLVMErrorRef Err;
    LLVMOrcThreadSafeModuleRef TSM = LLVMOrcCreateNewThreadSafeModule(jcontext->mod, jcontext->TSCtx);
    Err = LLVMOrcLLJITAddLLVMIRModule(jcontext->JIT, jcontext->MainJD, TSM);
    if (Err) { printf("LLJIT error (add): %s\n", LLVMGetErrorMessage(Err)); exit(6); }
    
    LLVMOrcExecutorAddress func_ptr;
    Err = LLVMOrcLLJITLookup(jcontext->JIT, &func_ptr, func_name);
    if (Err) { printf("LLJIT error (lookup): %s\n", LLVMGetErrorMessage(Err)); exit(6); }
    
    cache_entry->rip = cpu.rip;
    cache_entry->fn  = (void(*)(CPUState*))func_ptr;
    
    jcontext->mod = NULL;
}
