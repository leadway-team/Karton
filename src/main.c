#include "karton.h"

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
    uint64_t rax = cpu->gprs[0]; // RAX
    if (rax == 60) { // sys_exit
        printf("Exit called with code %ld\n", cpu->gprs[7]); // RDI
        //exit(cpu->gprs[7]);
    }
}

int main(int argc, char** argv) {
    printf("Karton Emu ; 02.2026\n");
    
    if (argc != 2) {
        printf("The number of arguments is strictly 2.");
        return 1;
    }
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("Libelf error, internal error code 1.\n");
        return 1;
    }
    
    int fd = open(argv[1], O_RDONLY, 0);
    if (fd < 0) {
        printf("Open file error, internal error code 2, \"open\" error code %d.\n", fd);
        return 2;
    }
    
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (e == NULL) {
        printf("Libelf error, internal error code 3.\n");
        return 3;
    }
    
    if (elf_kind(e) != ELF_K_ELF) {
        printf("Not ELF file, internal error code 3.\n");
        return 3;
    }
    
    GElf_Ehdr ehdr;
    if (gelf_getehdr(e, &ehdr) == NULL) {
        printf("Libelf error, internal error code 4.\n");
        return 4;
    }
    
    if (ehdr.e_machine != EM_X86_64 && ehdr.e_machine != EM_386) {
        printf("Not x86_64 or x86 executable, internal error code 5.\n");
        return 5;
    }
    
    ZyanU32 mode = (ehdr.e_machine == EM_X86_64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    ZyanU32 width = (ehdr.e_machine == EM_X86_64) ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        printf("Not executable file, internal error code 6.\n");
        return 6;
    }
    
    printf("First step is complete.\n");
    
    CPUState cpu = {0};
    LLVMTypeRef i64 = LLVMInt64Type();
    LLVMTypeRef cpu_struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), "CPUState");
    
    LLVMTypeRef array_type = LLVMArrayType(i64, 16);
    LLVMTypeRef fields[] = { array_type, i64 };
    LLVMStructSetBody(cpu_struct_type, fields, 2, 0);
    LLVMTypeRef cpu_ptr_type = LLVMPointerType(cpu_struct_type, 0);
    
    LLVMModuleRef mod = LLVMModuleCreateWithName("karton_module");
    LLVMTypeRef ret_type = LLVMFunctionType(LLVMVoidType(), &cpu_ptr_type, 1, 0);
    LLVMValueRef func = LLVMAddFunction(mod, "start", ret_type);
    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(func, "entry");
    LLVMBuilderRef builder = LLVMCreateBuilder();
    LLVMPositionBuilderAtEnd(builder, entry);
    
    LLVMValueRef cpu_ptr = LLVMGetParam(func, 0);
    LLVMValueRef indices[] = {
        LLVMConstInt(LLVMInt32Type(), 0, 0),
        LLVMConstInt(LLVMInt32Type(), 0, 0),
        LLVMConstInt(LLVMInt32Type(), 0, 0)
    };
    
    LLVMTypeRef param_types[] = { cpu_ptr_type };
    LLVMTypeRef func_type = LLVMFunctionType(LLVMVoidType(), param_types, 1, 0);
    LLVMValueRef syscall_handler = LLVMAddFunction(mod, "helper_syscall", func_type);
    
    ZyanU64 entry_point = ehdr.e_entry;
    printf("Preparing is done 🎉\nEntry point address: %lu\n", entry_point);
    
    ZyanUSize phnum;
    elf_getphdrnum(e, &phnum);
    GElf_Phdr phdr;
    
    for (ZyanUSize i = 0; i < phnum; i++) {
        gelf_getphdr(e, i, &phdr);
        
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            printf("EXEC SECTION №%zu ; SIZE %lu \n", i, phdr.p_memsz);
            
            ZyanU8 *data = malloc(phdr.p_filesz);
            lseek(fd, phdr.p_offset, SEEK_SET);
            read(fd, data, phdr.p_filesz);
            
            ZyanU64 entry_offset = entry_point - phdr.p_vaddr;
            if (entry_offset < phdr.p_filesz) {
                printf("ENTRY OFFSET %lu\n", entry_offset);
                ZydisDecoder decoder;
                ZydisDecoderInit(&decoder, mode, width);
                
                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                
                ZyanUSize offset = entry_offset;
                ZyanU64 runtime_address = entry_point;
                
                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                
                while (offset < phdr.p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, phdr.p_filesz - offset, &instruction, operands))) {
                    printf("%016" PRIX64 "  ", runtime_address);
                    
                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
                    puts(buffer);
                    
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                        if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            int reg_idx = get_register_index(operands[0].reg.value);
                            if (reg_idx != -1) {
                                LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                LLVMBuildStore(builder, LLVMConstInt(i64, operands[1].imm.value.s, 0), reg_ptr);
                            }
                        }
                    }
                    
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
                        LLVMValueRef args[] = { cpu_ptr };
                        LLVMBuildCall2(builder, func_type, syscall_handler, args, 1, "");
                    }
                    
                    offset += instruction.length;
                    runtime_address += instruction.length;
                }
            }
            
            free(data);
        }
    }
    
    LLVMBuildRetVoid(builder);
    LLVMLinkInMCJIT();
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    
    LLVMExecutionEngineRef engine;
    
    char *error = NULL;
    if (LLVMCreateExecutionEngineForModule(&engine, mod, &error) != 0) {
        printf("Execution engine error, internal error code 6, engine error code %s.\n", error);
        return 6;
    }
    LLVMAddGlobalMapping(engine, syscall_handler, &helper_syscall);
    
    uintptr_t func_ptr = (uintptr_t)LLVMGetFunctionAddress(engine, "start");
    void (*compiled_start)(CPUState*) = (void (*)(CPUState*))func_ptr;
    
    printf("Starting JIT execution...\n");
    compiled_start(&cpu);
    
    printf("No segfault? Uh oh, RDI: %ld\n", cpu.gprs[7]);
    
    LLVMDumpModule(mod);
    
    LLVMDisposeBuilder(builder);
    LLVMDisposeExecutionEngine(engine);
    elf_end(e);
    close(fd);
    return 0;
}
