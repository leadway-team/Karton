#include "karton.h"

LLVMTypeRef i64;

int main(int argc, char** argv) {
    printf("Karton Emu ; 02.2026\n");
    errno = 0;
    
    if (argc != 2) {
        printf("The number of arguments is strictly 2.");
        return 1;
    }
    
    FILE *fp = fopen("syscalls.json", "rb");
    if (fp == NULL) {
        printf("Open file error, internal error code 2, \"fopen\" error code: %s.\n", strerror(errno));
        return 2;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *data = malloc(fsize + 1);
    fread(data, 1, fsize, fp);
    fclose(fp);
    data[fsize] = 0;
    
    enum json_tokener_error jerr;
    jsoncalls = json_tokener_parse_verbose(data, &jerr);
    if (!jsoncalls) {
        printf("json-c error, internal error code -1, json-c error code %s.\n", json_util_get_last_err());
        return -1;
    }
    
    fp = fopen("ints80.json", "rb");
    if (fp == NULL) {
        printf("Open file error, internal error code 2, \"fopen\" error code: %s.\n", strerror(errno));
        return 2;
    }
    
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    data = malloc(fsize + 1);
    fread(data, 1, fsize, fp);
    fclose(fp);
    data[fsize] = 0;
    
    jsonints = json_tokener_parse_verbose(data, &jerr);
    if (!jsonints) {
        printf("json-c error, internal error code -1, json-c error code %s.\n", json_util_get_last_err());
        return -1;
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
    
    struct stat st;
    int fst = fstat(fd, &st);
    if (fst < 0) {
        printf("fstat error, internal error code 2, fstat error code %d.\n", fst); 
        return 2;
    }
    size_t file_size = st.st_size;
    
    uint8_t* raw_bin = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (raw_bin == MAP_FAILED) {
        printf("mmap error, internal error code 2.\n"); 
        return 2;
    }
    
    Elf *e = elf_memory((char*)raw_bin, file_size);
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
    
    CPUState cpu = {0};
    LLVMTypeRef cpu_struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), "CPUState");
    
    i64 = LLVMInt64Type();
    
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
    
    LLVMTypeRef param_types[] = { cpu_ptr_type };
    LLVMTypeRef func_type = LLVMFunctionType(LLVMVoidType(), param_types, 1, 0);
    LLVMValueRef syscall_handler = LLVMAddFunction(mod, "helper_syscall", func_type);
    LLVMValueRef int80_handler = LLVMAddFunction(mod, "helper_int80", func_type);
    
    ZyanU64 entry_point = ehdr.e_entry;
    printf("Preparing is done 🎉\n");
    
    #ifdef DEBUG
    printf("Entry point address: %lu\n", entry_point);
    #endif
    
    ZyanUSize phnum;
    elf_getphdrnum(e, &phnum);
    GElf_Phdr phdr;
    
    for (ZyanUSize i = 0; i < phnum; i++) {
        gelf_getphdr(e, i, &phdr);
        
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            #ifdef DEBUG
            printf("EXEC SECTION №%zu ; SIZE %lu \n", i, phdr.p_memsz);
            #endif
            
            ZyanU8 *data = malloc(phdr.p_filesz);
            lseek(fd, phdr.p_offset, SEEK_SET);
            read(fd, data, phdr.p_filesz);
            
            ZyanU64 entry_offset = entry_point - phdr.p_vaddr;
            if (entry_offset < phdr.p_filesz) {
                #ifdef DEBUG
                printf("ENTRY OFFSET %lu\n", entry_offset);
                #endif
                ZydisDecoder decoder;
                ZydisDecoderInit(&decoder, mode, width);
                
                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                
                ZyanUSize offset = entry_offset;
                ZyanU64 runtime_address = entry_point; // Only for debug (temporary?)
                
                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                
                CPUState dcpu = {0};
                dcpu.rip = entry_point;
                
                while (offset < phdr.p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, phdr.p_filesz - offset, &instruction, operands))) {
                    #ifdef DEBUG
                    printf("%016" PRIX64 "  ", runtime_address);
                    
                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
                    puts(buffer);
                    #endif
                    
                    LLVMValueRef value = get_operand_value(builder, &operands[1], cpu_ptr, cpu_struct_type, &phdr, raw_bin);
                    
                    switch (instruction.mnemonic) {
                        case ZYDIS_MNEMONIC_MOV: {
                            set_operand_value(value, builder, &operands[0], cpu_ptr, cpu_struct_type, &dcpu);
                            break;
                        }
                        
                        case ZYDIS_MNEMONIC_XOR: {
                            int reg_idx = get_register_index(operands[0].reg.value);
                            LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                            set_operand_value(LLVMBuildXor(builder, LLVMBuildLoad2(builder, i64, reg_ptr, "load_tmp"), 
                                                                value, "xor_tmp"), builder, &operands[0], cpu_ptr, cpu_struct_type, &dcpu);
                            break;
                        }
                        
                        case ZYDIS_MNEMONIC_ADD: {
                            int reg_idx = get_register_index(operands[0].reg.value);
                            LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                            set_operand_value(LLVMBuildAdd(builder, LLVMBuildLoad2(builder, i64, reg_ptr, "load_tmp"), 
                                                                value, "add_tmp"), builder, &operands[0], cpu_ptr, cpu_struct_type, &dcpu);
                            break;
                        }
                        
                        case ZYDIS_MNEMONIC_SUB: {
                            int reg_idx = get_register_index(operands[0].reg.value);
                            LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                            set_operand_value(LLVMBuildSub(builder, LLVMBuildLoad2(builder, i64, reg_ptr, "load_tmp"), 
                                                                value, "sub_tmp"), builder, &operands[0], cpu_ptr, cpu_struct_type, &dcpu);
                            break;
                        }
                        
                        case ZYDIS_MNEMONIC_SYSCALL: {
                            LLVMValueRef args[] = { cpu_ptr };
                            LLVMBuildCall2(builder, func_type, syscall_handler, args, 1, "");
                            
                            if (dcpu.gprs[0] == 60) {   // sys_exit
                                offset = phdr.p_filesz; // break "while"
                            }
                            break;
                        }
                        
                        case ZYDIS_MNEMONIC_INT: {
                            if (operands[0].imm.value.u == 0x80) {
                                LLVMValueRef args[] = { cpu_ptr };
                                LLVMBuildCall2(builder, func_type, int80_handler, args, 1, "");
                                
                                if (dcpu.gprs[0] == 1) {   // sys_exit
                                    offset = phdr.p_filesz; // break "while"
                                }
                            }
                            break;
                        }
                        
                        default: {
                            printf("PANIC!!!\nUnsupported instruction: %s\n", ZydisMnemonicGetString(instruction.mnemonic));
                            break;
                        }
                    }
                    
                    offset += instruction.length;
                    runtime_address += instruction.length;
                }
            }
            
            free(data);
        }
    }
    
    LLVMBuildRetVoid(builder);
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    
    LLVMOrcLLJITRef JIT;
    LLVMErrorRef Err;
    
    LLVMOrcLLJITBuilderRef JITBuilder = LLVMOrcCreateLLJITBuilder();
    Err = LLVMOrcCreateLLJIT(&JIT, JITBuilder);
    
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    LLVMOrcJITDylibRef MainJD = LLVMOrcLLJITGetMainJITDylib(JIT);
    
    LLVMOrcSymbolStringPoolEntryRef S_syscall = LLVMOrcLLJITMangleAndIntern(JIT, "helper_syscall");
    LLVMOrcSymbolStringPoolEntryRef S_int80 = LLVMOrcLLJITMangleAndIntern(JIT, "helper_int80");
    LLVMJITSymbolFlags Flags = { LLVMJITSymbolGenericFlagsExported, 0 };
    LLVMOrcRetainSymbolStringPoolEntry(S_syscall);
    LLVMOrcRetainSymbolStringPoolEntry(S_int80);
    
    LLVMOrcCSymbolMapPair Symbols[] = {
        { S_syscall, { (LLVMOrcExecutorAddress)&helper_syscall, Flags } },
        { S_int80,   { (LLVMOrcExecutorAddress)&helper_int80, Flags } }
    };
    
    LLVMOrcMaterializationUnitRef MU = LLVMOrcAbsoluteSymbols(Symbols, 2);
    Err = LLVMOrcJITDylibDefine(MainJD, MU);
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    #ifdef DEBUG
    printf("---- DEBUG: GENERATED IR: ----\n");
    LLVMDumpModule(mod);
    #endif
    
    LLVMOrcThreadSafeContextRef TSCtx = LLVMOrcCreateNewThreadSafeContext();
    LLVMOrcThreadSafeModuleRef TSM = LLVMOrcCreateNewThreadSafeModule(mod, TSCtx);
    
    Err = LLVMOrcLLJITAddLLVMIRModule(JIT, MainJD, TSM);
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    LLVMOrcExecutorAddress func_ptr;
    Err = LLVMOrcLLJITLookup(JIT, &func_ptr, "start");
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    void (*compiled_start)(CPUState*) = (void (*)(CPUState*))func_ptr;
    
    #ifdef DEBUG
    printf("---- DEBUG: PREPARATIONS FOR JIT - DONE. ----\n");
    #endif
    
    printf("Starting JIT execution...\n");
    compiled_start(&cpu);
        
    LLVMOrcReleaseSymbolStringPoolEntry(S_syscall);
    LLVMOrcReleaseSymbolStringPoolEntry(S_int80);
    LLVMDisposeBuilder(builder);
    LLVMOrcDisposeLLJIT(JIT);
    LLVMOrcDisposeThreadSafeContext(TSCtx);
    elf_end(e);
    close(fd);
    return 0;
}
