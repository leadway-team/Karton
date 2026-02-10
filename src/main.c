#include "karton.h"

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
    
    LLVMTypeRef param_types[] = { cpu_ptr_type };
    LLVMTypeRef func_type = LLVMFunctionType(LLVMVoidType(), param_types, 1, 0);
    LLVMValueRef syscall_handler = LLVMAddFunction(mod, "helper_syscall", func_type);
    
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
                
                while (offset < phdr.p_filesz && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, phdr.p_filesz - offset, &instruction, operands))) {
                    #ifdef DEBUG
                    printf("%016" PRIX64 "  ", runtime_address);
                    
                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
                    puts(buffer);
                    #endif
                    
                    switch (instruction.mnemonic) {
                        case ZYDIS_MNEMONIC_MOV:
                            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                int reg_idx = get_register_index(operands[0].reg.value);
                                uint64_t tmp = operands[1].imm.value.s;
                                if (tmp >= phdr.p_vaddr && tmp < (phdr.p_vaddr + phdr.p_memsz)) {
                                    tmp = (uint64_t)access_quest(tmp, &phdr, raw_bin);
                                }
                                if (reg_idx != -1) {
                                    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                    LLVMBuildStore(builder, LLVMConstInt(i64, tmp, 0), reg_ptr);
                                    dcpu.gprs[reg_idx] = tmp;
                                }
                            } else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) { // not working?
                                int reg_idx = get_register_index(operands[0].reg.value);
                                if (reg_idx != -1) {
                                    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                    dcpu.gprs[reg_idx] = (uint64_t)access_quest(operands[1].mem.disp.value, &phdr, raw_bin);
                                    LLVMBuildStore(builder, LLVMConstInt(i64, dcpu.gprs[reg_idx], 0), reg_ptr);
                                }
                            } else {
                                int reg_idx  = get_register_index(operands[0].reg.value);
                                int reg_sidx = get_register_index(operands[1].reg.value);
                                if (reg_idx != -1 && reg_sidx) {
                                    LLVMValueRef reg_ptr1 = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                    LLVMValueRef reg_ptr2 = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_sidx);
                                    LLVMBuildStore(builder, LLVMBuildLoad2(builder, i64, reg_ptr2, "reg_ptr2"), reg_ptr1);
                                    dcpu.gprs[reg_idx] = dcpu.gprs[reg_sidx];
                                }
                            }
                            break;
                        
                        case ZYDIS_MNEMONIC_XOR:
                            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                int reg_idx = get_register_index(operands[0].reg.value);
                                if (reg_idx != -1) {
                                    LLVMValueRef reg_ptr = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                    LLVMBuildStore(builder, LLVMBuildXor(builder, LLVMBuildLoad2(builder, i64, reg_ptr, "load_tmp"), 
                                                                LLVMConstInt(i64, operands[1].imm.value.s, 0), "xor_tmp"), reg_ptr);
                                    dcpu.gprs[reg_idx] = dcpu.gprs[reg_idx] ^ operands[1].imm.value.s;
                                }
                            } else {
                                int reg_idx  = get_register_index(operands[0].reg.value);
                                int reg_sidx = get_register_index(operands[1].reg.value);
                                if (reg_idx != -1 && reg_sidx) {
                                    LLVMValueRef reg_ptr1 = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_idx);
                                    LLVMValueRef reg_ptr2 = get_reg_ptr(builder, cpu_ptr, cpu_struct_type, reg_sidx);
                                    LLVMBuildStore(builder, LLVMBuildXor(builder, LLVMBuildLoad2(builder, i64, reg_ptr1, "load_tmp"), 
                                                                       LLVMBuildLoad2(builder, i64, reg_ptr2, "reg_ptr2"), "xor_tmp"), reg_ptr1);
                                    dcpu.gprs[reg_idx] = dcpu.gprs[reg_idx] ^ dcpu.gprs[reg_sidx];
                                }
                            }
                            break;
                        
                        case ZYDIS_MNEMONIC_SYSCALL:
                            LLVMValueRef args[] = { cpu_ptr };
                            LLVMBuildCall2(builder, func_type, syscall_handler, args, 1, "");
                            
                            if (dcpu.gprs[0] == 60) {   // sys_exit
                                offset = phdr.p_filesz; // break "while"
                            }
                            break;
                        
                        default:
                            printf("PANIC!!!\nUnsupported instruction: %s\n", ZydisMnemonicGetString(instruction.mnemonic));
                            break;
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
    
    #ifdef DEBUG
    printf("---- DEBUG: PREPARATIONS FOR JIT - DONE. GENERATED IR: ----\n");
    LLVMDumpModule(mod);
    #endif
    
    printf("Starting JIT execution...\n");
    compiled_start(&cpu);
        
    LLVMDisposeBuilder(builder);
    LLVMDisposeExecutionEngine(engine);
    elf_end(e);
    close(fd);
    return 0;
}
