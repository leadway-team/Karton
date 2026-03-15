#include "karton.h"

LLVMTypeRef i64;
GElf_Phdr* phdrs;
CPUState cpu = {0};

int main(int argc, char** argv) {
    printf("Karton Emu ; 03.2026\n");
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
    
    char* jdata = malloc(fsize + 1);
    fread(jdata, 1, fsize, fp);
    fclose(fp);
    jdata[fsize] = 0;
    
    enum json_tokener_error jerr;
    jsoncalls = json_tokener_parse_verbose(jdata, &jerr);
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
    
    jdata = malloc(fsize + 1);
    fread(jdata, 1, fsize, fp);
    fclose(fp);
    jdata[fsize] = 0;
    
    jsonints = json_tokener_parse_verbose(jdata, &jerr);
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
    
    JITCtx jcontext;
    jcontext.mod = LLVMModuleCreateWithName("karton_module");
    
    jcontext.cpu_struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), "CPUState");
    
    i64 = LLVMInt64Type();
    
    LLVMTypeRef array_type = LLVMArrayType(i64, 16);
    LLVMTypeRef fields[] = { array_type, i64 };
    LLVMStructSetBody(jcontext.cpu_struct_type, fields, 2, 0);
    jcontext.cpu_ptr_type = LLVMPointerType(jcontext.cpu_struct_type, 0);
    
    LLVMTypeRef param_types[] = { jcontext.cpu_ptr_type };
    jcontext.func_type = LLVMFunctionType(LLVMVoidType(), param_types, 1, 0);
    jcontext.syscall_handler = LLVMAddFunction(jcontext.mod, "helper_syscall", jcontext.func_type);
    jcontext.int80_handler = LLVMAddFunction(jcontext.mod, "helper_int80", jcontext.func_type);
    
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMErrorRef Err;
    
    LLVMOrcLLJITBuilderRef JITBuilder = LLVMOrcCreateLLJITBuilder();
    Err = LLVMOrcCreateLLJIT(&jcontext.JIT, JITBuilder);
    
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    jcontext.MainJD = LLVMOrcLLJITGetMainJITDylib(jcontext.JIT);
    
    LLVMOrcSymbolStringPoolEntryRef S_syscall = LLVMOrcLLJITMangleAndIntern(jcontext.JIT, "helper_syscall");
    LLVMOrcSymbolStringPoolEntryRef S_int80 = LLVMOrcLLJITMangleAndIntern(jcontext.JIT, "helper_int80");
    LLVMJITSymbolFlags Flags = { LLVMJITSymbolGenericFlagsExported, 0 };
    LLVMOrcRetainSymbolStringPoolEntry(S_syscall);
    LLVMOrcRetainSymbolStringPoolEntry(S_int80);
    
    LLVMOrcCSymbolMapPair Symbols[] = {
        { S_syscall, { (LLVMOrcExecutorAddress)&helper_syscall, Flags } },
        { S_int80,   { (LLVMOrcExecutorAddress)&helper_int80, Flags } }
    };
    
    LLVMOrcMaterializationUnitRef MU = LLVMOrcAbsoluteSymbols(Symbols, 2);
    Err = LLVMOrcJITDylibDefine(jcontext.MainJD, MU);
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    ZyanU64 entry_point = ehdr.e_entry;
    printf("Preparing is done 🎉\n");
    
    #ifdef DEBUG
    printf("Entry point address: %lu\n", entry_point);
    #endif
    
    phdrs = vector_create();
    
    ZyanUSize phnum;
    elf_getphdrnum(e, &phnum);
    
    ZydisCtx zcontext;
    ZydisDecoderInit(&zcontext.decoder, mode, width);
    ZydisFormatterInit(&zcontext.formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    
    for (ZyanUSize i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        gelf_getphdr(e, i, &phdr);
        vector_add(&phdrs, phdr);
    }
    
    ZyanU8** data = vector_create();
    vector_add(&data, (ZyanU8*)entry_point);
    
    GElf_Phdr phdr = *find_phdr(phnum, entry_point);
    
    while (vector_size(data)) {
        init_llir(&jcontext);
        gen_ir(&data, &phdr, phnum, raw_bin, &zcontext, &jcontext);
        run_ir(&jcontext);
    }
    
    vector_free(&phdrs);
    LLVMOrcDisposeLLJIT(jcontext.JIT);
    LLVMOrcReleaseSymbolStringPoolEntry(S_syscall);
    LLVMOrcReleaseSymbolStringPoolEntry(S_int80);
    elf_end(e);
    close(fd);
    return 0;
}
