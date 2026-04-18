#include "karton.h"

LLVMTypeRef i64;
LLVMTypeRef i8;
GElf_Phdr* phdrs;
CPUState cpu = {0};
Cache block_cache[65536] = {0};
uint8_t  *mem_image;
uint64_t  base_vaddr;

int main(int argc, char** argv) {
    printf("Karton Emu ; 04.2026\n");
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
    
    int fd = open(argv[1], O_RDONLY, 0);
    if (fd < 0) {
        printf("Open file error, internal error code 2, \"open\" error code %d.\n", fd);
        return 2;
    }
    
    char *binary_path = strdup(argv[1]);
    char *dir = dirname(binary_path);
    
    if (chdir(dir) != 0) {
        printf("chdir error: %s\n", strerror(errno));
        return 2;
    }
    
    free(binary_path);
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("Libelf error, internal error code 1.\n");
        return 1;
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
    
    ZyanUSize phnum;
    elf_getphdrnum(e, &phnum);
    
    base_vaddr = UINT64_MAX;
    uint64_t top_vaddr = 0;
    for (ZyanUSize i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        gelf_getphdr(e, i, &phdr);
        if (phdr.p_type != PT_LOAD) continue;
        if (phdr.p_vaddr < base_vaddr) base_vaddr = phdr.p_vaddr;
        if (phdr.p_vaddr + phdr.p_memsz > top_vaddr) top_vaddr = phdr.p_vaddr + phdr.p_memsz;
    }
    
    mem_image = calloc(1, top_vaddr - base_vaddr);
    if (!mem_image) {
        printf("calloc error, internal error code 2.\n");
        return 2;
    }
    
    for (ZyanUSize i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        gelf_getphdr(e, i, &phdr);
        if (phdr.p_type != PT_LOAD) continue;
        memcpy(mem_image + (phdr.p_vaddr - base_vaddr),
               raw_bin   +  phdr.p_offset,
               phdr.p_filesz);
    }
    
    phdrs = vector_create();
    for (ZyanUSize i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        gelf_getphdr(e, i, &phdr);
        vector_add(&phdrs, phdr);
    }
    
    ZyanU64 entry_point = ehdr.e_entry;
    
    elf_end(e);
    close(fd);
    munmap(raw_bin, file_size);
    raw_bin = NULL;
    
    cpu.gprs[4] = (uint64_t)mmap(NULL, 8388608, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) + 8388608;
    
    JITCtx jcontext;
    jcontext.mod = LLVMModuleCreateWithName("karton_module");
    
    jcontext.cpu_struct_type = LLVMStructCreateNamed(LLVMGetGlobalContext(), "CPUState");
    
    i64 = LLVMInt64Type();
    i8  = LLVMInt8Type();
    
    LLVMTypeRef array_type = LLVMArrayType(i64, 16);
    LLVMTypeRef fields[]   = { array_type, i64, i8, i8, i8, i8, i8 };
    LLVMStructSetBody(jcontext.cpu_struct_type, fields, 7, 0);
    jcontext.cpu_ptr_type = LLVMPointerType(jcontext.cpu_struct_type, 0);
    
    LLVMTypeRef param_types[] = { jcontext.cpu_ptr_type };
    jcontext.func_type       = LLVMFunctionType(LLVMVoidType(), param_types, 1, 0);
    jcontext.syscall_handler = LLVMAddFunction(jcontext.mod, "helper_syscall", jcontext.func_type);
    jcontext.int80_handler   = LLVMAddFunction(jcontext.mod, "helper_int80",   jcontext.func_type);
    
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
    LLVMOrcSymbolStringPoolEntryRef S_int80   = LLVMOrcLLJITMangleAndIntern(jcontext.JIT, "helper_int80");
    LLVMJITSymbolFlags Flags = { LLVMJITSymbolGenericFlagsExported, 0 };
    LLVMOrcRetainSymbolStringPoolEntry(S_syscall);
    LLVMOrcRetainSymbolStringPoolEntry(S_int80);
    
    LLVMOrcCSymbolMapPair Symbols[] = {
        { S_syscall, { (LLVMOrcExecutorAddress)&helper_syscall, Flags } },
        { S_int80,   { (LLVMOrcExecutorAddress)&helper_int80,   Flags } }
    };
    
    LLVMOrcMaterializationUnitRef MU = LLVMOrcAbsoluteSymbols(Symbols, 2);
    Err = LLVMOrcJITDylibDefine(jcontext.MainJD, MU);
    if (Err) {
        printf("LLJIT creation error, internal error code 6, LLJIT error code %s.\n", LLVMGetErrorMessage(Err));
        return 6;
    }
    
    ZydisCtx zcontext;
    ZydisDecoderInit(&zcontext.decoder, mode, width);
    ZydisFormatterInit(&zcontext.formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    
    cpu.rip = entry_point;
    
    jcontext.TSCtx = LLVMOrcCreateNewThreadSafeContext();
    
    printf("Preparing is done 🎉\n");
    
    #ifdef DEBUG
    printf("Entry point address: 0x%lx\n", entry_point);
    printf("base_vaddr: 0x%lx  top_vaddr: 0x%lx  image_size: 0x%lx\n",
           base_vaddr, top_vaddr, top_vaddr - base_vaddr);
    #endif
    
    signal(SIGPIPE, SIG_IGN);
    while (1) {
        Cache *entry = cache_lookup(cpu.rip);
        
        if (entry->rip != cpu.rip) {
            char func_name[64];
            snprintf(func_name, sizeof(func_name), "block_%lx", cpu.rip);
            
            GElf_Phdr *cur_phdr = find_phdr(phnum, cpu.rip);
            if (!cur_phdr) {
                printf("PANIC: rip 0x%lx outside any PT_LOAD segment\n", cpu.rip);
                break;
            }
            
            init_llir(&jcontext, func_name);
            gen_ir(cur_phdr, phnum, &zcontext, &jcontext);
            run_ir(&jcontext, func_name, entry);
        }
        
        entry->fn(&cpu);
    }
    
    LLVMOrcDisposeThreadSafeContext(jcontext.TSCtx);
    vector_free(&phdrs);
    free(mem_image);
    LLVMOrcDisposeLLJIT(jcontext.JIT);
    LLVMOrcReleaseSymbolStringPoolEntry(S_syscall);
    LLVMOrcReleaseSymbolStringPoolEntry(S_int80);
    return 0;
}
