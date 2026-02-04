#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <Zydis/Zydis.h>
#include <libelf.h>
#include <gelf.h>

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
    
    ZyanU64 entry_point = ehdr.e_entry;
    printf("All checks done 🎉\nEntry point address: %lu\n", entry_point);
    
    ZyanUSize phnum;
    elf_getphdrnum(e, &phnum);
    GElf_Phdr phdr;
    
    int64_t rax = 0;
    
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
                            if (operands[0].reg.value == ZYDIS_REGISTER_RAX) {
                                //TODO: determine is signed or unsigned
                                rax = operands[1].imm.value.s;
                                //printf("RAX REDIFINED: %ld\n", rax);
                            }
                        }
                    }
                    
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
                        if (rax == 60) {
                            printf("sys_exit syscall ; program is ended\n");
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
    
    elf_end(e);
    close(fd);
    return 0;
}
