#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <Zydis/Zydis.h>
#include <libelf.h>
#include <gelf.h>

#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>

typedef struct {
    uint64_t gprs[16]; // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8-r15
    uint64_t rip;
} CPUState;
