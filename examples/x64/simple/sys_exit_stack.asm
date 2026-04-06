format ELF64 executable
entry _start

_start:
    mov rax, 60
    push 43
    push 64
    pop rdi
    syscall
