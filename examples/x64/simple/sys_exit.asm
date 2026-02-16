format ELF64 executable
entry _start

_start:
    mov rax, 60
    mov rdi, 43
    syscall
