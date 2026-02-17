format ELF64 executable
entry _start

_start:
    mov rax, 60
    mov rdi, 43
    add rdi, 57
    sub rdi, 31
    syscall
