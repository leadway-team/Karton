format ELF64 executable
entry _start

_start:
    cld
    
    mov rsi, src
    mov rdi, dst
    mov rcx, 15
    rep movsb
    
    mov rax, 1
    mov rdi, 1
    mov rsi, dst
    mov rdx, 15
    syscall
    
    mov rax, 60
    xor rdi, rdi
    syscall

src db "Hello, Karton!", 10
dst db 15 dup(0)
