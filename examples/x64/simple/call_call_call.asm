format ELF64 executable
entry _start

_start:    
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, len
    syscall
    
    call _start

msg db "OH YEAH, CALL!", 10
len = $ - msg
