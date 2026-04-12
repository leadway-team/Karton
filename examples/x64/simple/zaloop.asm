format ELF64 executable
entry _start

_start:
    mov rcx, 3
    mov rsi, msg
.loop:
    push rcx
    mov rax, 1
    mov rdi, 1
    mov rdx, len
    syscall
    pop rcx
    loop .loop

    mov rax, 60
    xor rdi, rdi
    syscall

msg db "zaloop!", 10
len = $ - msg
