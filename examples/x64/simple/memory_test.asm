format ELF64 executable
entry _start

_start:
    mov rdi, 10
    mov rsi, 20
    call add_numbers
    
    mov rdi, rax
    mov rax, 60        ; sys_exit
    syscall

add_numbers:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    
    mov [rbp - 8], rdi
    mov [rbp - 16], rsi
    
    mov rax, [rbp - 8]
    add rax, [rbp - 16]
    
    mov rsp, rbp
    pop rbp
    ret
