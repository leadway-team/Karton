format ELF64 executable
entry _start

_start:
    mov rsi, str1
    mov rdi, str2
    mov rcx, 5
    repe cmpsb
    jz  .t1_ok
    mov rsi, fail1
    mov rdx, fail1_len
    jmp .t1_print
.t1_ok:
    mov rsi, ok1
    mov rdx, ok1_len
.t1_print:
    mov rax, 1
    mov rdi, 1
    syscall
    
    mov rsi, str1
    mov rdi, str3
    mov rcx, 5
    repe cmpsb
    jnz .t2_ok
    mov rsi, fail2
    mov rdx, fail2_len
    jmp .t2_print
.t2_ok:
    mov rsi, ok2
    mov rdx, ok2_len
.t2_print:
    mov rax, 1
    mov rdi, 1
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

str1 db "hello"
str2 db "hello"
str3 db "world"

ok1   db "[OK] REPE CMPSB: hello == hello, ZF=1", 10
ok1_len = $ - ok1
ok2   db "[OK] REPE CMPSB: hello != world, ZF=0", 10
ok2_len = $ - ok2
fail1 db "[FAIL] REPE CMPSB: should be equal", 10
fail1_len = $ - fail1
fail2 db "[FAIL] REPE CMPSB: should be different", 10
fail2_len = $ - fail2
