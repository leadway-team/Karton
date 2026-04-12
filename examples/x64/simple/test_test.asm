format ELF64 executable
entry _start

_start:
    xor rax, rax        ; rax = 0
    test rax, rax
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

    mov rax, 42
    test rax, rax
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

    mov rax, 5          ; 0b0101
    mov rbx, 2          ; 0b0010
    test rax, rbx
    jz  .t3_ok
    mov rsi, fail3
    mov rdx, fail3_len
    jmp .t3_print
.t3_ok:
    mov rsi, ok3
    mov rdx, ok3_len
.t3_print:
    mov rax, 1
    mov rdi, 1
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

ok1   db "[OK] TEST: rax=0,  ZF=1, JZ jumped", 10
ok1_len = $ - ok1
ok2   db "[OK] TEST: rax=42, ZF=0, JNZ jumped", 10
ok2_len = $ - ok2
ok3   db "[OK] TEST: 5 AND 2 = 0, ZF=1", 10
ok3_len = $ - ok3

fail1 db "[FAIL] TEST: rax=0 should set ZF", 10
fail1_len = $ - fail1
fail2 db "[FAIL] TEST: rax=42 should clear ZF", 10
fail2_len = $ - fail2
fail3 db "[FAIL] TEST: 5 AND 2 should be 0", 10
fail3_len = $ - fail3
