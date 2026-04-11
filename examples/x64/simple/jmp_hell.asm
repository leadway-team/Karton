format ELF64 executable
entry _start

_start:
    ; === CLD ===
    std
    cld

    ; === Test 1: JZ ===
    mov rax, 42
    mov rbx, 42
    cmp rax, rbx
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

    ; === Test 2: JNZ ===
    mov rax, 5
    mov rbx, 99
    cmp rax, rbx
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

    ; === Test 3: JL срабатывает ===
    mov rax, 3
    mov rbx, 100
    cmp rax, rbx
    jl  .t3_ok
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

    ; === Test 4: JL НЕ срабатывает ===
    mov rax, 100
    mov rbx, 3
    cmp rax, rbx
    jl  .t4_oops
    mov rsi, ok4
    mov rdx, ok4_len
    jmp .t4_print
.t4_oops:
    mov rsi, fail4
    mov rdx, fail4_len
.t4_print:
    mov rax, 1
    mov rdi, 1
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

ok1   db "[OK] JZ  : 42 == 42, jumped", 10
ok1_len = $ - ok1
ok2   db "[OK] JNZ : 5 != 99, jumped", 10
ok2_len = $ - ok2
ok3   db "[OK] JL  : 3 < 100, jumped", 10
ok3_len = $ - ok3
ok4   db "[OK] JL  : 100 > 3, NOT jumped", 10
ok4_len = $ - ok4

fail1 db "[FAIL] JZ  : should have jumped!", 10
fail1_len = $ - fail1
fail2 db "[FAIL] JNZ : should have jumped!", 10
fail2_len = $ - fail2
fail3 db "[FAIL] JL  : should have jumped!", 10
fail3_len = $ - fail3
fail4 db "[FAIL] JL  : should NOT have jumped!", 10
fail4_len = $ - fail4
