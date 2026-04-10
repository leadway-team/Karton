format ELF64 executable
entry _start

_start:
    ; ZF = 1
    mov eax, 42
    mov ebx, 42
    cmp eax, ebx

    ; CF = 1, ZF = 0
    mov eax, 5
    mov ebx, 10
    cmp eax, ebx

    ; SF = 0, ZF = 0, CF = 0
    mov eax, 100
    mov ebx, 1
    cmp eax, ebx
    
    mov eax, 1
    xor ebx, ebx
    int 0x80
