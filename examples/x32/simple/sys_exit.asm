format ELF executable
entry _start

_start:
    mov eax, 1
    mov ebx, 43
    int 0x80
