format ELF64 executable
entry _start

_start:
    jmp print

print:
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, len
    int 0x80
    jmp exit

exit:
    mov rax, 60
    mov rdi, 0
    mov edi, 43
    syscall

msg db 'Hell yeah, this is Karton!', 10
len = $ - msg
