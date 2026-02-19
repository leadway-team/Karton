format ELF executable
entry _start

_start:    
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, len
    int 0x80
    
    
    mov eax, 1
    xor ebx, ebx
    int 0x80

msg db "Hell World!", 10
len = $ - msg
