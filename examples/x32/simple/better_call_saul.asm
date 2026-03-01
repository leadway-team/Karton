format ELF executable
entry _start

_start:    
    call saul
    call exit

saul:
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, len
    int 0x80
    ret

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80
    ret ; nevermind

msg db "Better call Saul!", 10
len = $ - msg
