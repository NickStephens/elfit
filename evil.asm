BITS 32

jmp short b
a:
    xor eax, eax
    pop ecx 
    mov ebx, 1
    mov edx, 4
    mov eax, 4
    int 0x80

    mov eax, 0
    jmp eax

b:
    call a
    db "evil"
