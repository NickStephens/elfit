BITS 32 

jmp short b
a:
    pop ecx 
    pusha
    xor eax, eax
    mov ebx, 1
    mov edx, 5
    mov eax, 4
    int 0x80
    popa

    mov eax, 0x00112233
    jmp eax

b:
    call a
    db "evil "
