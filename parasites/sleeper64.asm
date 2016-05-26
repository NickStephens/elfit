BITS 64

push rax
push rbx
push rcx
push rdx
push rbp
push rdi
push rsi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15

push 0x0
push 0x3

; nanosleep(esp, NULL)
mov rdi, rsp 
mov rsi, 0
mov rax, 35
syscall
pop rax ; get rid of the junk
pop rax

pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rsi
pop rdi
pop rbp
pop rdx
pop rcx
pop rbx
pop rax

mov rax, 0x0011223344556677
jmp rax
