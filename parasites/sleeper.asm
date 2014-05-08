BITS 32

pusha

push 0x0
push 0x3

; nanosleep(esp, NULL)
mov ebx, esp 
mov ecx, 0
mov eax, 162
int 0x80
pop eax ; get rid of the junk
pop eax

popa

mov eax, 0x00112233
jmp eax
