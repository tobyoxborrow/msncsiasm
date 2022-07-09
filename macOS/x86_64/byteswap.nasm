; Decimal byte swapper
;
; Takes a decimal number, performs a byte swap and outputs the number in hex
; for your use elsewhere.
; Use case: You need numbers (e.g. "53") in network byte order
; Treats all input as 16 bit numbers (i.e. 0-65535)
; Using numbers (or any other character) outside this range is not expected and
; the results are undefined.
;
; Usage:   byteswap <number>
;
; Example usage:
; $ ./byteswap 53
; 0x3500
; $ ./byteswap 30640
; 0xB077
;
BITS 64

global _main

section .text

exit_1:
    mov eax, __NR_exit
    mov edi, 0x1
    syscall


_main:
    ; require exactly 1 command-line argument
    cmp rdi, 0x2
    jne exit_1

    mov rdi, [rsi]  ; dereference char **argv
    mov rax, 0x0
    mov rcx, 0xFF
    cld
    repne scasb     ; skip argv[0] (filename)

    ;mov rax, 0x0    ; temp for quad running total

    ; loop over each character converting the ASCII character codes into an
    ; actual number
    decode_loop:
        mov bl, [rdi]   ; current character

        sub bl, 0x30    ; subtract 0x30 from ASCII character code

        add ax, bx      ; update running total

        cmp byte [rdi+1], 0x0   ; end of the string?
        je decode_loop_end

        ; there is another digit, multiply current value by 10 to shift it over
        ; one power (i.e. 655 becomes 6550) to accept the next character
        mov rdx, 0xA
        mul rdx

        inc rdi
        jmp decode_loop
    decode_loop_end:

    ; bswap works on 32/64bits, we are only interested in 16 bits, so discard
    ; the 16 least significant bits
    bswap eax       ; ex: 0x0000B077 becomes 0x77B00000
    shr eax, 0x10   ; ex: 0x77B00000 becomes 0x000077B0

    ; copy template to output string
    mov rcx, 0x7
    mov rsi, output_template
    mov rdi, output
    cld
    rep movsb

    ; convert number back to ASCII for display and store in output string
    mov rcx, 0x4
    mov rsi, output
    add rsi, 0x5    ; skip to the last position, write from right to left
    encode_loop:
        ; divide the number by 0x10 to get one digit (popped into rdx)
        mov rdx, 0x0
        mov rbx, 0x10
        div bx

        ; lookup rdx against hex_chars
        mov rdi, hex_chars
        add rdi, rdx
        mov dl, byte [rdi]

        mov byte [rsi], dl  ; store the result in output

        dec rsi
        loop encode_loop

    mov rax, __NR_write
    mov rdi, 0x1    ; stdout
    mov rsi, output
    mov rdx, 0x7
    syscall

    mov rax, __NR_exit
    mov rdi, 0x0
    syscall

section .data
    ; bsd/kern/syscalls.master
    __NR_exit:  equ 0x2000001
    __NR_write: equ 0x2000004

    hex_chars: db '0123456789ABCDEF'
    output_template: db '0x????', 0xA

section .bss
    output: resb 0x7
