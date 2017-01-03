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

global _start

section .text

exit1:
    mov eax, __NR_exit
    mov ebx, 0x1
    int 0x80


_start:
    ; require 1 command-line argument
    pop ecx
    cmp ecx, 0x2
    jne exit1

    pop ecx         ; command filename (ignored)
    pop ecx         ; first argument

    ; loop over each character converting the ASCII character codes into an
    ; actual number
    decode_loop:
        mov bl, [ecx]   ; current character

        sub bl, 0x30    ; subtract 0x30 from ASCII character code

        add ax, bx      ; update running total

        cmp byte [ecx+1], 0x0   ; end of the string?
        je decode_loop_end

        ; there is another digit, multiply current value by 10 to shift it over
        ; one power (i.e. 655 becomes 6550) to accept the next character
        mov edx, 0xA
        mul edx

        inc ecx
        jmp decode_loop
    decode_loop_end:

    ; bswap works on 32/64bits, we are only interested in 16 bits, so discard
    ; the 16 least significant bits
    bswap eax       ; ex: 0x0000B077 becomes 0x77B00000
    shr eax, 0x10   ; ex: 0x77B00000 becomes 0x000077B0

    ; copy template to output string
    mov ecx, 0x7
    mov esi, output_template
    mov edi, output
    cld
    rep movsb

    ; convert number back to ASCII for display and store in output string
    mov ecx, 0x4
    mov esi, output
    add esi, 0x5    ; skip to the last position, write from right to left
    encode_loop:
        ; divide the number by 0x10 to get one digit (popped into edx)
        mov edx, 0x0
        mov ebx, 0x10
        div bx

        ; lookup edx against hex_chars
        mov edi, hex_chars
        add edi, edx
        mov dl, byte [edi]

        mov byte [esi], dl  ; store the result in output

        dec esi
        loop encode_loop

    mov eax, __NR_write
    mov ebx, 0x1    ; stdout
    mov ecx, output
    mov edx, 0x7
    int 0x80

    mov eax, __NR_exit
    mov ebx, 0x0
    int 0x80

section .data
    ; asm/unistd_32.h
    __NR_exit equ 1
    __NR_write equ 4

    hex_chars: db '0123456789ABCDEF'
    output_template: db '0x????', 0xA

section .bss
    output: resb 0x7
