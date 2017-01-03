; IP byte swapper
;
; Takes an IP address in dotted quad format, performs a byte swap and outputs
; the result in hex for your use elsewhere.
; Use case: You need an IP address (e.g. "192.0.2.57") in network byte order
; Using numbers (or any other character) outside this range is not expected and
; the results are undefined.
;
; Usage:   byteswapip <ip-address>
;
; Example usage:
; $ ./byteswapip 192.0.2.57
; 0x4D0200C0
; $ ./byteswapip 8.8.8.8
; 0x08080808
;

global _start

section .text

exit1:
    mov eax, __NR_exit
    mov ebx, 0x1
    int 0x80


_start:
    ; require exactly 1 command-line argument
    pop ecx
    cmp ecx, 0x2
    jne exit1

    pop ecx         ; command filename (ignored)
    pop ecx         ; first argument

    mov eax, 0x0    ; temp for quad running total
    mov edx, 0xA    ; for mul instruction in loop
    mov esi, 0x0    ; quad counter (to abort if there is the wrong number)

    ; loop over each character converting the ASCII character codes into an
    ; actual number
    decode_loop:
        mov bl, [ecx]   ; current character
        inc ecx

        cmp bl, '0'     ; sanity test, ASCII code is digit
        jl exit1
        cmp bl, '9'
        jg exit1

        sub bl, 0x30    ; subtract 0x30 from ASCII character code

        add al, bl      ; update quad running total
        jc exit1        ; this quad is >255 (e.g. input was: 256)

        cmp byte [ecx], '.'   ; end of the quad?
        je decode_loop_next_quad

        cmp byte [ecx], 0x0   ; end of the string?
        je decode_loop_end

        ; there is another digit, multiply current value by 10 to shift it over
        ; one power (i.e. 19 becomes 190) to accept the next character
        mul dl
        jc exit1        ; this quad is >255 (e.g. input was: 999)

        jmp decode_loop
    decode_loop_next_quad:
        add edi, eax    ; update address running total
        mov eax, 0x0    ; reset quad running total
        shl edi, 0x8    ; shift address to make space for next quad

        inc esi         ; sanity test, too many quads
        cmp esi, 0x3
        ja exit1

        inc ecx         ; skip over the '.'
        jmp decode_loop
    decode_loop_end:
        add edi, eax    ; update address running total

    mov eax, edi
    bswap eax

    ; copy template to output string
    mov ecx, output_template_len
    mov esi, output_template
    mov edi, output
    cld
    rep movsb

    ; convert number back to ASCII for display and store in output string
    mov ecx, 0x8
    mov esi, output
    add esi, 0x9    ; skip to the last position, write from right to left
    encode_loop:
        ; divide the number by 0x10 to get one digit (popped into edx)
        mov edx, 0x0
        mov ebx, 0x10
        div ebx

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
    mov edx, output_template_len
    int 0x80

    mov eax, __NR_exit
    mov ebx, 0x0
    int 0x80

section .data
    ; asm/unistd_32.h
    __NR_exit equ 1
    __NR_write equ 4

    hex_chars: db '0123456789ABCDEF'
    output_template: db '0x????????', 0xA
    output_template_len: equ $-output_template

section .bss
    output: resb output_template_len
