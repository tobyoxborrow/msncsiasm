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
BITS 64

global _main

section .text

exit_1:
    mov rax, __NR_exit
    mov rdi, 0x1
    syscall


_main:
    ; require exactly 1 command-line argument
    cmp rdi, 0x2    ; argc
    jne exit_1

    mov rdi, [rsi]  ; dereference char **argv
    mov rax, 0x0
    mov rcx, 0xFF
    cld
    repne scasb     ; skip argv[0] (filename)

    ;mov rax, 0x0    ; temp for quad running total
    mov rbx, 0x0    ; current character
    mov rcx, 0x0    ; quad counter (to abort if there is the wrong number)
    mov rdx, 0xA    ; for mul instruction in loop
    mov r8, 0x0     ; the address in full, as it is being constructed

    ; loop over each character converting the ASCII character codes into an
    ; actual number
    ; using rax, rbx so we can use their byte forms and easily detect overflows
    decode_loop:
        mov bl, [rdi]   ; current character
        inc rdi

        cmp bl, '0'     ; sanity test, ASCII code is digit
        jl exit_1
        cmp bl, '9'
        jg exit_1

        sub bl, 0x30    ; subtract 0x30 from ASCII character code

        add al, bl      ; update quad running total
        jc exit_1       ; this quad is >255 (e.g. input was: 256)

        cmp byte [rdi], '.'   ; end of the quad?
        je decode_loop_next_quad

        cmp byte [rdi], 0x0   ; end of the string?
        je decode_loop_end

        ; there is another digit, multiply current value by 10 to shift it over
        ; one power (i.e. 19 becomes 190) to accept the next character
        mul dl
        jc exit_1       ; this quad is >255 (e.g. input was: 999)

        jmp decode_loop
    decode_loop_next_quad:
        add r8, rax     ; update address running total
        mov rax, 0x0    ; reset quad running total
        shl r8, 0x8     ; shift address to make space for next quad

        inc rcx
        cmp rcx, 0x3    ; sanity test, too many quads?
        ja exit_1

        inc rdi         ; skip over the '.'
        jmp decode_loop
    decode_loop_end:
        add r8, rax     ; update address running total

    mov rax, r8

    ; operate on the 32bit value
    bswap eax

    ; copy template to output string
    mov rcx, output_template_len
    mov rsi, output_template
    mov rdi, output
    cld
    rep movsb

    ; convert number back to ASCII for display and store in output string
    mov rcx, 0x8
    mov rsi, output
    add rsi, 0x9    ; skip to the last position, write from right to left
    encode_loop:
        ; divide the number by 0x10 to get one digit (popped into edx)
        mov rdx, 0x0
        mov rbx, 0x10
        div rbx

        ; lookup edx against hex_chars
        mov rdi, hex_chars
        add rdi, rdx
        mov dl, byte [rdi]

        mov byte [rsi], dl  ; store the result in output

        dec rsi
        loop encode_loop

    mov rax, __NR_write
    mov rdi, 0x1    ; stdout
    mov rsi, output
    mov rdx, output_template_len
    syscall

    mov rax, __NR_exit
    mov rdi, 0x0
    syscall

section .data
    ; bsd/kern/syscalls.master
    __NR_exit:  equ 0x2000001
    __NR_write: equ 0x2000004

    hex_chars: db '0123456789ABCDEF'
    output_template: db '0x????????', 0xA
    output_template_len: equ $-output_template

section .bss
    output: resb output_template_len
