; Microsoft Network Connectivity Status Indicator
; Makes GET request for http://www.msftncsi.com/ncsi.txt
; Exits 0 if GET request succeeds (full connectivity)
; If GET request fails, performs DNS lookup on dns.msftncsi.com, expecting the
; result 131.107.255.255
; Exits 1 if DNS request succeeds (partial connectivity)
; Otherwise, exits -1 (no connectivity)
; Exits -2 for internal processing errors, though that may be due to some
; network reason
;
BITS 64

global _main

section .text


exit:
    mov rax, __NR_exit
    syscall


exit_0:
    mov rdi, 0x0
    jmp exit


; Partial connectivity
exit_1:
    mov rdi, 0x1
    jmp exit


; Network error
exit_neg1:
    mov rdi, -1
    jmp exit


; Internal error
exit_neg2:
    mov rdi, -2
    jmp exit


sys_socket_udp:
    ; int socket(int domain, int type, int protocol);
    mov edi, PF_INET     ; int domain
    mov esi, SOCK_DGRAM  ; int type
    mov edx, IPPROTO_IP  ; int protocol
    call sys_socket
    ret


sys_socket_tcp:
    ; int socket(int domain, int type, int protocol);
    mov edi, PF_INET     ; int domain
    mov esi, SOCK_STREAM ; int type
    mov edx, IPPROTO_IP  ; int protocol
    call sys_socket
    ret


; arguments:
; rdi - int domain
; rsi - int type
; rdx - int protocol
; return values:
; r15 - socket file descriptor
sys_socket:
    ; int socket(int domain, int type, int protocol);
    mov rax, __NR_socket
    syscall

    mov r15, rax

    ret


; set all sockets to 5 seconds read timeout
sys_setsockopt:
    ; int setsockopt(int socket, int level, int option_name,
    ;                const void *option_value, socklen_t option_len);
    ; see also: bsd/kern/uipc_syscalls.c

    mov rax, __NR_setsockopt
    mov rdi, r15
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    mov rcx, timeval_struct
    mov r10, rcx
    mov r8,  timeval_struct_len
    syscall

    ret


; arguments:
; rdi - file descriptor
sys_close:
    ; int close(int fd);
    mov rax, __NR_close
    syscall

    ret


; arguments:
; eax - sin_addr in network byte order
; bx -  sin_port in network byte order
sys_connect:
    ; int connect(int s, caddr_t name, socklen_t namelen);
    ; reference:
    ; https://www.freebsd.org/doc/en/books/developers-handbook/sockets-essential-functions.html
    mov rsi, connect_struct     ; struct sockaddr_in {
    ;mov byte  [rsi],   0x0      ; sin_len
    mov byte  [rsi+1], AF_INET  ; sin_family
    mov word  [rsi+2], bx       ; sin_port
    mov dword [rsi+4], eax      ; sin_addr
                                ; };

    mov rax, __NR_connect
    mov rdi, r15                ; int s
    ;mov rsi, connect_struct    ; caddr_t name
    mov rdx, dword connect_struct_len ; socklen_t namelen
    syscall

    ret


; arguments:
; rdi - file handle
; rsi - message
; rdx - message length
sys_write:
    ; user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte);
    mov rax, __NR_write
    syscall

    ret


; arguments:
; rdi - file handle
; rsi - buffer
; rdx - buffer length
sys_read:
    ; user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte);
    mov rax, __NR_read
    syscall

    ret


; simple domain name resolver
; requires a recursive server to answer our queries (e.g. 8.8.8.8)
; arguments:
; r15 - socket file descriptor
; prepare [packet_buffer] with a valid dns query packet before calling
; return values:
; r14 - ip address or 0 if not found
resolve_name:
    call sys_socket_udp
    cmp rax, 0x0
    jl exit_neg2

    ; set timeout options on socket
    call sys_setsockopt
    cmp rax, 0x0
    jnz exit_neg2

    mov rax, addr_8888
    mov rbx, port_domain
    call sys_connect
    cmp rax, 0x0
    jnz exit_neg1

    ; send question
    mov rdi, r15
    mov rsi, packet_buffer
    mov rdx, dns_query_packet_len
    call sys_write
    cmp rax, 0x0
    jl exit_neg2

    ; erase ID from [packet_buffer] so we can be sure what we see in there
    ; later has been received and not just the packet we sent
    mov [rsi], word 0x0

    ; receive answer
    mov rdi, r15
    mov rsi, packet_buffer
    mov rdx, packet_buffer_len
    call sys_read
    cmp rax, 0x0
    jl exit_neg2

    ;mov r10, rax    ; save size of answer

    ; close socket
    mov rdi, r15
    call sys_close

    ; parse answer
    mov rax, packet_buffer

    ; sanity check: verify ID
    cmp word [rax], 0x77B0
    jne exit_neg1
    add rax, 0x2    ; skip over ID

    ; check rcode for errors (e.g. servfail), *should* be 0
    ; rcode is the last four bits of byte 4 of the header
    mov rbx, 0x0
    mov bl, byte [rax+1]
    and bl, 0xF     ; get just the last four bits from the byte
    cmp bl, 0x0
    jne exit_neg1

    add rax, 0x4    ; skip over flags, query count

    ; get number of resource records in the answer
    mov rcx, 0x0
    mov cx, word [rax]
    bswap ecx
    shr ecx, 0x10
    add rax, 0x2    ; skip answer count

    ; skip to first answer
    add rax, 0x4    ; skip auth rr, additional rr
    add rax, 0x12   ; skip question labels
                    ; the two domains we will query are the same length, so we
                    ; can hard-code the value here.
    add rax, 0x4    ; skip answer QTYPE, QCLASS

    ; go through each answer
    ; stop on the first A record, ignore all other types
    ; rax - pointer to current character
    ; rbx - temp storage of current pointed value
    ; rcx - number of records
    mov r14, 0x0 ; result of search: the ip address or nothing
    rr_loop:
        ; is the name a label or pointer?
        cmp word [rax], 0xC000
        jge rr_loop_pointer
        jmp rr_loop_label
    rr_loop_post_name:   ; return here after processing the name
        cmp word [rax], QTYPE_A
        je rr_loop_handle_a

        add rax, 0x8    ; skip type, class, ttl
        mov rbx, 0x0    ; read rdata length
        mov bx, word [rax]
        bswap ebx
        shr ebx, 0x10

        add rax, 0x2    ; skip rdata length
        add rax, rbx    ; skip rdata

        loop rr_loop
        jmp rr_loop_end
    rr_loop_pointer:
        add rax, 0x2    ; skip over the pointer
        jmp rr_loop_post_name
    rr_loop_label:
        cmp byte [rax], 0x0
        je rr_loop_post_name
        mov rbx, 0x0
        mov bl, byte [rax]
        inc rax         ; skip label length
        add rax, rbx    ; skip label value
        jmp rr_loop_label
    rr_loop_handle_a:
        add rax, 0x8    ; skip type, class, ttl

        mov rbx, 0x0    ; read rdata length
        mov bx, word [rax]
        bswap ebx
        shr ebx, 0x10

        cmp rbx, 0x4    ; sanity check: IPv4 should be 4 bytes... right?
        jne exit_neg2

        add rax, 0x2    ; skip rdata length

        mov r14d, [eax]
    rr_loop_end:

    cmp r14, 0x0    ; did we find an A record?
    je exit_neg2

    ret


; arguments:
; r14 - IP address
http_request:
    call sys_socket_tcp

    ; set timeout options on socket
    call sys_setsockopt
    cmp rax, 0x0
    jnz exit_neg2

    mov rax, r14
    mov rbx, port_http
    call sys_connect
    cmp rax, 0x0
    jnz exit_neg1

    ; send request
    mov rdi, r15
    mov rsi, http_request_request
    mov rdx, http_request_request_len
    call sys_write
    cmp rax, 0x0
    jl exit_neg2

    ; receive response
    mov rdi, r15
    mov rsi, packet_buffer
    mov rdx, packet_buffer_len
    call sys_read
    cmp rax, 0x0
    jl exit_neg2

    mov r10, rax    ; save size of response

    ; close socket
    mov rdi, r15
    call sys_close

    ; parse response
    ; TODO: check HTTP response code - redirect or OK or other?
    mov rax, packet_buffer

    cmp dword [rax], "HTTP"   ; sanity check: looks like a HTTP response
    jne exit_neg1

    ; we could scan through the packet looking for "NCSI" but we know it'll be
    ; the last four bytes (there is not even CRLF) so we can just check there
    ; r10 is still the size of the response from sys_read
    sub r10, 0x4
    add rax, r10
    cmp dword [rax], "NCSI"
    je exit_0   ; if the text was found, we are done

    ret


resolve_www_name:
    mov rax, www_msftncsi_com_label
    mov rbx, www_msftncsi_com_label_len
    call craft_dns_query_packet
    call resolve_name
    ret


resolve_dns_name:
    mov rax, dns_msftncsi_com_label
    mov rbx, dns_msftncsi_com_label_len
    call craft_dns_query_packet
    call resolve_name
    ret


; arguments:
; rax - pointer to label string
; rbx - length of label string
craft_dns_query_packet:
    ; if we needed to calculate the dns query packet length, something like
    ; this would be needed. however, since both domains are the same length, we
    ; can hard code the value.
    ;mov [dns_query_packet_len], word dns_query_header_len
    ;add [dns_query_packet_len], bx
    ;add [dns_query_packet_len], word 0x4 ; trailing params

    ; HEADER
    mov rcx, dns_query_header_len
    mov rsi, dns_query_header
    mov rdi, packet_buffer
    ;cld
    rep movsb

    ; QUESTION
    mov rcx, rbx
    mov rsi, rax
    ; rdi is already at the right spot
    ;cld
    rep movsb

    ; trailing params
    mov [rdi],   word QTYPE_A   ; QTYPE (1 - A, a host name)
    mov [rdi+2], word QCLASS_IN ; QCLASS (1 - IN, the Internet)

    ret


_main:
    ; method 1. GET request for www.msftncsi.com/ncsi.txt
    call resolve_www_name
    call http_request

    ; method 2. DNS query for dns.msftncsi.com
    call resolve_dns_name
    cmp r14d, dword addr_131107255255
    je exit_1       ; correct result
    jmp exit_neg1   ; otherwise, bad result and fail


section .data
    ; bsd/kern/syscalls.master
    __NR_exit:       equ 0x2000001
    __NR_read:       equ 0x2000003
    __NR_write:      equ 0x2000004
    __NR_close:      equ 0x2000006
    __NR_socket:     equ 0x2000061
    __NR_connect:    equ 0x2000062
    __NR_setsockopt: equ 0x2000069

    ; bsd/netinet/in.h
    IPPROTO_IP:    equ 0    ; dummy for IP

    ; bsd/sys/socket.h
    AF_INET: equ 2          ; internetwork: UDP, TCP, etc.
    PF_INET: equ AF_INET
    SOCK_STREAM: equ 1      ; stream socket
    SOCK_DGRAM:  equ 2      ; datagram socket
    SOL_SOCKET:  equ 0xffff ; options for socket level
    SO_RCVTIMEO: equ 0x1006 ; receive timeout

    ; /etc/services - in network byte order
    port_domain: equ 0x3500 ; decimal: 53
    port_http:   equ 0x5000 ; decimal: 80

    addr_8888:         equ 0x08080808   ; 8.8.8.8
    addr_131107255255: equ 0xFFFF6B83   ; 131.107.255.255

    ; https://tools.ietf.org/html/rfc1035#section-3.2.2
    ;QTYPE_A:   equ 0x1   ; A, 1 a host address
    ;QCLASS_IN: equ 0x1   ; 1 - IN, the Internet
    ; word size, in network byte order
    QTYPE_A:   equ 0x100
    QCLASS_IN: equ 0x100

    ; Domain name message header section format
    ; https://tools.ietf.org/html/rfc1035#section-4.1.1
    ; Z bits that were reserved then gained usage: The AD and CD header bits
    ; https://tools.ietf.org/html/rfc2065#section-6
    dns_query_header:
        db 0xB0, 0x77,  ; ID
        db 0x01, 0x00,  ; QR (0), Opcode (0), AA (0), TC (0), RD (1)
                        ; RA (0), Z (0), AD (0), CD (0), RCODE (0)
        db 0x00, 0x01,  ; QDCOUNT (1)
        db 0x00, 0x00,  ; ANCOUNT (0)
        db 0x00, 0x00,  ; NSCOUNT (0)
        db 0x00, 0x00,  ; ARCOUNT (0)
    dns_query_header_len: equ $-dns_query_header

    dns_query_packet_len: equ 0x22

    dns_msftncsi_com_label: db 0x3, "dns", 0x8, "msftncsi", 0x3, "com", 0x0
    dns_msftncsi_com_label_len: equ $-dns_msftncsi_com_label
    www_msftncsi_com_label: db 0x3, "www", 0x8, "msftncsi", 0x3, "com", 0x0
    www_msftncsi_com_label_len: equ $-www_msftncsi_com_label

    ; use \r\n because it's probably IIS on windows, make it happy
    http_request_request:
        db "GET /ncsi.txt HTTP/1.1", 0xD, 0xA,
        db "Host: www.msftncsi.com", 0xD, 0xA,
        db 0xD, 0xA
    http_request_request_len: equ $-http_request_request

    connect_struct_len: equ 0x10
    packet_buffer_len:  equ 512  ; udp packet max
                                 ; also sufficient for ncsi.txt http response
                                 ; (headers+body: ~180 bytes)

    timeval_struct: ; struct timeval {
        dq 0x5,     ; __darwin_time_t tv_sec; /* seconds */
        dq 0x0      ; __darwin_suseconds_t tv_usec; /* and microseconds */
                    ; };
    timeval_struct_len: equ $-timeval_struct

section .bss
    connect_struct: resb connect_struct_len
    packet_buffer:  resb packet_buffer_len
