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
global _start

section .text


exit:
    mov eax, __NR_exit
    int 0x80


exit_0:
    mov ebx, 0x0
    jmp exit


; Partial connectivity
exit_1:
    mov ebx, 0x1
    jmp exit


; Network error
exit_neg1:
    mov ebx, -1
    jmp exit


; Internal error
exit_neg2:
    mov ebx, -2
    jmp exit


; prepare [socket_args] before calling
sys_socket:
    ; int socketcall(int call, unsigned long *args);
    ; int socket(int domain, int type, int protocol);
    mov eax, __NR_socketcall
    mov ebx, SYS_SOCKET     ; int call
    mov ecx, socket_args    ; unsigned long *args
    int 0x80

    ; save the socket file descriptor
    mov esi, eax

    ret


; arguments:
; ebx - file descriptor
sys_close:
    ; int close(int fd);
    mov eax, __NR_close
    int 0x80

    ret


; arguments:
; eax - sin_addr in network byte order
; ebx - sin_port in network byte order
sys_connect:
    ; int socketcall(int call, unsigned long *args);
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    mov [connect_struct],   word AF_INET    ; sin_family
    mov [connect_struct+2], word bx         ; sin_port
    mov [connect_struct+4], dword eax       ; sin_addr

    mov [connect_args],   esi
    mov [connect_args+4], dword connect_struct
    mov [connect_args+8], dword __SOCK_SIZE__

    mov eax, __NR_socketcall
    mov ebx, SYS_CONNECT    ; int call
    mov ecx, connect_args   ; *args
    int 0x80

    ret


; arguments:
; ebx - file handle
; ecx - message
; edx - message length
sys_write:
    ; ssize_t write(int fd, const void *buf, size_t count);
    mov eax, __NR_write
    int 0x80

    ret


; arguments:
; ebx - file handle
; ecx - buffer
; edx - buffer length
sys_read:
    ; ssize_t read(int fd, void *buf, size_t count);
    mov eax, __NR_read
    int 0x80

    ret


; simple domain name resolver
; requires a recursive server to answer our queries (e.g. 8.8.8.8)
; prepare [packet_buffer] with a valid dns query packet before calling
resolve_name:
    ; ecx - *args for socketcall() / socket()
    mov [socket_args],   dword PF_INET     ; int domain
    mov [socket_args+4], dword SOCK_DGRAM  ; int domain
    mov [socket_args+8], dword IPPROTO_IP  ; int domain
    call sys_socket
    cmp eax, 0x0
    jl exit_neg2

    mov eax, addr_8888
    mov ebx, port_domain
    call sys_connect
    cmp eax, 0x0
    jnz exit_neg1

    ; send question
    mov ebx, esi
    mov ecx, packet_buffer
    mov edx, dns_query_packet_len
    call sys_write
    cmp eax, 0x0
    jl exit_neg2

    ; receive answer
    mov ebx, esi
    mov ecx, packet_buffer
    mov edx, packet_buffer_len
    call sys_read
    cmp eax, 0x0
    jl exit_neg2

    ;mov ecx, eax    ; save size of answer

    ; close socket
    mov ebx, esi
    call sys_close

    ; parse answer
    mov eax, packet_buffer

    ; sanity check: verify ID
    cmp word [eax], 0x77B0
    jne exit_neg1
    add eax, 0x2    ; skip over ID

    ; TODO: check rcode flags for errors (e.g. servfail)
    ; TODO: check RA bit is set (server is recursive)?
    nop

    ; get number of resource records in the answer
    add eax, 0x4    ; skip over flags, query count
    mov ecx, 0x0
    mov cx, word [eax]
    bswap ecx
    shr ecx, 0x10
    add eax, 0x2    ; skip answer count

    ; skip to first answer
    add eax, 0x4    ; skip auth rr, additional rr
    add eax, 0x12   ; skip question labels
                    ; the two domains we will query are the same length, so we
                    ; can hard-code the value here.
    add eax, 0x4    ; skip answer QTYPE, QCLASS

    ; go through each answer
    ; stop on the first A record
    ; ignore other types
    mov edi, 0x0    ; IP address will be stored here
    rr_loop:
        ; is the name a label or pointer?
        cmp word [eax], 0xC000
        jge rr_loop_pointer
        jmp rr_loop_label
    rr_loop_post_name:   ; return here after processing the name
        mov bx, word [eax]  ; resource record type

        cmp ebx, QTYPE_A  ; is it an A record?
        je rr_loop_handle_a

        add eax, 0x8    ; skip type, class, ttl
        mov ebx, 0x0    ; read rdata length
        mov bx, word [eax]
        bswap ebx
        shr ebx, 0x10
        add eax, 0x2    ; skip rdata length
        add eax, ebx    ; skip rdata

        loop rr_loop
        jmp rr_loop_end
    rr_loop_pointer:
        add eax, 0x2    ; skip over the pointer
        jmp rr_loop_post_name
    rr_loop_label:
        cmp byte [eax], 0x0
        je rr_loop_post_name
        mov ebx, 0
        mov bl, byte [eax]
        inc eax         ; skip label length
        add eax, ebx    ; skip label value
        jmp rr_loop_label
    rr_loop_handle_a:
        add eax, 0x8    ; skip type, class, ttl
        mov ebx, 0x0    ; read rdata length
        mov bx, word [eax]
        bswap ebx
        shr ebx, 0x10

        cmp ebx, 0x4    ; sanity check: IPv4 should be 4 bytes... right?
        jne exit_neg2

        add eax, 0x2    ; skip rdata length

        mov edi, [eax]
    rr_loop_end:

    cmp edi, 0x0    ; did we find an A record?
    je exit_neg2

    ret


; arguments:
; edi - IP address
http_request:
    ; ecx - *args for socketcall() / socket()
    mov [socket_args],   dword PF_INET     ; int domain
    mov [socket_args+4], dword SOCK_STREAM ; int domain
    mov [socket_args+8], dword IPPROTO_IP  ; int domain
    call sys_socket
    cmp eax, 0x0
    jl exit_neg2

    mov eax, edi
    mov ebx, port_http
    call sys_connect
    cmp eax, 0x0
    jnz exit_neg1

    ; send request
    mov ebx, esi
    mov ecx, http_request_request
    mov edx, http_request_request_len
    call sys_write
    cmp eax, 0x0
    jl exit_neg2

    ; receive response
    mov ebx, esi
    mov ecx, packet_buffer
    mov edx, packet_buffer_len
    call sys_read
    cmp eax, 0x0
    jl exit_neg2

    mov ecx, eax    ; save size of response

    ; close socket
    mov ebx, esi
    call sys_close

    ; parse response
    ; TODO: check HTTP response code - redirect or OK or other?
    mov eax, packet_buffer

    cmp dword [eax], "HTTP"   ; sanity check: looks like a HTTP response
    jne exit_neg1

    ; we could scan through the packet looking for "NCSI" but we know it'll be
    ; the last four bytes (there is not even CRLF) so we can just check there
    ; ecx is still the size of the response from sys_read
    sub ecx, 0x4
    add eax, ecx
    cmp dword [eax], "NCSI"
    je exit_0   ; if the text was found, we are done

    ret


resolve_www_name:
    mov eax, www_msftncsi_com_label
    mov ebx, www_msftncsi_com_label_len
    call craft_dns_query_packet
    call resolve_name
    ret


resolve_dns_name:
    mov eax, dns_msftncsi_com_label
    mov ebx, dns_msftncsi_com_label_len
    call craft_dns_query_packet
    call resolve_name
    ret


; arguments:
; eax - pointer to label string
; ebx - length of label string
craft_dns_query_packet:
    ; if we needed to calculate the dns query packet length, something like
    ; this would be needed. however, since both domains are the same length, we
    ; can hard code the value.
    ;mov [dns_query_packet_len], word dns_query_header_len
    ;add [dns_query_packet_len], bx
    ;add [dns_query_packet_len], word 0x4 ; trailing params

    ; HEADER
    mov ecx, dns_query_header_len
    mov esi, dns_query_header
    mov edi, packet_buffer
    ;cld
    rep movsb

    ; QUESTION
    mov ecx, ebx
    mov esi, eax
    ; edi is at the right spot
    ;cld
    rep movsb

    ; trailing params
    mov [edi],   word QTYPE_A   ; QTYPE (1 - A, a host name)
    mov [edi+2], word QCLASS_IN ; QCLASS (1 - IN, the Internet)

    ret


_start:
    ; method 1. GET request for www.msftncsi.com/ncsi.txt
    call resolve_www_name
    call http_request

    ; method 2. DNS query for dns.msftncsi.com
    call resolve_dns_name
    cmp edi, addr_131107255255
    je exit_1       ; correct result
    jmp exit_neg1   ; otherwise, bad result and fail


section .data
    ; asm/unistd_32.h
    __NR_exit:  equ 1
    __NR_read:  equ 3
    __NR_write: equ 4
    __NR_close: equ 6
    __NR_socketcall: equ 102

    ; /usr/include/linux/net.h
    SYS_SOCKET:  equ 1  ; sys_socket(2)
    SYS_CONNECT: equ 3  ; sys_connect(2)

    ; /usr/include/linux/in.h
    IPPROTO_IP:    equ 0    ; Dummy protocol for TCP
    __SOCK_SIZE__: equ 16   ; sizeof(struct sockaddr)

    ; /usr/include/.../bits/socket.h
    PF_INET: equ 2          ; IP protocol family.
    AF_INET: equ PF_INET

    ; /usr/include/.../bits/socket_type.h
    SOCK_STREAM: equ 1      ; Sequenced, reliable, connection-based
    SOCK_DGRAM:  equ 2      ; Connectionless, unreliable datagrams

    ; /etc/services - in network byte order
    port_domain: equ 0x3500     ; decimal: 53
    port_http:   equ 0x5000     ; decimal: 80

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
        ; HEADER
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

    ; use \r\n because we are all one big happy family
    http_request_request: db "GET /ncsi.txt HTTP/1.1", 0xD, 0xA, "Host: www.msftncsi.com", 0xD, 0xA, 0xD, 0xA
    http_request_request_len: equ $-http_request_request

    packet_buffer_len: equ 512  ; udp packet max
                                ; also sufficient for ncsi.txt http response
                                ; (headers+body: ~180 bytes)


section .bss
    socket_args: resb 12
    connect_args: resb 12
    connect_struct: resb 8

    packet_buffer: resb packet_buffer_len
