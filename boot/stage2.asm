; CardinalOS - Stage 2 Bootloader
; Loads kernel and initializes 64-bit mode

[BITS 32]
[ORG 0x7E00]

section .text
    global stage2_start

stage2_start:
    ; Print stage 2 message
    mov esi, stage2_msg
    call print_string_pm

    ; Load kernel from disk
    call load_kernel

    ; Check for long mode support
    call check_long_mode
    test eax, eax
    jz no_long_mode

    ; Setup paging for long mode
    call setup_paging

    ; Enable PAE
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; Set long mode bit
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    ; Load 64-bit GDT
    lgdt [gdt64_descriptor]

    ; Jump to 64-bit kernel
    jmp CODE64_SEG:KERNEL_OFFSET

no_long_mode:
    mov esi, no_lm_msg
    call print_string_pm
    jmp $

check_long_mode:
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode
    
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode
    
    mov eax, 1
    ret

.no_long_mode:
    xor eax, eax
    ret

setup_paging:
    ; Identity map first 4GB
    mov edi, 0x1000
    mov cr3, edi
    xor eax, eax
    mov ecx, 4096
    rep stosd
    mov edi, cr3

    ; PML4
    mov DWORD [edi], 0x2003
    add edi, 0x1000

    ; PDPT
    mov DWORD [edi], 0x3003
    add edi, 0x1000

    ; PD
    mov DWORD [edi], 0x4003
    add edi, 0x1000

    ; PT (map first 2MB)
    mov ebx, 0x00000003
    mov ecx, 512
.loop:
    mov DWORD [edi], ebx
    add ebx, 0x1000
    add edi, 8
    loop .loop

    ret

load_kernel:
    ; Load kernel from disk to KERNEL_OFFSET
    mov eax, 0x20           ; Start sector
    mov ebx, KERNEL_OFFSET
    mov ecx, 100            ; Load 100 sectors (50KB)
.read_loop:
    push eax
    push ecx
    
    mov ah, 0x02
    mov al, 1
    mov ch, 0
    mov cl, al
    mov dh, 0
    int 0x13
    jc .error
    
    pop ecx
    pop eax
    add ebx, 512
    inc eax
    loop .read_loop
    ret

.error:
    mov esi, kernel_err_msg
    call print_string_pm
    jmp $

print_string_pm:
    pusha
    mov edx, 0xB8000
.loop:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0F
    mov [edx], ax
    add edx, 2
    jmp .loop
.done:
    popa
    ret

; 64-bit GDT
gdt64_start:
    dq 0x0

gdt64_code:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 0x9A
    db 0xAF
    db 0x0

gdt64_data:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 0x92
    db 0xCF
    db 0x0

gdt64_end:

gdt64_descriptor:
    dw gdt64_end - gdt64_start - 1
    dd gdt64_start

CODE64_SEG equ gdt64_code - gdt64_start
DATA64_SEG equ gdt64_data - gdt64_start

KERNEL_OFFSET equ 0x100000

; Messages
stage2_msg db 'Stage 2: Loading kernel...', 0
no_lm_msg db 'ERROR: 64-bit mode not supported!', 0
kernel_err_msg db 'ERROR: Failed to load kernel!', 0

times 7680-($-$$) db 0
