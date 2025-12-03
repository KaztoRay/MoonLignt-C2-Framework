; CardinalOS - Attack-Oriented Operating System
; Stage 1 Bootloader (512 bytes, BIOS boot sector)

[BITS 16]
[ORG 0x7C00]

section .text
    global _start

_start:
    ; Initialize segments
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    ; Clear screen
    mov ah, 0x00
    mov al, 0x03
    int 0x10

    ; Print boot message
    mov si, boot_msg
    call print_string

    ; Load stage 2 bootloader
    mov ah, 0x02        ; Read sectors
    mov al, 15          ; Read 15 sectors (stage 2)
    mov ch, 0           ; Cylinder 0
    mov cl, 2           ; Start at sector 2
    mov dh, 0           ; Head 0
    mov bx, 0x7E00      ; Load to 0x7E00
    int 0x13
    jc disk_error

    ; Enable A20 line
    call enable_a20

    ; Switch to protected mode
    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    
    ; Jump to 32-bit code
    jmp CODE_SEG:init_pm

disk_error:
    mov si, disk_err_msg
    call print_string
    jmp $

print_string:
    pusha
.loop:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    int 0x10
    jmp .loop
.done:
    popa
    ret

enable_a20:
    in al, 0x92
    or al, 2
    out 0x92, al
    ret

[BITS 32]
init_pm:
    ; Setup segments
    mov ax, DATA_SEG
    mov ds, ax
    mov ss, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov esp, 0x90000

    ; Jump to stage 2
    jmp 0x7E00

; GDT
gdt_start:
    dd 0x0
    dd 0x0

gdt_code:
    dw 0xFFFF       ; Limit
    dw 0x0          ; Base low
    db 0x0          ; Base mid
    db 0x9A         ; Access
    db 0xCF         ; Granularity
    db 0x0          ; Base high

gdt_data:
    dw 0xFFFF
    dw 0x0
    db 0x0
    db 0x92
    db 0xCF
    db 0x0

gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEG equ gdt_code - gdt_start
DATA_SEG equ gdt_data - gdt_start

; Data
boot_msg db 'CardinalOS v1.0 - Attack Platform Loading...', 0x0D, 0x0A, 0
disk_err_msg db 'Disk read error!', 0x0D, 0x0A, 0

; Boot signature
times 510-($-$$) db 0
dw 0xAA55
