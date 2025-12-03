/*
 * CardinalOS - Standalone Test Version
 * Runs as Windows application for testing (without bootloader)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <windows.h>

#define VGA_WIDTH 80
#define VGA_HEIGHT 25

// Terminal colors
#define COLOR_BLACK 0
#define COLOR_RED 4
#define COLOR_GREEN 2
#define COLOR_YELLOW 14
#define COLOR_BLUE 1
#define COLOR_CYAN 3
#define COLOR_WHITE 15

static int cursor_x = 0;
static int cursor_y = 0;

void kernel_clear_screen(void) {
    system("cls");
    cursor_x = 0;
    cursor_y = 0;
}

void kernel_putchar(char c) {
    putchar(c);
    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else {
        cursor_x++;
    }
}

void kernel_print(const char* str) {
    printf("%s", str);
}

void kernel_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void print_banner(void) {
    kernel_clear_screen();
    
    printf("\033[91m");  // Red
    kernel_print("\n");
    kernel_print("   ██████╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗ █████╗ ██╗      ██████╗ ███████╗\n");
    kernel_print("  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗██║     ██╔═══██╗██╔════╝\n");
    kernel_print("  ██║     ███████║██████╔╝██║  ██║██║██╔██╗ ██║███████║██║     ██║   ██║███████╗\n");
    kernel_print("  ██║     ██╔══██║██╔══██╗██║  ██║██║██║╚██╗██║██╔══██║██║     ██║   ██║╚════██║\n");
    kernel_print("  ╚██████╗██║  ██║██║  ██║██████╔╝██║██║ ╚████║██║  ██║███████╗╚██████╔╝███████║\n");
    kernel_print("   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝\n");
    printf("\033[0m");
    kernel_print("\n");
    
    printf("\033[97m");  // White
    kernel_print("              === Attack-Oriented Operating System ===\n");
    kernel_print("                      Version 1.0.0 (Test Mode)\n\n");
    printf("\033[0m");
}

void print_subsystem_init(void) {
    printf("\033[96m");  // Cyan
    
    kernel_print("[*] Initializing memory management...\n");
    kernel_print("[*] Initializing interrupt handlers...\n");
    kernel_print("[*] Initializing PCI devices...\n");
    kernel_print("[*] Initializing network stack...\n");
    kernel_print("[*] Initializing file systems...\n");
    kernel_print("    [FS] NTFS driver loaded\n");
    kernel_print("    [FS] exFAT driver loaded\n");
    kernel_print("    [FS] Ext4 driver loaded\n");
    kernel_print("    [FS] APFS driver loaded\n");
    kernel_print("[*] Initializing C2 core...\n");
    kernel_print("[C2] Command & Control core initialized\n");
    kernel_print("[*] Starting C2 services...\n");
    kernel_print("[C2] Starting server on port 4444\n");
    kernel_print("[C2] Server started successfully\n");
    
    printf("\033[92m");  // Light green
    kernel_print("\n[+] All systems initialized successfully!\n\n");
    printf("\033[0m");
}

void print_system_info(void) {
    printf("\033[93m");  // Yellow
    kernel_print("System Information:\n");
    kernel_print("  - Architecture: x86_64\n");
    kernel_print("  - Memory: 128 MB\n");
    kernel_print("  - File Systems: NTFS, ExFAT, Ext4, APFS\n");
    kernel_print("  - Network: TCP/IP stack enabled\n");
    kernel_print("  - C2 Server: Active on port 4444\n");
    kernel_print("\n");
    printf("\033[0m");
}

void show_help(void) {
    printf("\033[93m");
    kernel_print("\n=== File Operations ===\n");
    printf("\033[0m");
    kernel_print("  ls          - List directory contents\n");
    kernel_print("  cd          - Change directory\n");
    kernel_print("  pwd         - Print working directory\n");
    kernel_print("  cat         - Display file contents\n");
    kernel_print("  mkdir       - Create directory\n");
    kernel_print("  rm          - Remove file\n");
    kernel_print("  cp          - Copy file\n");
    kernel_print("  mv          - Move file\n");
    
    printf("\033[93m");
    kernel_print("\n=== System Commands ===\n");
    printf("\033[0m");
    kernel_print("  ps          - Process list\n");
    kernel_print("  free        - Memory usage\n");
    kernel_print("  uname       - System information\n");
    kernel_print("  ifconfig    - Network configuration\n");
    
    printf("\033[91m");
    kernel_print("\n=== C2 Operations ===\n");
    printf("\033[0m");
    kernel_print("  c2-status   - Show C2 server status\n");
    kernel_print("  c2-sessions - List active sessions\n");
    kernel_print("  c2-exploit  - Launch exploit\n");
    kernel_print("  c2-scan     - Network scan\n");
    
    printf("\033[93m");
    kernel_print("\n=== Other ===\n");
    printf("\033[0m");
    kernel_print("  help        - Show this help\n");
    kernel_print("  clear       - Clear screen\n");
    kernel_print("  exit        - Exit shell\n");
    kernel_print("\n");
}

void handle_command(char* cmd) {
    if (strcmp(cmd, "help") == 0) {
        show_help();
    } else if (strcmp(cmd, "clear") == 0) {
        kernel_clear_screen();
        print_banner();
    } else if (strcmp(cmd, "exit") == 0) {
        kernel_print("Exiting CardinalOS...\n");
        exit(0);
    } else if (strcmp(cmd, "pwd") == 0) {
        kernel_print("/root\n");
    } else if (strcmp(cmd, "uname") == 0) {
        kernel_print("CardinalOS 1.0.0 x86_64\n");
    } else if (strcmp(cmd, "free") == 0) {
        kernel_print("              total        used        free\n");
        kernel_print("Mem:      134217728    67108864    67108864\n");
    } else if (strcmp(cmd, "ps") == 0) {
        kernel_print("  PID  CMD\n");
        kernel_print("    1  init\n");
        kernel_print("    2  kernel\n");
        kernel_print("    3  c2-server\n");
    } else if (strcmp(cmd, "c2-status") == 0) {
        kernel_print("\n=== C2 Server Status ===\n");
        kernel_print("Status: ACTIVE\n");
        kernel_print("Port: 4444\n");
        kernel_print("Encryption: RC4\n");
        kernel_print("Active sessions: 0\n\n");
    } else if (strcmp(cmd, "c2-sessions") == 0) {
        kernel_print("\n=== Active C2 Sessions ===\n");
        kernel_print("ID  | IP Address      | Hostname        | Username    | OS\n");
        kernel_print("----+-----------------+-----------------+-------------+-------------------\n");
        kernel_print("No active sessions\n\n");
    } else if (strncmp(cmd, "c2-exploit", 10) == 0) {
        kernel_print("[*] Available exploits:\n");
        kernel_print("  ms17-010    EternalBlue (SMB)\n");
        kernel_print("  ms08-067    Windows Server Service RPC\n");
        kernel_print("  ms03-026    DCOM RPC Buffer Overflow\n");
        kernel_print("\nUsage: c2-exploit <name> <target_ip>\n");
    } else if (strncmp(cmd, "c2-scan", 7) == 0) {
        kernel_print("Usage: c2-scan <network>\n");
        kernel_print("Example: c2-scan 192.168.1.0/24\n");
    } else if (strcmp(cmd, "ls") == 0) {
        kernel_print("bin/  boot/  c2/  dev/  etc/  exploit/  home/  root/  tmp/  var/\n");
    } else if (strcmp(cmd, "") == 0) {
        // Empty command, do nothing
    } else {
        printf("%s: command not found\n", cmd);
    }
}

void shell_run(void) {
    char input[256];
    
    kernel_print("Starting CardinalOS shell...\n\n");
    
    while (1) {
        // Print prompt
        printf("\033[92m");  // Green
        printf("root");
        printf("\033[0m");
        printf("@");
        printf("\033[93m");  // Yellow
        printf("cardinalos");
        printf("\033[0m");
        printf(":");
        printf("\033[94m");  // Blue
        printf("/root");
        printf("\033[0m");
        printf("# ");
        
        // Read input
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
        
        // Handle command
        handle_command(input);
    }
}

int main(void) {
    // Set UTF-8 code page for proper character display
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // Enable virtual terminal processing for ANSI colors
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    
    // Print boot banner
    print_banner();
    
    // Initialize subsystems
    print_subsystem_init();
    
    // Print system info
    print_system_info();
    
    // Start shell
    shell_run();
    
    return 0;
}
