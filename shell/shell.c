/*
 * CardinalOS - Shell Implementation
 * Linux-compatible command interpreter
 */

#include "shell.h"
#include "../kernel/kernel.h"
#include "../c2/c2_core.h"
#include "../fs/vfs.h"

static char input_buffer[SHELL_BUFFER_SIZE];
static int input_pos = 0;
static char current_dir[256] = "/";

// Command table (Linux compatible + C2 extensions)
static shell_command_t commands[] = {
    // File operations
    {"ls", "List directory contents", cmd_ls},
    {"cd", "Change directory", cmd_cd},
    {"pwd", "Print working directory", cmd_pwd},
    {"cat", "Concatenate and display files", cmd_cat},
    {"echo", "Display a line of text", cmd_echo},
    {"mkdir", "Make directories", cmd_mkdir},
    {"rm", "Remove files or directories", cmd_rm},
    {"cp", "Copy files", cmd_cp},
    {"mv", "Move/rename files", cmd_mv},
    {"touch", "Create empty file", cmd_touch},
    {"grep", "Search text patterns", cmd_grep},
    {"find", "Search for files", cmd_find},
    
    // Process management
    {"ps", "Report process status", cmd_ps},
    {"kill", "Send signal to process", cmd_kill},
    {"top", "Display processes", cmd_top},
    
    // Filesystem
    {"mount", "Mount filesystem", cmd_mount},
    {"umount", "Unmount filesystem", cmd_umount},
    {"df", "Report filesystem disk space", cmd_df},
    {"du", "Estimate file space usage", cmd_du},
    
    // System info
    {"free", "Display memory usage", cmd_free},
    {"uname", "Print system information", cmd_uname},
    {"hostname", "Show or set hostname", cmd_hostname},
    
    // Network
    {"ifconfig", "Configure network interface", cmd_ifconfig},
    {"ping", "Send ICMP ECHO_REQUEST", cmd_ping},
    {"netstat", "Network statistics", cmd_netstat},
    {"route", "Show/manipulate routing table", cmd_route},
    
    // C2 commands
    {"c2-status", "Show C2 server status", cmd_c2_status},
    {"c2-sessions", "List active C2 sessions", cmd_c2_sessions},
    {"c2-interact", "Interact with C2 session", cmd_c2_interact},
    {"c2-exploit", "Launch exploit", cmd_c2_exploit},
    {"c2-scan", "Scan network for targets", cmd_c2_scan},
    {"c2-lateral", "Perform lateral movement", cmd_c2_lateral},
    
    // System
    {"help", "Show available commands", cmd_help},
    {"clear", "Clear screen", cmd_clear},
    {"exit", "Exit shell", cmd_exit},
    {"reboot", "Reboot system", cmd_reboot},
    {"shutdown", "Shutdown system", cmd_shutdown},
    
    {NULL, NULL, NULL}
};

void shell_init(void) {
    kernel_print("CardinalOS Shell v1.0\n");
    kernel_print("Type 'help' for available commands\n\n");
}

void shell_prompt(void) {
    kernel_print_color("root", 0x0A);
    kernel_print("@");
    kernel_print_color("cardinalos", 0x0E);
    kernel_print(":");
    kernel_print_color(current_dir, 0x09);
    kernel_print("# ");
}

int shell_parse(char* input, char** argv) {
    int argc = 0;
    char* token = input;
    
    while (*token && argc < MAX_ARGS) {
        // Skip whitespace
        while (*token == ' ' || *token == '\t') token++;
        
        if (*token == '\0') break;
        
        argv[argc++] = token;
        
        // Find end of token
        while (*token && *token != ' ' && *token != '\t') token++;
        
        if (*token) {
            *token = '\0';
            token++;
        }
    }
    
    return argc;
}

void shell_execute(int argc, char** argv) {
    if (argc == 0) return;
    
    // Find and execute command
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(argv[0], commands[i].name) == 0) {
            commands[i].handler(argc, argv);
            return;
        }
    }
    
    kernel_printf("%s: command not found\n", argv[0]);
}

void shell_run(void) {
    char* argv[MAX_ARGS];
    
    while (1) {
        shell_prompt();
        
        // Read input (simplified - would use keyboard driver)
        // TODO: Implement keyboard input
        
        // For now, just show prompt
        // In real implementation, would read from keyboard
        break;
    }
}

// Command implementations

void cmd_help(int argc, char** argv) {
    kernel_print("\nAvailable commands:\n\n");
    
    kernel_print_color("=== File Operations ===\n", 0x0E);
    for (int i = 0; commands[i].name != NULL; i++) {
        if (i >= 0 && i <= 11) {
            kernel_printf("  %-12s - %s\n", commands[i].name, commands[i].description);
        }
    }
    
    kernel_print_color("\n=== Process Management ===\n", 0x0E);
    for (int i = 12; i <= 14; i++) {
        kernel_printf("  %-12s - %s\n", commands[i].name, commands[i].description);
    }
    
    kernel_print_color("\n=== C2 Operations ===\n", 0x0C);
    for (int i = 23; i <= 28; i++) {
        kernel_printf("  %-12s - %s\n", commands[i].name, commands[i].description);
    }
    
    kernel_print("\n");
}

void cmd_clear(int argc, char** argv) {
    kernel_clear_screen();
}

void cmd_pwd(int argc, char** argv) {
    kernel_printf("%s\n", current_dir);
}

void cmd_uname(int argc, char** argv) {
    kernel_print("CardinalOS 1.0.0 x86_64\n");
}

void cmd_hostname(int argc, char** argv) {
    kernel_print("cardinalos\n");
}

void cmd_free(int argc, char** argv) {
    kernel_print("              total        used        free\n");
    kernel_printf("Mem:    %10lu  %10lu  %10lu\n", 
        memory_get_total(), 
        memory_get_total() / 2,  // Placeholder
        memory_get_total() / 2); // Placeholder
}

void cmd_ps(int argc, char** argv) {
    kernel_print("  PID  CMD\n");
    kernel_print("    1  init\n");
    kernel_print("    2  kernel\n");
    kernel_print("    3  c2-server\n");
}

void cmd_ls(int argc, char** argv) {
    kernel_print(".\n..\n");
    // TODO: Implement directory listing using VFS
}

void cmd_cd(int argc, char** argv) {
    if (argc < 2) {
        strcpy(current_dir, "/");
    } else {
        // TODO: Validate and change directory
        strncpy(current_dir, argv[1], sizeof(current_dir) - 1);
    }
}

// C2 commands

void cmd_c2_status(int argc, char** argv) {
    kernel_print("\n=== C2 Server Status ===\n");
    kernel_print("Status: ACTIVE\n");
    kernel_printf("Port: %d\n", C2_DEFAULT_PORT);
    kernel_print("Encryption: RC4\n");
    kernel_print("Active sessions: 0\n\n");
}

void cmd_c2_sessions(int argc, char** argv) {
    c2_list_sessions();
}

void cmd_c2_exploit(int argc, char** argv) {
    if (argc < 3) {
        kernel_print("Usage: c2-exploit <exploit_name> <target_ip>\n");
        kernel_print("Available exploits:\n");
        kernel_print("  ms17-010    EternalBlue (SMB)\n");
        kernel_print("  ms08-067    Windows Server Service RPC\n");
        return;
    }
    
    // Parse target IP (simplified)
    kernel_printf("[*] Launching %s against %s\n", argv[1], argv[2]);
}

void cmd_c2_scan(int argc, char** argv) {
    if (argc < 2) {
        kernel_print("Usage: c2-scan <network>\n");
        kernel_print("Example: c2-scan 192.168.1.0/24\n");
        return;
    }
    
    kernel_printf("[*] Scanning network: %s\n", argv[1]);
    // TODO: Implement network scanning
}

void cmd_exit(int argc, char** argv) {
    kernel_print("Exiting shell...\n");
    // Exit shell loop
}

void cmd_reboot(int argc, char** argv) {
    kernel_print("Rebooting system...\n");
    // TODO: Implement reboot
}

void cmd_shutdown(int argc, char** argv) {
    kernel_print("Shutting down system...\n");
    // TODO: Implement shutdown
}

// Stub implementations for other commands
void cmd_cat(int argc, char** argv) { kernel_print("cat: not yet implemented\n"); }
void cmd_echo(int argc, char** argv) { 
    for (int i = 1; i < argc; i++) {
        kernel_print(argv[i]);
        if (i < argc - 1) kernel_print(" ");
    }
    kernel_print("\n");
}
void cmd_mkdir(int argc, char** argv) { kernel_print("mkdir: not yet implemented\n"); }
void cmd_rm(int argc, char** argv) { kernel_print("rm: not yet implemented\n"); }
void cmd_cp(int argc, char** argv) { kernel_print("cp: not yet implemented\n"); }
void cmd_mv(int argc, char** argv) { kernel_print("mv: not yet implemented\n"); }
void cmd_touch(int argc, char** argv) { kernel_print("touch: not yet implemented\n"); }
void cmd_grep(int argc, char** argv) { kernel_print("grep: not yet implemented\n"); }
void cmd_find(int argc, char** argv) { kernel_print("find: not yet implemented\n"); }
void cmd_kill(int argc, char** argv) { kernel_print("kill: not yet implemented\n"); }
void cmd_top(int argc, char** argv) { kernel_print("top: not yet implemented\n"); }
void cmd_mount(int argc, char** argv) { kernel_print("mount: not yet implemented\n"); }
void cmd_umount(int argc, char** argv) { kernel_print("umount: not yet implemented\n"); }
void cmd_df(int argc, char** argv) { kernel_print("df: not yet implemented\n"); }
void cmd_du(int argc, char** argv) { kernel_print("du: not yet implemented\n"); }
void cmd_ifconfig(int argc, char** argv) { kernel_print("ifconfig: not yet implemented\n"); }
void cmd_ping(int argc, char** argv) { kernel_print("ping: not yet implemented\n"); }
void cmd_netstat(int argc, char** argv) { kernel_print("netstat: not yet implemented\n"); }
void cmd_route(int argc, char** argv) { kernel_print("route: not yet implemented\n"); }
void cmd_c2_interact(int argc, char** argv) { kernel_print("c2-interact: not yet implemented\n"); }
void cmd_c2_lateral(int argc, char** argv) { kernel_print("c2-lateral: not yet implemented\n"); }
