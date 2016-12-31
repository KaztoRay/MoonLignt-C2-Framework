/*
 * CardinalOS v4.0.0 - Enterprise Edition
 * Advanced Operating System with GUI Support, Security Features, and ISO Generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <windows.h>
#include <time.h>
#include <conio.h>

// System Configuration
#define VERSION "4.0.0-enterprise"
#define MAX_DIRS 500
#define MAX_FILES 1000
#define MAX_USERS 50
#define MAX_PROCESSES 100
#define MEMORY_SIZE (512 * 1024 * 1024)  // 512MB

// User Permissions
#define PERM_READ    0x01
#define PERM_WRITE   0x02
#define PERM_EXECUTE 0x04
#define PERM_ADMIN   0x08

// Security Levels
typedef enum {
    SECURITY_LOW = 0,
    SECURITY_MEDIUM = 1,
    SECURITY_HIGH = 2,
    SECURITY_PARANOID = 3
} security_level_t;

// User structure
typedef struct {
    char username[64];
    char password_hash[128];
    int uid;
    int gid;
    uint8_t permissions;
    bool is_admin;
    bool logged_in;
    time_t last_login;
    int failed_attempts;
} user_t;

// File structure
typedef struct {
    char name[128];
    char path[256];
    uint8_t permissions;
    int owner_uid;
    int group_gid;
    size_t size;
    time_t created;
    time_t modified;
    time_t accessed;
    bool is_directory;
    bool is_hidden;
    bool is_encrypted;
    char content[4096];
} file_t;

// Process structure
typedef struct {
    int pid;
    int ppid;
    char name[64];
    int uid;
    int priority;
    size_t memory;
    float cpu_usage;
    time_t start_time;
    bool is_running;
    bool is_hidden;
} process_t;

// System state
typedef struct {
    char hostname[64];
    char kernel_version[32];
    security_level_t security_level;
    bool firewall_enabled;
    bool selinux_enabled;
    bool audit_enabled;
    size_t total_memory;
    size_t used_memory;
    int cpu_count;
    float cpu_usage;
    time_t boot_time;
    int active_sessions;
    bool desktop_mode;
} system_state_t;

// Global variables
static file_t files[MAX_FILES];
static int file_count = 0;
static user_t users[MAX_USERS];
static int user_count = 0;
static process_t processes[MAX_PROCESSES];
static int process_count = 0;
static system_state_t system_state;
static user_t* current_user = NULL;
static char current_dir[256] = "/root";
static bool gui_mode = false;

// Function prototypes
void init_system(void);
void init_users(void);
void init_filesystem_advanced(void);
void init_processes(void);
void create_file_advanced(const char* path, const char* content, uint8_t permissions);
void create_dir_advanced(const char* path, uint8_t permissions);
bool authenticate_user(const char* username, const char* password);
bool check_permission(const char* path, uint8_t required_perm);
void start_gui_desktop(void);
void generate_iso_image(void);
void print_security_status(void);
void manage_firewall(const char* action);
void audit_log(const char* action, const char* details);

// Utility functions
void sleep_ms(int ms) { Sleep(ms); }

void kernel_clear_screen(void) {
    system("cls");
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

// Simple hash function for passwords (for demo - use bcrypt in production)
unsigned long hash_password(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

void init_users(void) {
    user_count = 0;
    
    // Root user
    users[user_count].uid = 0;
    users[user_count].gid = 0;
    strcpy(users[user_count].username, "root");
    sprintf(users[user_count].password_hash, "%lu", hash_password("toor"));
    users[user_count].permissions = PERM_READ | PERM_WRITE | PERM_EXECUTE | PERM_ADMIN;
    users[user_count].is_admin = true;
    users[user_count].logged_in = true;
    users[user_count].failed_attempts = 0;
    users[user_count].last_login = time(NULL);
    current_user = &users[user_count];
    user_count++;
    
    // Regular users
    const char* user_names[] = {"admin", "user", "operator", "security", "audit"};
    for (int i = 0; i < 5; i++) {
        users[user_count].uid = 1000 + i;
        users[user_count].gid = 1000 + i;
        strcpy(users[user_count].username, user_names[i]);
        sprintf(users[user_count].password_hash, "%lu", hash_password("password"));
        users[user_count].permissions = PERM_READ | PERM_EXECUTE;
        users[user_count].is_admin = (i == 0);
        users[user_count].logged_in = false;
        users[user_count].failed_attempts = 0;
        user_count++;
    }
}

void init_filesystem_advanced(void) {
    file_count = 0;
    
    // Linux standard directories
    const char* linux_dirs[] = {
        "/", "/root", "/home", "/bin", "/sbin", "/boot", "/dev", "/etc", 
        "/lib", "/lib64", "/opt", "/proc", "/sys", "/tmp", "/usr", "/var",
        "/mnt", "/media", "/srv", "/run",
        "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/share",
        "/usr/include", "/usr/src",
        "/var/log", "/var/tmp", "/var/cache", "/var/lib", "/var/spool",
        "/var/mail", "/var/run", "/var/lock",
        "/etc/init.d", "/etc/systemd", "/etc/network", "/etc/security",
        "/home/admin", "/home/user", "/home/operator",
        "/opt/cardinal", "/opt/exploits", "/opt/tools",
        
        // CardinalOS specific
        "/cardinal", "/cardinal/c2", "/cardinal/exploits", "/cardinal/payloads",
        "/cardinal/logs", "/cardinal/tools", "/cardinal/modules",
        "/cardinal/config", "/cardinal/database", "/cardinal/sessions"
    };
    
    for (int i = 0; i < sizeof(linux_dirs) / sizeof(linux_dirs[0]); i++) {
        create_dir_advanced(linux_dirs[i], PERM_READ | PERM_EXECUTE);
    }
    
    // DOS directories
    const char* dos_dirs[] = {
        "C:", "C:/WINDOWS", "C:/WINDOWS/System32", "C:/WINDOWS/System",
        "C:/Program Files", "C:/Program Files (x86)", "C:/Users",
        "C:/Users/Administrator", "C:/Users/Public", "C:/Temp",
        "C:/ProgramData", "C:/DOS"
    };
    
    for (int i = 0; i < sizeof(dos_dirs) / sizeof(dos_dirs[0]); i++) {
        create_dir_advanced(dos_dirs[i], PERM_READ | PERM_EXECUTE);
    }
    
    // Create configuration files
    create_file_advanced("/etc/hostname", "cardinalos-enterprise\n", PERM_READ);
    create_file_advanced("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n192.168.1.100 cardinalos\n", PERM_READ);
    create_file_advanced("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", PERM_READ);
    create_file_advanced("/etc/shadow", "root:$6$encrypted$hash:18000:0:99999:7:::\n", PERM_ADMIN);
    create_file_advanced("/etc/group", "root:x:0:\nadmin:x:1000:\n", PERM_READ);
    create_file_advanced("/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n", PERM_READ);
    create_file_advanced("/etc/network/interfaces", "auto eth0\niface eth0 inet dhcp\n", PERM_READ | PERM_WRITE);
    
    create_file_advanced("/root/.bashrc", "# CardinalOS bash configuration\nPS1='\\u@\\h:\\w\\$ '\n", PERM_READ | PERM_WRITE);
    create_file_advanced("/root/.bash_profile", "# Profile\n", PERM_READ | PERM_WRITE);
    
    create_file_advanced("/var/log/syslog", "", PERM_READ | PERM_WRITE);
    create_file_advanced("/var/log/auth.log", "", PERM_ADMIN);
    create_file_advanced("/var/log/kern.log", "", PERM_READ);
    
    create_file_advanced("/cardinal/config/c2.conf", "port=4444\nencryption=aes256\n", PERM_ADMIN);
    create_file_advanced("/cardinal/database/exploits.db", "# Exploit database\n", PERM_READ);
    
    create_file_advanced("C:/AUTOEXEC.BAT", "@ECHO OFF\nPROMPT $P$G\n", PERM_READ | PERM_EXECUTE);
    create_file_advanced("C:/CONFIG.SYS", "FILES=30\nBUFFERS=20\n", PERM_READ);
}

void create_dir_advanced(const char* path, uint8_t permissions) {
    if (file_count >= MAX_FILES) return;
    
    strcpy(files[file_count].path, path);
    strcpy(files[file_count].name, strrchr(path, '/') ? strrchr(path, '/') + 1 : path);
    files[file_count].is_directory = true;
    files[file_count].permissions = permissions;
    files[file_count].owner_uid = current_user ? current_user->uid : 0;
    files[file_count].group_gid = current_user ? current_user->gid : 0;
    files[file_count].size = 4096;
    files[file_count].created = time(NULL);
    files[file_count].modified = time(NULL);
    files[file_count].accessed = time(NULL);
    files[file_count].is_hidden = false;
    files[file_count].is_encrypted = false;
    file_count++;
}

void create_file_advanced(const char* path, const char* content, uint8_t permissions) {
    if (file_count >= MAX_FILES) return;
    
    strcpy(files[file_count].path, path);
    strcpy(files[file_count].name, strrchr(path, '/') ? strrchr(path, '/') + 1 : path);
    files[file_count].is_directory = false;
    files[file_count].permissions = permissions;
    files[file_count].owner_uid = current_user ? current_user->uid : 0;
    files[file_count].group_gid = current_user ? current_user->gid : 0;
    strncpy(files[file_count].content, content, sizeof(files[file_count].content) - 1);
    files[file_count].size = strlen(content);
    files[file_count].created = time(NULL);
    files[file_count].modified = time(NULL);
    files[file_count].accessed = time(NULL);
    files[file_count].is_hidden = false;
    files[file_count].is_encrypted = false;
    file_count++;
}

void init_processes(void) {
    process_count = 0;
    
    // System processes
    const char* proc_names[] = {
        "init", "kthreadd", "ksoftirqd/0", "kworker/0:0", "systemd",
        "cardinalos-kernel", "cardinalos-c2", "exploit-daemon",
        "network-manager", "firewall", "audit-daemon", "security-monitor",
        "encryption-service", "stealth-agent", "persistence-manager"
    };
    
    for (int i = 0; i < 15; i++) {
        processes[process_count].pid = i + 1;
        processes[process_count].ppid = i == 0 ? 0 : 1;
        strcpy(processes[process_count].name, proc_names[i]);
        processes[process_count].uid = i < 5 ? 0 : current_user->uid;
        processes[process_count].priority = 20 - (i % 10);
        processes[process_count].memory = (rand() % 50000) + 10000;
        processes[process_count].cpu_usage = (float)(rand() % 100) / 10.0f;
        processes[process_count].start_time = time(NULL) - (rand() % 3600);
        processes[process_count].is_running = true;
        processes[process_count].is_hidden = i >= 10;
        process_count++;
    }
}

void init_system(void) {
    strcpy(system_state.hostname, "cardinalos-enterprise");
    strcpy(system_state.kernel_version, VERSION);
    system_state.security_level = SECURITY_HIGH;
    system_state.firewall_enabled = true;
    system_state.selinux_enabled = true;
    system_state.audit_enabled = true;
    system_state.total_memory = MEMORY_SIZE;
    system_state.used_memory = MEMORY_SIZE / 3;
    system_state.cpu_count = 4;
    system_state.cpu_usage = 15.5f;
    system_state.boot_time = time(NULL);
    system_state.active_sessions = 1;
    system_state.desktop_mode = false;
    
    init_users();
    init_filesystem_advanced();
    init_processes();
}

file_t* find_file(const char* path) {
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].path, path) == 0) {
            return &files[i];
        }
    }
    return NULL;
}

bool check_permission(const char* path, uint8_t required_perm) {
    if (!current_user) return false;
    if (current_user->is_admin) return true;
    
    file_t* file = find_file(path);
    if (!file) return false;
    
    if (file->owner_uid == current_user->uid) {
        return (file->permissions & required_perm) != 0;
    }
    
    return false;
}

void list_directory_advanced(const char* path) {
    int found = 0;
    int file_count_dir = 0;
    int dir_count_dir = 0;
    
    printf("\033[96m");
    printf("Directory: %s\n", path);
    printf("Permissions: ");
    if (check_permission(path, PERM_READ)) printf("r");
    if (check_permission(path, PERM_WRITE)) printf("w");
    if (check_permission(path, PERM_EXECUTE)) printf("x");
    printf("\n\n");
    printf("\033[0m");
    
    for (int i = 0; i < file_count; i++) {
        if (strncmp(files[i].path, path, strlen(path)) == 0) {
            const char* remainder = files[i].path + strlen(path);
            if (*remainder == '/') remainder++;
            
            if (strchr(remainder, '/') == NULL && strlen(remainder) > 0) {
                if (files[i].is_directory) {
                    printf("\033[94m[DIR]\033[0m  ");
                    dir_count_dir++;
                } else {
                    printf("\033[92m[FILE]\033[0m ");
                    file_count_dir++;
                }
                
                printf("%-30s ", remainder);
                printf("%8zu bytes  ", files[i].size);
                
                char time_str[64];
                struct tm* tm_info = localtime(&files[i].modified);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
                printf("%s", time_str);
                
                if (files[i].is_encrypted) printf("  \033[93m[ENC]\033[0m");
                if (files[i].is_hidden) printf("  \033[90m[HIDDEN]\033[0m");
                
                printf("\n");
                found = 1;
            }
        }
    }
    
    if (found) {
        printf("\n\033[96m%d directories, %d files\033[0m\n\n", dir_count_dir, file_count_dir);
    } else {
        printf("Directory is empty\n\n");
    }
}

void print_boot_sequence(void) {
    kernel_clear_screen();
    
    printf("\033[90m");
    printf("CardinalOS Enterprise BIOS v4.0.0\n");
    printf("Copyright (C) 2025 Cardinal Security Research Team\n");
    printf("Build: %s %s\n\n", __DATE__, __TIME__);
    printf("\033[0m");
    sleep_ms(200);
    
    printf("CPU: Intel Core i7-9700K @ 3.6GHz (8 cores)\n");
    printf("RAM: 512 MB DDR4 @ 3200 MHz\n");
    printf("Boot Device: /dev/nvme0n1p1 (NVMe SSD)\n");
    printf("Firmware: UEFI 2.8\n");
    printf("Secure Boot: \033[92mEnabled\033[0m\n");
    printf("TPM 2.0: \033[92mDetected\033[0m\n\n");
    sleep_ms(300);
    
    printf("\033[93mStarting CardinalOS Enterprise Kernel...\033[0m\n\n");
    sleep_ms(400);
    
    const char* boot_msgs[] = {
        "Loading unified kernel (Linux/DOS compatible)",
        "Initializing memory management (512MB)",
        "Setting up page tables and MMU",
        "Loading interrupt descriptor table (IDT)",
        "Initializing PCI/PCIe bus",
        "Detecting hardware devices",
        "Loading device drivers",
        "Mounting root filesystem (EXT4)",
        "Initializing virtual filesystem (VFS)",
        "Loading filesystem drivers (NTFS/EXT4/FAT32)",
        "Starting network subsystem",
        "Initializing TCP/IP stack (IPv4/IPv6)",
        "Loading network interface drivers",
        "Starting firewall (iptables/nftables)",
        "Enabling SELinux (Enforcing mode)",
        "Starting audit daemon",
        "Loading security modules",
        "Initializing cryptographic engines",
        "Starting C2 framework (Multi-protocol)",
        "Loading exploit database (200+ CVEs)",
        "Initializing stealth framework",
        "Starting anti-forensics engine",
        "Loading persistence manager",
        "Initializing GUI subsystem (X11 compatible)",
        "Starting desktop environment"
    };
    
    for (int i = 0; i < sizeof(boot_msgs) / sizeof(boot_msgs[0]); i++) {
        printf("\033[92m[  OK  ]\033[0m %s\n", boot_msgs[i]);
        sleep_ms(80 + (rand() % 100));
    }
    
    printf("\n");
    sleep_ms(200);
}

void print_banner(void) {
    kernel_clear_screen();
    print_boot_sequence();
    
    printf("\033[91m");
    printf("\n");
    printf("   ██████╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗ █████╗ ██╗      ██████╗ ███████╗\n");
    printf("  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗██║     ██╔═══██╗██╔════╝\n");
    printf("  ██║     ███████║██████╔╝██║  ██║██║██╔██╗ ██║███████║██║     ██║   ██║███████╗\n");
    printf("  ██║     ██╔══██║██╔══██╗██║  ██║██║██║╚██╗██║██╔══██║██║     ██║   ██║╚════██║\n");
    printf("  ╚██████╗██║  ██║██║  ██║██████╔╝██║██║ ╚████║██║  ██║███████╗╚██████╔╝███████║\n");
    printf("   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝\n");
    printf("\033[0m");
    
    printf("\033[93m");
    printf("\n          ⚠  ENTERPRISE ATTACK PLATFORM v4.0.0  ⚠\n");
    printf("\033[0m");
    
    printf("\033[97m");
    printf("\n          === ADVANCED SECURITY RESEARCH OS ===\n");
    printf("        Linux Kernel 6.1 + MS-DOS 6.22 + GUI Desktop\n");
    printf("          High-Performance | Military-Grade Security\n\n");
    printf("\033[0m");
    
    printf("\033[92m");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  ALL SYSTEMS OPERATIONAL - SECURITY LEVEL: HIGH              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
}

void print_security_status(void) {
    printf("\n\033[96m╔════════════════════════════════════════════╗\n");
    printf("║       SECURITY STATUS REPORT               ║\n");
    printf("╚════════════════════════════════════════════╝\033[0m\n\n");
    
    printf("Security Level:     ");
    switch (system_state.security_level) {
        case SECURITY_LOW: printf("\033[93mLOW\033[0m\n"); break;
        case SECURITY_MEDIUM: printf("\033[93mMEDIUM\033[0m\n"); break;
        case SECURITY_HIGH: printf("\033[92mHIGH\033[0m\n"); break;
        case SECURITY_PARANOID: printf("\033[91mPARANOID\033[0m\n"); break;
    }
    
    printf("Firewall:           %s\n", system_state.firewall_enabled ? "\033[92mENABLED\033[0m" : "\033[91mDISABLED\033[0m");
    printf("SELinux:            %s\n", system_state.selinux_enabled ? "\033[92mENFORCING\033[0m" : "\033[91mDISABLED\033[0m");
    printf("Audit:              %s\n", system_state.audit_enabled ? "\033[92mACTIVE\033[0m" : "\033[91mINACTIVE\033[0m");
    printf("Encryption:         \033[92mAES-256-GCM\033[0m\n");
    printf("Anti-Debug:         \033[92mACTIVE\033[0m\n");
    printf("Rootkit Detection:  \033[92mENABLED\033[0m\n");
    printf("Network Stealth:    \033[92mACTIVE\033[0m\n\n");
}

void audit_log(const char* action, const char* details) {
    if (!system_state.audit_enabled) return;
    
    time_t now = time(NULL);
    char timestamp[64];
    struct tm* tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("\033[90m[AUDIT] %s | User: %s | Action: %s | Details: %s\033[0m\n", 
           timestamp, 
           current_user ? current_user->username : "system", 
           action, 
           details);
}

void manage_firewall(const char* action) {
    if (strcmp(action, "enable") == 0) {
        system_state.firewall_enabled = true;
        audit_log("FIREWALL", "Firewall enabled");
        printf("\033[92mFirewall enabled\033[0m\n");
    } else if (strcmp(action, "disable") == 0) {
        if (!current_user || !current_user->is_admin) {
            printf("\033[91mPermission denied: Admin privileges required\033[0m\n");
            return;
        }
        system_state.firewall_enabled = false;
        audit_log("FIREWALL", "Firewall disabled");
        printf("\033[93mFirewall disabled\033[0m\n");
    } else if (strcmp(action, "status") == 0) {
        printf("Firewall: %s\n", system_state.firewall_enabled ? "\033[92mENABLED\033[0m" : "\033[91mDISABLED\033[0m");
    }
}

// Win32 GUI Desktop Environment
#ifdef _WIN32
#include <commctrl.h>
#include <shellapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

#define IDM_EXIT 1001
#define IDM_TERMINAL 1002
#define IDM_FILES 1003
#define IDM_ABOUT 1004
#define IDM_SECURITY 1005
#define IDM_PROCESSES 1006
#define IDM_NETWORK 1007
#define IDM_EXPLOITS 1008

HWND hwndDesktop = NULL;
HWND hwndTerminal = NULL;
HWND hwndTaskbar = NULL;
HWND hwndOutput = NULL;
bool desktop_running = false;

// Window procedure for desktop
LRESULT CALLBACK DesktopWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Create menu bar
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreatePopupMenu();
            HMENU hToolsMenu = CreatePopupMenu();
            HMENU hHelpMenu = CreatePopupMenu();
            
            AppendMenu(hFileMenu, MF_STRING, IDM_TERMINAL, "Terminal");
            AppendMenu(hFileMenu, MF_STRING, IDM_FILES, "File Manager");
            AppendMenu(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenu(hFileMenu, MF_STRING, IDM_EXIT, "Exit Desktop");
            
            AppendMenu(hToolsMenu, MF_STRING, IDM_SECURITY, "Security Dashboard");
            AppendMenu(hToolsMenu, MF_STRING, IDM_PROCESSES, "Process Monitor");
            AppendMenu(hToolsMenu, MF_STRING, IDM_NETWORK, "Network Analyzer");
            AppendMenu(hToolsMenu, MF_STRING, IDM_EXPLOITS, "Exploit Console");
            
            AppendMenu(hHelpMenu, MF_STRING, IDM_ABOUT, "About");
            
            AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, "File");
            AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, "Tools");
            AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, "Help");
            
            SetMenu(hwnd, hMenu);
            
            // Create taskbar at bottom
            hwndTaskbar = CreateWindowEx(
                0, "STATIC", "",
                WS_CHILD | WS_VISIBLE | SS_BLACKFRAME,
                0, 0, 0, 0,
                hwnd, NULL, GetModuleHandle(NULL), NULL
            );
            
            // Create desktop label
            CreateWindowEx(
                0, "STATIC", 
                "CardinalOS Desktop v4.0\r\nDouble-click icons to launch applications",
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                50, 50, 400, 60,
                hwnd, NULL, GetModuleHandle(NULL), NULL
            );
            
            // Create desktop icons
            CreateWindowEx(
                0, "BUTTON", "Terminal",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                50, 150, 100, 80,
                hwnd, (HMENU)IDM_TERMINAL, GetModuleHandle(NULL), NULL
            );
            
            CreateWindowEx(
                0, "BUTTON", "File Manager",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 150, 100, 80,
                hwnd, (HMENU)IDM_FILES, GetModuleHandle(NULL), NULL
            );
            
            CreateWindowEx(
                0, "BUTTON", "Security",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                290, 150, 100, 80,
                hwnd, (HMENU)IDM_SECURITY, GetModuleHandle(NULL), NULL
            );
            
            CreateWindowEx(
                0, "BUTTON", "Processes",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                50, 250, 100, 80,
                hwnd, (HMENU)IDM_PROCESSES, GetModuleHandle(NULL), NULL
            );
            
            CreateWindowEx(
                0, "BUTTON", "Network",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 250, 100, 80,
                hwnd, (HMENU)IDM_NETWORK, GetModuleHandle(NULL), NULL
            );
            
            CreateWindowEx(
                0, "BUTTON", "Exploits",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                290, 250, 100, 80,
                hwnd, (HMENU)IDM_EXPLOITS, GetModuleHandle(NULL), NULL
            );
            
            break;
        }
        
        case WM_SIZE: {
            // Resize taskbar
            RECT rect;
            GetClientRect(hwnd, &rect);
            MoveWindow(hwndTaskbar, 0, rect.bottom - 40, rect.right, 40, TRUE);
            break;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDM_EXIT:
                    desktop_running = false;
                    PostQuitMessage(0);
                    break;
                    
                case IDM_TERMINAL: {
                    MessageBox(hwnd, 
                        "Terminal window launched.\r\n\r\n"
                        "Available commands:\r\n"
                        "• ls, dir - List files\r\n"
                        "• cd - Change directory\r\n"
                        "• ifconfig, netstat - Network\r\n"
                        "• ps, tasklist - Processes\r\n"
                        "• exploit-db - Exploits",
                        "Cardinal Terminal", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_FILES: {
                    // Show file manager dialog
                    char fileList[2048] = "Root Directories:\r\n\r\n";
                    for (int i = 0; i < file_count && i < 20; i++) {
                        if (files[i].is_directory && strchr(files[i].path + 1, '/') == NULL) {
                            strcat(fileList, files[i].path);
                            strcat(fileList, "\r\n");
                        }
                    }
                    MessageBox(hwnd, fileList, "Cardinal File Manager", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_SECURITY: {
                    char secMsg[512];
                    sprintf(secMsg,
                        "Security Status:\r\n\r\n"
                        "Security Level: %s\r\n"
                        "Firewall: %s\r\n"
                        "SELinux: %s\r\n"
                        "Audit: %s\r\n"
                        "Encryption: AES-256-GCM\r\n"
                        "Anti-Debug: ACTIVE",
                        system_state.security_level == SECURITY_HIGH ? "HIGH" : "MEDIUM",
                        system_state.firewall_enabled ? "ENABLED" : "DISABLED",
                        system_state.selinux_enabled ? "ENFORCING" : "DISABLED",
                        system_state.audit_enabled ? "ACTIVE" : "INACTIVE"
                    );
                    MessageBox(hwnd, secMsg, "Security Dashboard", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_PROCESSES: {
                    char procList[2048] = "Running Processes:\r\n\r\n";
                    char temp[128];
                    for (int i = 0; i < process_count && i < 15; i++) {
                        if (processes[i].is_running) {
                            sprintf(temp, "PID %d: %s (%.1f%% CPU)\r\n", 
                                   processes[i].pid, processes[i].name, processes[i].cpu_usage);
                            strcat(procList, temp);
                        }
                    }
                    MessageBox(hwnd, procList, "Process Monitor", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_NETWORK: {
                    MessageBox(hwnd,
                        "Network Interfaces:\r\n\r\n"
                        "eth0: 192.168.1.100/24\r\n"
                        "  Status: UP\r\n"
                        "  RX: 8.9 MB\r\n"
                        "  TX: 1.8 MB\r\n\r\n"
                        "lo: 127.0.0.1/8\r\n"
                        "  Status: UP\r\n"
                        "  Loopback interface",
                        "Network Analyzer", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_EXPLOITS: {
                    MessageBox(hwnd,
                        "Exploit Database (200+ CVEs):\r\n\r\n"
                        "1. MS17-010 - EternalBlue SMB RCE [CRITICAL]\r\n"
                        "2. MS08-067 - Windows Server RCE [CRITICAL]\r\n"
                        "3. CVE-2021-44228 - Log4Shell RCE [CRITICAL]\r\n"
                        "4. CVE-2014-0160 - Heartbleed SSL [HIGH]\r\n"
                        "5. CVE-2017-5638 - Apache Struts2 RCE [CRITICAL]\r\n"
                        "6. CVE-2019-0708 - BlueKeep RDP RCE [CRITICAL]\r\n"
                        "7. CVE-2020-1472 - Zerologon Domain [CRITICAL]\r\n"
                        "8. CVE-2021-26855 - ProxyLogon Exchange [CRITICAL]\r\n\r\n"
                        "Use terminal 'exploit-db' for full list",
                        "Exploit Console", MB_ICONINFORMATION);
                    break;
                }
                
                case IDM_ABOUT: {
                    MessageBox(hwnd,
                        "CardinalOS Enterprise Edition v4.0.0\r\n\r\n"
                        "Advanced Security Research OS\r\n"
                        "Linux + DOS + GUI Desktop\r\n\r\n"
                        "Features:\r\n"
                        "• 300+ Unified Commands\r\n"
                        "• 200+ Exploit Database\r\n"
                        "• C2 Framework\r\n"
                        "• GUI Desktop Environment\r\n"
                        "• ISO Generation\r\n\r\n"
                        "Copyright © 2025 Cardinal Security Research Team",
                        "About CardinalOS", MB_ICONINFORMATION);
                    break;
                }
            }
            break;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Draw desktop background
            RECT rect;
            GetClientRect(hwnd, &rect);
            HBRUSH hBrush = CreateSolidBrush(RGB(30, 30, 40));
            FillRect(hdc, &rect, hBrush);
            DeleteObject(hBrush);
            
            // Draw taskbar background
            RECT taskbarRect = {0, rect.bottom - 40, rect.right, rect.bottom};
            HBRUSH hTaskbarBrush = CreateSolidBrush(RGB(20, 20, 30));
            FillRect(hdc, &taskbarRect, hTaskbarBrush);
            DeleteObject(hTaskbarBrush);
            
            // Draw taskbar text
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 255, 255));
            RECT textRect = {10, rect.bottom - 35, 400, rect.bottom - 5};
            
            char taskbarText[256];
            time_t now = time(NULL);
            struct tm* tm_info = localtime(&now);
            sprintf(taskbarText, "CardinalOS | %s@%s | %02d:%02d:%02d", 
                   current_user ? current_user->username : "root",
                   system_state.hostname,
                   tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
            DrawText(hdc, taskbarText, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            
            EndPaint(hwnd, &ps);
            break;
        }
        
        case WM_DESTROY:
            desktop_running = false;
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void start_gui_desktop(void) {
    if (gui_mode) {
        printf("\033[93mGUI Desktop is already running\033[0m\n");
        return;
    }
    
    printf("\033[96m");
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║        Starting CardinalOS Desktop Environment          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
    
    printf("Loading Win32 GUI subsystem...\n");
    sleep_ms(300);
    printf("Initializing window manager...\n");
    sleep_ms(300);
    printf("Creating desktop environment...\n");
    sleep_ms(300);
    printf("Loading taskbar and menu...\n");
    sleep_ms(300);
    printf("Initializing applications...\n");
    sleep_ms(300);
    
    gui_mode = true;
    system_state.desktop_mode = true;
    desktop_running = true;
    
    printf("\n\033[92m✓ Desktop GUI started\033[0m\n\n");
    
    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = DesktopWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "CardinalDesktop";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassEx(&wc)) {
        printf("\033[91mFailed to register window class\033[0m\n");
        gui_mode = false;
        system_state.desktop_mode = false;
        return;
    }
    
    // Create desktop window
    hwndDesktop = CreateWindowEx(
        0,
        "CardinalDesktop",
        "CardinalOS Desktop v4.0 - Enterprise Edition",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1024, 768,
        NULL, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (!hwndDesktop) {
        printf("\033[91mFailed to create desktop window\033[0m\n");
        gui_mode = false;
        system_state.desktop_mode = false;
        return;
    }
    
    ShowWindow(hwndDesktop, SW_SHOW);
    UpdateWindow(hwndDesktop);
    
    // Message loop
    MSG msg;
    while (desktop_running && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Cleanup
    DestroyWindow(hwndDesktop);
    UnregisterClass("CardinalDesktop", GetModuleHandle(NULL));
    
    gui_mode = false;
    system_state.desktop_mode = false;
    printf("\n\033[92mDesktop GUI closed\033[0m\n\n");
}
#else
void start_gui_desktop(void) {
    printf("\033[93mGUI Desktop is only available on Windows\033[0m\n");
}
#endif

void generate_iso_image(void) {
    printf("\033[96m");
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║          CardinalOS ISO Image Generator                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
    
    if (!current_user || !current_user->is_admin) {
        printf("\033[91mPermission denied: Admin privileges required\033[0m\n");
        return;
    }
    
    char iso_filename[256];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char date_str[32];
    strftime(date_str, sizeof(date_str), "%Y%m%d-%H%M%S", tm_info);
    sprintf(iso_filename, "CardinalOS-v%s-%s.iso", VERSION, date_str);
    
    printf("ISO Filename: \033[93m%s\033[0m\n\n", iso_filename);
    
    printf("Stage 1: Preparing filesystem image...\n");
    sleep_ms(800);
    printf("  ✓ Creating ext4 filesystem (512 MB)\n");
    sleep_ms(500);
    printf("  ✓ Mounting filesystem\n");
    sleep_ms(500);
    printf("  ✓ Copying %d files and directories\n", file_count);
    sleep_ms(800);
    
    printf("\nStage 2: Installing bootloader...\n");
    sleep_ms(800);
    printf("  ✓ Installing GRUB 2.06\n");
    sleep_ms(500);
    printf("  ✓ Configuring boot menu\n");
    sleep_ms(500);
    printf("  ✓ Writing MBR and GPT tables\n");
    sleep_ms(500);
    
    printf("\nStage 3: Building kernel image...\n");
    sleep_ms(800);
    printf("  ✓ Compiling Linux kernel 6.1\n");
    sleep_ms(1000);
    printf("  ✓ Building initramfs\n");
    sleep_ms(800);
    printf("  ✓ Including DOS compatibility layer\n");
    sleep_ms(500);
    
    printf("\nStage 4: Packaging system components...\n");
    sleep_ms(800);
    printf("  ✓ Bundling C2 framework\n");
    sleep_ms(500);
    printf("  ✓ Including exploit database (200+ CVEs)\n");
    sleep_ms(800);
    printf("  ✓ Adding security tools\n");
    sleep_ms(500);
    printf("  ✓ Packaging GUI desktop environment\n");
    sleep_ms(800);
    
    printf("\nStage 5: Creating ISO image...\n");
    sleep_ms(800);
    printf("  ✓ Running mkisofs/genisoimage\n");
    sleep_ms(1200);
    printf("  ✓ Making image bootable (hybrid UEFI/BIOS)\n");
    sleep_ms(800);
    printf("  ✓ Calculating checksums (MD5/SHA256)\n");
    sleep_ms(600);
    
    printf("\nStage 6: Finalizing...\n");
    sleep_ms(500);
    printf("  ✓ Verifying ISO integrity\n");
    sleep_ms(500);
    printf("  ✓ Creating torrent file\n");
    sleep_ms(400);
    printf("  ✓ Generating documentation\n");
    sleep_ms(400);
    
    printf("\n\033[92m");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            ISO IMAGE CREATED SUCCESSFULLY                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");
    
    printf("ISO Details:\n");
    printf("  File: %s\n", iso_filename);
    printf("  Size: 487 MB (511,705,088 bytes)\n");
    printf("  Type: Hybrid ISO (UEFI + BIOS)\n");
    printf("  Format: ISO 9660 + Joliet + Rock Ridge\n");
    printf("  MD5: a3c5f8e9d1b4a2c6e7f8a9b0c1d2e3f4\n");
    printf("  SHA256: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b\n\n");
    
    printf("\033[96mBoot Instructions:\033[0m\n");
    printf("  1. Write ISO to USB: dd if=%s of=/dev/sdX bs=4M\n", iso_filename);
    printf("  2. Or burn to DVD-R using any ISO burning software\n");
    printf("  3. Boot from USB/DVD in UEFI or Legacy BIOS mode\n");
    printf("  4. Follow on-screen installation wizard\n\n");
    
    audit_log("ISO_GENERATION", iso_filename);
}

void handle_command_advanced(char* input) {
    if (!input || strlen(input) == 0) return;
    
    // Parse command and arguments
    char* args[20] = {0};
    int argc = 0;
    char* token = strtok(input, " \t\n");
    while (token != NULL && argc < 20) {
        args[argc++] = token;
        token = strtok(NULL, " \t\n");
    }
    
    if (argc == 0) return;
    
    const char* cmd = args[0];
    
    // DOS Commands
    if (strcmp(cmd, "copy") == 0 || strcmp(cmd, "xcopy") == 0) {
        if (argc < 3) {
            printf("Usage: copy <source> <destination>\n");
        } else {
            printf("Copying %s to %s...\n", args[1], args[2]);
            printf("1 file(s) copied.\n");
        }
    }
    else if (strcmp(cmd, "del") == 0 || strcmp(cmd, "erase") == 0) {
        if (argc < 2) {
            printf("Usage: del <file>\n");
        } else {
            printf("Deleting %s...\n", args[1]);
            audit_log("DELETE", args[1]);
        }
    }
    else if (strcmp(cmd, "ren") == 0 || strcmp(cmd, "rename") == 0) {
        if (argc < 3) {
            printf("Usage: ren <oldname> <newname>\n");
        } else {
            printf("Renaming %s to %s...\n", args[1], args[2]);
        }
    }
    else if (strcmp(cmd, "move") == 0) {
        if (argc < 3) {
            printf("Usage: move <source> <destination>\n");
        } else {
            printf("Moving %s to %s...\n", args[1], args[2]);
            printf("1 file(s) moved.\n");
        }
    }
    else if (strcmp(cmd, "attrib") == 0) {
        if (argc < 2) {
            printf("Usage: attrib [+R | -R] [+H | -H] <file>\n");
        } else {
            printf("Attributes for %s:\n", args[1]);
            printf("  A  SH     %s\n", args[1]);
        }
    }
    else if (strcmp(cmd, "tree") == 0) {
        printf("\n");
        printf("Folder PATH listing\n");
        printf("Volume serial number is 1A2B-3C4D\n");
        printf("%s\n", current_dir);
        printf("│\n");
        for (int i = 0; i < file_count && i < 10; i++) {
            if (files[i].is_directory && strstr(files[i].path, current_dir) == files[i].path) {
                printf("├───%s\n", files[i].name);
            }
        }
        printf("\n");
    }
    else if (strcmp(cmd, "vol") == 0) {
        printf(" Volume in drive C is CARDINAL\n");
        printf(" Volume Serial Number is 1A2B-3C4D\n\n");
    }
    else if (strcmp(cmd, "label") == 0) {
        printf("Volume in drive C is CARDINAL\n");
        printf("Volume Serial Number is 1A2B-3C4D\n");
        if (argc > 1) {
            printf("Volume label changed to %s\n", args[1]);
        }
    }
    else if (strcmp(cmd, "path") == 0) {
        printf("PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin;C:\\WINDOWS\\system32;C:\\WINDOWS\n");
    }
    else if (strcmp(cmd, "prompt") == 0) {
        printf("Current prompt: $P$G\n");
    }
    else if (strcmp(cmd, "doskey") == 0) {
        printf("DOSKey installed.\n");
        printf("Available macros:\n");
        printf("  ll = ls -la\n");
        printf("  .. = cd ..\n");
        printf("  cls = clear\n");
    }
    else if (strcmp(cmd, "mem") == 0 || strcmp(cmd, "memory") == 0) {
        printf("\nMemory Type        Total       Used       Free\n");
        printf("────────────────────────────────────────────────\n");
        printf("Conventional    %8zu  %8zu  %8zu\n", 
               system_state.total_memory, 
               system_state.used_memory,
               system_state.total_memory - system_state.used_memory);
        printf("Extended        %8zu  %8zu  %8zu\n",
               system_state.total_memory,
               system_state.used_memory / 2,
               system_state.total_memory - system_state.used_memory / 2);
        printf("Total memory    %8zu KB\n\n", system_state.total_memory / 1024);
    }
    else if (strcmp(cmd, "chkdsk") == 0 || strcmp(cmd, "scandisk") == 0) {
        printf("\nChecking disk...\n\n");
        printf("The type of the file system is EXT4.\n");
        printf("Volume label is CARDINAL.\n\n");
        sleep_ms(500);
        printf("Stage 1: Examining basic file system structure...\n");
        sleep_ms(800);
        printf("  512 file records processed.\n");
        sleep_ms(500);
        printf("\nStage 2: Examining file name linkage...\n");
        sleep_ms(800);
        printf("  612 index entries processed.\n");
        sleep_ms(500);
        printf("\nStage 3: Examining security descriptors...\n");
        sleep_ms(800);
        printf("  Security descriptors verified.\n\n");
        printf("Windows has scanned the file system and found no problems.\n");
        printf("No further action is required.\n\n");
        printf("  536870912 KB total disk space.\n");
        printf("  257294336 KB in 512 files.\n");
        printf("  279576576 KB available.\n\n");
    }
    else if (strcmp(cmd, "format") == 0) {
        if (argc < 2) {
            printf("Usage: format <drive>\n");
        } else {
            printf("\033[91mWARNING: ALL DATA ON %s WILL BE LOST!\033[0m\n", args[1]);
            printf("Proceed with Format (Y/N)? ");
            printf("N\n[Cancelled]\n");
        }
    }
    else if (strcmp(cmd, "diskpart") == 0) {
        printf("\nMicrosoft DiskPart version 10.0.19041.1\n\n");
        printf("DISKPART> list disk\n\n");
        printf("  Disk ###  Status         Size     Free     Dyn  Gpt\n");
        printf("  ────────  ─────────────  ───────  ───────  ───  ───\n");
        printf("  Disk 0    Online          512 GB   245 GB        *\n\n");
    }
    else if (strcmp(cmd, "comp") == 0 || strcmp(cmd, "fc") == 0) {
        if (argc < 3) {
            printf("Usage: %s <file1> <file2>\n", cmd);
        } else {
            printf("Comparing files %s and %s...\n", args[1], args[2]);
            printf("FC: no differences encountered\n");
        }
    }
    else if (strcmp(cmd, "find") == 0 || strcmp(cmd, "findstr") == 0) {
        if (argc < 2) {
            printf("Usage: %s <pattern> [files]\n", cmd);
        } else {
            printf("Searching for \"%s\"...\n", args[1]);
            printf("No matches found.\n");
        }
    }
    else if (strcmp(cmd, "more") == 0 || strcmp(cmd, "less") == 0) {
        if (argc < 2) {
            printf("Usage: %s <file>\n", cmd);
        } else {
            file_t* file = find_file(args[1]);
            if (file && !file->is_directory) {
                printf("%s", file->content);
                printf("\n-- More --\n");
            } else {
                printf("File not found: %s\n", args[1]);
            }
        }
    }
    else if (strcmp(cmd, "sort") == 0) {
        printf("Sorting...\n");
        printf("(Lines would be sorted alphabetically)\n");
    }
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        printf("\n\033[96m╔══════════════════════════════════════════════════════════╗\n");
        printf("║              CardinalOS v4.0 Command Reference           ║\n");
        printf("╚══════════════════════════════════════════════════════════╝\033[0m\n\n");
        
        printf("\033[93mSystem Commands (Linux/Unix/DOS):\033[0m\n");
        printf("  help, ?           - Show this help\n");
        printf("  version, ver      - Display version info\n");
        printf("  uname             - Print system information\n");
        printf("  hostname          - Show/set hostname\n");
        printf("  uptime            - Show system uptime\n");
        printf("  reboot/shutdown   - Restart or shutdown system\n");
        printf("  date, time        - Show date/time\n");
        printf("  cls, clear        - Clear screen\n\n");
        
        printf("\033[93mFile Operations (Linux/Unix):\033[0m\n");
        printf("  ls [path]         - List directory contents\n");
        printf("  cd <path>         - Change directory\n");
        printf("  pwd               - Print working directory\n");
        printf("  mkdir <dir>       - Create directory\n");
        printf("  touch <file>      - Create empty file\n");
        printf("  cat <file>        - Display file content\n");
        printf("  rm <file>         - Remove file\n");
        printf("  cp <src> <dst>    - Copy file\n");
        printf("  mv <src> <dst>    - Move/rename file\n");
        printf("  ln <src> <dst>    - Create link\n");
        printf("  chmod <mode> <f>  - Change permissions\n");
        printf("  chown <user> <f>  - Change owner\n");
        printf("  find <pattern>    - Search files\n");
        printf("  grep <pattern>    - Search in files\n");
        printf("  head, tail <file> - View file parts\n");
        printf("  more, less <file> - Page through file\n");
        printf("  diff <f1> <f2>    - Compare files\n\n");
        
        printf("\033[93mFile Operations (DOS):\033[0m\n");
        printf("  dir [path]        - List directory (DOS)\n");
        printf("  cd, chdir <path>  - Change directory (DOS)\n");
        printf("  md, mkdir <dir>   - Create directory (DOS)\n");
        printf("  rd, rmdir <dir>   - Remove directory (DOS)\n");
        printf("  copy <src> <dst>  - Copy file (DOS)\n");
        printf("  xcopy <src> <dst> - Extended copy (DOS)\n");
        printf("  move <src> <dst>  - Move file (DOS)\n");
        printf("  del, erase <file> - Delete file (DOS)\n");
        printf("  ren <old> <new>   - Rename file (DOS)\n");
        printf("  type <file>       - Display file (DOS)\n");
        printf("  attrib [+/-RH] <f>- File attributes (DOS)\n");
        printf("  tree              - Display tree (DOS)\n");
        printf("  comp, fc <f1> <f2>- Compare files (DOS)\n");
        printf("  find, findstr <p> - Find string (DOS)\n");
        printf("  sort              - Sort text (DOS)\n\n");
        
        printf("\033[93mUser Management:\033[0m\n");
        printf("  whoami            - Print current user\n");
        printf("  users             - List all users\n");
        printf("  su <user>         - Switch user\n");
        printf("  sudo <cmd>        - Execute as admin\n");
        printf("  passwd            - Change password\n");
        printf("  id                - Display user identity\n");
        printf("  groups            - Show user groups\n\n");
        
        printf("\033[93mProcess Management (Linux/Unix):\033[0m\n");
        printf("  ps                - List processes\n");
        printf("  top               - Process monitor\n");
        printf("  kill <pid>        - Terminate process\n");
        printf("  killall <name>    - Kill by name\n");
        printf("  bg, fg            - Background/foreground\n");
        printf("  jobs              - List jobs\n\n");
        
        printf("\033[93mProcess Management (DOS):\033[0m\n");
        printf("  tasklist          - List processes (DOS)\n");
        printf("  taskkill <pid>    - Kill process (DOS)\n");
        printf("  start <prog>      - Start program (DOS)\n\n");
        
        printf("\033[93mDisk Management (DOS):\033[0m\n");
        printf("  chkdsk, scandisk  - Check disk\n");
        printf("  format <drive>    - Format disk\n");
        printf("  diskpart          - Disk partition tool\n");
        printf("  vol               - Volume information\n");
        printf("  label             - Set volume label\n");
        printf("  mem, memory       - Memory information\n");
        printf("  path              - Show/set PATH\n");
        printf("  prompt            - Show prompt\n");
        printf("  doskey            - Keyboard macros\n\n");
        
        printf("\033[93mNetwork Commands (Linux/Unix):\033[0m\n");
        printf("  ifconfig          - Network interfaces\n");
        printf("  netstat           - Network connections\n");
        printf("  ping <host>       - Test connectivity\n");
        printf("  traceroute <host> - Trace route\n");
        printf("  nslookup <host>   - DNS lookup\n");
        printf("  dig <host>        - DNS query\n");
        printf("  route             - Show routing table\n");
        printf("  arp               - ARP table\n");
        printf("  nc <host> <port>  - Netcat\n");
        printf("  curl <url>        - Transfer data\n");
        printf("  wget <url>        - Download file\n\n");
        
        printf("\033[93mNetwork Commands (DOS):\033[0m\n");
        printf("  ipconfig          - IP configuration (DOS)\n");
        printf("  tracert <host>    - Trace route (DOS)\n");
        printf("  net <cmd>         - Network commands (DOS)\n\n");
        
        printf("\033[93mSecurity Commands:\033[0m\n");
        printf("  security          - Security status\n");
        printf("  firewall <cmd>    - Manage firewall\n");
        printf("  selinux <cmd>     - SELinux control\n");
        printf("  audit             - Audit logs\n\n");
        
        printf("\033[93mAttack Commands:\033[0m\n");
        printf("  exploit-db        - List exploits\n");
        printf("  c2-start          - Start C2 server\n");
        printf("  payload-gen       - Generate payload\n");
        printf("  scan <target>     - Port scan\n\n");
        
        printf("\033[93mAdvanced Features:\033[0m\n");
        printf("  desktop           - Launch GUI mode\n");
        printf("  iso-generate      - Create bootable ISO\n");
        printf("  benchmark         - System performance test\n\n");
    }
    else if (strcmp(cmd, "version") == 0 || strcmp(cmd, "ver") == 0) {
        printf("\033[96mCardinalOS Enterprise Edition\033[0m\n");
        printf("Version: %s\n", VERSION);
        printf("Kernel: Linux 6.1 + MS-DOS 6.22\n");
        printf("Architecture: x86_64\n");
        printf("Build: %s %s\n", __DATE__, __TIME__);
        printf("License: Proprietary (Research Use Only)\n\n");
    }
    else if (strcmp(cmd, "uname") == 0) {
        if (argc > 1 && strcmp(args[1], "-a") == 0) {
            printf("CardinalOS %s %s x86_64 GNU/Linux\n", system_state.hostname, system_state.kernel_version);
        } else {
            printf("CardinalOS\n");
        }
    }
    else if (strcmp(cmd, "hostname") == 0) {
        if (argc > 1) {
            if (current_user && current_user->is_admin) {
                strncpy(system_state.hostname, args[1], sizeof(system_state.hostname) - 1);
                audit_log("HOSTNAME", args[1]);
                printf("Hostname set to: %s\n", system_state.hostname);
            } else {
                printf("\033[91mPermission denied: Admin privileges required\033[0m\n");
            }
        } else {
            printf("%s\n", system_state.hostname);
        }
    }
    else if (strcmp(cmd, "uptime") == 0) {
        time_t now = time(NULL);
        time_t uptime_sec = now - system_state.boot_time;
        int hours = uptime_sec / 3600;
        int minutes = (uptime_sec % 3600) / 60;
        printf("System uptime: %d hours, %d minutes\n", hours, minutes);
        printf("Load average: %.2f, %.2f, %.2f\n", 
               system_state.cpu_usage / 100.0, 
               system_state.cpu_usage / 120.0, 
               system_state.cpu_usage / 150.0);
    }
    else if (strcmp(cmd, "whoami") == 0) {
        if (current_user) {
            printf("%s\n", current_user->username);
        } else {
            printf("unknown\n");
        }
    }
    else if (strcmp(cmd, "users") == 0 || strcmp(cmd, "who") == 0) {
        printf("\n\033[96mRegistered Users:\033[0m\n");
        printf("%-15s %-8s %-8s %-10s %s\n", "USERNAME", "UID", "GID", "ADMIN", "LOGGED IN");
        printf("─────────────────────────────────────────────────────────\n");
        for (int i = 0; i < user_count; i++) {
            printf("%-15s %-8d %-8d %-10s %s\n", 
                   users[i].username,
                   users[i].uid,
                   users[i].gid,
                   users[i].is_admin ? "Yes" : "No",
                   users[i].logged_in ? "\033[92mYes\033[0m" : "No");
        }
        printf("\n");
    }
    else if (strcmp(cmd, "pwd") == 0) {
        printf("%s\n", current_dir);
    }
    else if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "dir") == 0) {
        const char* path = argc > 1 ? args[1] : current_dir;
        list_directory_advanced(path);
    }
    else if (strcmp(cmd, "cd") == 0 || strcmp(cmd, "chdir") == 0) {
        if (argc < 2) {
            strcpy(current_dir, "/root");
        } else {
            file_t* dir = find_file(args[1]);
            if (dir && dir->is_directory) {
                if (check_permission(args[1], PERM_EXECUTE)) {
                    strcpy(current_dir, args[1]);
                } else {
                    printf("\033[91mPermission denied\033[0m\n");
                }
            } else {
                printf("\033[91mDirectory not found: %s\033[0m\n", args[1]);
            }
        }
    }
    else if (strcmp(cmd, "mkdir") == 0 || strcmp(cmd, "md") == 0) {
        if (argc < 2) {
            printf("Usage: mkdir <directory>\n");
        } else {
            if (check_permission(current_dir, PERM_WRITE)) {
                create_dir_advanced(args[1], PERM_READ | PERM_WRITE | PERM_EXECUTE);
                audit_log("MKDIR", args[1]);
                printf("Directory created: %s\n", args[1]);
            } else {
                printf("\033[91mPermission denied\033[0m\n");
            }
        }
    }
    else if (strcmp(cmd, "cat") == 0 || strcmp(cmd, "type") == 0) {
        if (argc < 2) {
            printf("Usage: cat <file>\n");
        } else {
            file_t* file = find_file(args[1]);
            if (file && !file->is_directory) {
                if (check_permission(args[1], PERM_READ)) {
                    printf("%s", file->content);
                    file->accessed = time(NULL);
                } else {
                    printf("\033[91mPermission denied\033[0m\n");
                }
            } else {
                printf("\033[91mFile not found: %s\033[0m\n", args[1]);
            }
        }
    }
    else if (strcmp(cmd, "ps") == 0 || strcmp(cmd, "tasklist") == 0) {
        printf("\n\033[96mRunning Processes:\033[0m\n");
        printf("%-8s %-8s %-25s %-8s %-10s %-8s\n", "PID", "PPID", "NAME", "USER", "MEMORY", "CPU%");
        printf("────────────────────────────────────────────────────────────────────\n");
        for (int i = 0; i < process_count; i++) {
            if (processes[i].is_running) {
                if (processes[i].is_hidden && (!current_user || !current_user->is_admin)) {
                    continue;
                }
                printf("%-8d %-8d %-25s %-8d %-10zu %-8.1f\n",
                       processes[i].pid,
                       processes[i].ppid,
                       processes[i].name,
                       processes[i].uid,
                       processes[i].memory,
                       processes[i].cpu_usage);
            }
        }
        printf("\n");
    }
    else if (strcmp(cmd, "security") == 0) {
        print_security_status();
    }
    else if (strcmp(cmd, "firewall") == 0) {
        if (argc < 2) {
            manage_firewall("status");
        } else {
            manage_firewall(args[1]);
        }
    }
    else if (strcmp(cmd, "desktop") == 0 || strcmp(cmd, "startx") == 0) {
        start_gui_desktop();
    }
    else if (strcmp(cmd, "iso-generate") == 0 || strcmp(cmd, "mkiso") == 0) {
        generate_iso_image();
    }
    else if (strcmp(cmd, "ifconfig") == 0 || strcmp(cmd, "ipconfig") == 0) {
        printf("\n\033[96mNetwork Interfaces:\033[0m\n\n");
        printf("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n");
        printf("        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n");
        printf("        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n");
        printf("        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n");
        printf("        RX packets 12847  bytes 8932047 (8.9 MB)\n");
        printf("        TX packets 7234  bytes 1892374 (1.8 MB)\n\n");
        printf("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n");
        printf("        inet 127.0.0.1  netmask 255.0.0.0\n");
        printf("        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n");
        printf("        loop  txqueuelen 1000  (Local Loopback)\n");
        printf("        RX packets 1024  bytes 102400 (100.0 KB)\n");
        printf("        TX packets 1024  bytes 102400 (100.0 KB)\n\n");
    }
    else if (strcmp(cmd, "netstat") == 0) {
        printf("\n\033[96mActive Internet connections:\033[0m\n");
        printf("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");
        printf("tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN\n");
        printf("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n");
        printf("tcp        0      0 192.168.1.100:4444      192.168.1.50:49234      ESTABLISHED\n");
        printf("udp        0      0 0.0.0.0:53              0.0.0.0:*\n");
        printf("udp        0      0 0.0.0.0:67              0.0.0.0:*\n\n");
    }
    else if (strcmp(cmd, "ping") == 0) {
        const char* host = argc > 1 ? args[1] : "8.8.8.8";
        printf("\n\033[96mPING %s (8.8.8.8) 56(84) bytes of data.\033[0m\n", host);
        for (int i = 0; i < 4; i++) {
            printf("64 bytes from %s: icmp_seq=%d ttl=64 time=%d.%d ms\n", 
                   host, i+1, 10 + (rand() % 40), rand() % 1000);
            sleep_ms(1000);
        }
        printf("\n--- %s ping statistics ---\n", host);
        printf("4 packets transmitted, 4 received, 0%% packet loss, time 3003ms\n");
        printf("rtt min/avg/max/mdev = 10.234/25.456/48.789/12.345 ms\n\n");
    }
    else if (strcmp(cmd, "traceroute") == 0 || strcmp(cmd, "tracert") == 0) {
        const char* host = argc > 1 ? args[1] : "8.8.8.8";
        printf("\n\033[96mtraceroute to %s (8.8.8.8), 30 hops max, 60 byte packets\033[0m\n", host);
        printf(" 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.089 ms\n");
        printf(" 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.543 ms  5.432 ms\n");
        printf(" 3  172.16.0.1 (172.16.0.1)  12.345 ms  12.234 ms  12.123 ms\n");
        printf(" 4  8.8.8.8 (8.8.8.8)  18.456 ms  18.345 ms  18.234 ms\n\n");
    }
    else if (strcmp(cmd, "nmap") == 0) {
        const char* target = argc > 1 ? args[1] : "192.168.1.1";
        printf("\n\033[96mStarting Nmap scan on %s\033[0m\n\n", target);
        printf("PORT     STATE SERVICE\n");
        printf("21/tcp   open  ftp\n");
        printf("22/tcp   open  ssh\n");
        printf("80/tcp   open  http\n");
        printf("443/tcp  open  https\n");
        printf("3389/tcp open  ms-wbt-server\n");
        printf("4444/tcp open  krb524\n\n");
        printf("Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds\n\n");
    }
    else if (strcmp(cmd, "portscan") == 0) {
        const char* target = argc > 1 ? args[1] : "192.168.1.1";
        printf("\n\033[96mScanning %s...\033[0m\n\n", target);
        printf("Open ports:\n");
        int ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 4444, 8080};
        for (int i = 0; i < 14; i++) {
            printf("  \033[92m%d/tcp\033[0m open\n", ports[i]);
            sleep_ms(100);
        }
        printf("\nScan complete: 14 open ports found\n\n");
    }
    else if (strcmp(cmd, "exploit-db") == 0 || strcmp(cmd, "exploits") == 0) {
        printf("\n\033[96m╔══════════════════════════════════════════════════════════╗\n");
        printf("║              Cardinal Exploit Database                   ║\n");
        printf("╚══════════════════════════════════════════════════════════╝\033[0m\n\n");
        printf("ID     CVE            Name                              Severity\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        printf("1      MS17-010       EternalBlue SMB RCE               \033[91mCRITICAL\033[0m\n");
        printf("2      MS08-067       Windows Server Service RCE        \033[91mCRITICAL\033[0m\n");
        printf("3      CVE-2021-44228 Log4Shell RCE                     \033[91mCRITICAL\033[0m\n");
        printf("4      CVE-2014-0160  Heartbleed SSL                    \033[93mHIGH\033[0m\n");
        printf("5      CVE-2017-5638  Apache Struts2 RCE                \033[91mCRITICAL\033[0m\n");
        printf("6      CVE-2019-0708  BlueKeep RDP RCE                  \033[91mCRITICAL\033[0m\n");
        printf("7      CVE-2020-1472  Zerologon Domain Takeover         \033[91mCRITICAL\033[0m\n");
        printf("8      CVE-2021-26855 ProxyLogon Exchange RCE           \033[91mCRITICAL\033[0m\n");
        printf("\nTotal: 200+ exploits available\n");
        printf("Use: exploit-run <id> <target> to execute\n\n");
    }
    else if (strcmp(cmd, "c2-start") == 0) {
        printf("\n\033[96mStarting Cardinal C2 Server...\033[0m\n\n");
        printf("Initializing C2 framework...\n");
        sleep_ms(500);
        printf("Loading exploit modules...\n");
        sleep_ms(500);
        printf("Starting listener on 0.0.0.0:4444...\n");
        sleep_ms(500);
        printf("Starting HTTP server on 0.0.0.0:8080...\n");
        sleep_ms(500);
        printf("Initializing payload generator...\n");
        sleep_ms(500);
        printf("Loading post-exploitation modules...\n");
        sleep_ms(500);
        printf("\n\033[92m✓ C2 Server started successfully\033[0m\n");
        printf("\nListeners:\n");
        printf("  TCP: 0.0.0.0:4444 (Main C2)\n");
        printf("  HTTP: 0.0.0.0:8080 (Web delivery)\n");
        printf("  HTTPS: 0.0.0.0:8443 (Secure C2)\n\n");
        audit_log("C2_START", "C2 server started");
    }
    else if (strcmp(cmd, "payload-gen") == 0) {
        printf("\n\033[96mPayload Generator\033[0m\n\n");
        printf("Available payloads:\n");
        printf("  1. windows/meterpreter/reverse_tcp\n");
        printf("  2. linux/x64/shell/reverse_tcp\n");
        printf("  3. android/meterpreter/reverse_tcp\n");
        printf("  4. python/shell_reverse_tcp\n");
        printf("  5. php/meterpreter_reverse_tcp\n\n");
        printf("Usage: payload-gen <type> <lhost> <lport>\n\n");
    }
    else if (strcmp(cmd, "scan") == 0) {
        if (argc < 2) {
            printf("Usage: scan <target>\n");
        } else {
            printf("\n\033[96mScanning %s...\033[0m\n\n", args[1]);
            printf("Phase 1: Host discovery...\n");
            sleep_ms(500);
            printf("Phase 2: Port scanning...\n");
            sleep_ms(800);
            printf("Phase 3: Service detection...\n");
            sleep_ms(800);
            printf("Phase 4: Vulnerability assessment...\n");
            sleep_ms(1000);
            printf("\n\033[92mScan complete\033[0m\n\n");
            printf("Results:\n");
            printf("  Host: %s [UP]\n", args[1]);
            printf("  OS: Windows Server 2019\n");
            printf("  Open ports: 7\n");
            printf("  Vulnerabilities: 3 critical, 5 high, 12 medium\n\n");
        }
    }
    else if (strcmp(cmd, "touch") == 0) {
        if (argc < 2) {
            printf("Usage: touch <filename>\n");
        } else {
            create_file_advanced(args[1], "", PERM_READ | PERM_WRITE);
            audit_log("TOUCH", args[1]);
            printf("File created: %s\n", args[1]);
        }
    }
    else if (strcmp(cmd, "echo") == 0) {
        for (int i = 1; i < argc; i++) {
            printf("%s", args[i]);
            if (i < argc - 1) printf(" ");
        }
        printf("\n");
    }
    else if (strcmp(cmd, "free") == 0) {
        printf("\n\033[96mMemory Usage:\033[0m\n");
        printf("              total        used        free      shared  buff/cache   available\n");
        printf("Mem:     %10zu  %10zu  %10zu           0           0  %10zu\n",
               system_state.total_memory,
               system_state.used_memory,
               system_state.total_memory - system_state.used_memory,
               system_state.total_memory - system_state.used_memory);
        printf("Swap:             0           0           0\n\n");
    }
    else if (strcmp(cmd, "df") == 0) {
        printf("\n\033[96mFilesystem Usage:\033[0m\n");
        printf("Filesystem      Size  Used Avail Use%% Mounted on\n");
        printf("/dev/nvme0n1p1  512M  245M  267M  48%% /\n");
        printf("tmpfs           256M    0M  256M   0%% /tmp\n");
        printf("C:              1.0T  450G  550G  45%% /mnt/c\n\n");
    }
    else if (strcmp(cmd, "mount") == 0) {
        printf("\n\033[96mMounted Filesystems:\033[0m\n");
        printf("/dev/nvme0n1p1 on / type ext4 (rw,relatime)\n");
        printf("proc on /proc type proc (rw,nosuid,nodev,noexec)\n");
        printf("sysfs on /sys type sysfs (rw,nosuid,nodev,noexec)\n");
        printf("tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n");
        printf("C: on /mnt/c type ntfs (rw,relatime)\n\n");
    }
    else if (strcmp(cmd, "kill") == 0) {
        if (argc < 2) {
            printf("Usage: kill <pid>\n");
        } else {
            int pid = atoi(args[1]);
            bool found = false;
            for (int i = 0; i < process_count; i++) {
                if (processes[i].pid == pid) {
                    processes[i].is_running = false;
                    printf("Process %d terminated\n", pid);
                    audit_log("KILL", args[1]);
                    found = true;
                    break;
                }
            }
            if (!found) {
                printf("\033[91mProcess not found: %d\033[0m\n", pid);
            }
        }
    }
    else if (strcmp(cmd, "reboot") == 0 || strcmp(cmd, "restart") == 0) {
        printf("\033[93mRebooting system...\033[0m\n");
        audit_log("REBOOT", "User initiated reboot");
        sleep_ms(1000);
        printf("System will restart now.\n");
        sleep_ms(500);
        exit(0);
    }
    else if (strcmp(cmd, "shutdown") == 0) {
        printf("\033[93mShutting down system...\033[0m\n");
        audit_log("SHUTDOWN", "User initiated shutdown");
        sleep_ms(1000);
        printf("Power off.\n");
        sleep_ms(500);
        exit(0);
    }
    else if (strcmp(cmd, "date") == 0) {
        time_t now = time(NULL);
        printf("%s", ctime(&now));
    }
    else if (strcmp(cmd, "time") == 0) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        printf("%02d:%02d:%02d\n", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    }
    else if (strcmp(cmd, "env") == 0 || strcmp(cmd, "set") == 0) {
        printf("\n\033[96mEnvironment Variables:\033[0m\n");
        printf("PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\n");
        printf("HOME=%s\n", current_dir);
        printf("USER=%s\n", current_user ? current_user->username : "root");
        printf("SHELL=/bin/bash\n");
        printf("HOSTNAME=%s\n", system_state.hostname);
        printf("TERM=xterm-256color\n");
        printf("CARDINAL_HOME=/cardinal\n\n");
    }
    else if (strcmp(cmd, "clear") == 0 || strcmp(cmd, "cls") == 0) {
        kernel_clear_screen();
    }
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        printf("\033[93mShutting down CardinalOS...\033[0m\n");
        audit_log("SHUTDOWN", "User initiated shutdown");
        sleep_ms(500);
        exit(0);
    }
    else {
        printf("\033[91mCommand not found: %s\033[0m\n", cmd);
        printf("Type 'help' for available commands\n");
    }
}

void shell_run(void) {
    char input[512];
    
    while (1) {
        // Dynamic prompt
        if (current_user) {
            if (current_user->is_admin) {
                printf("\033[91m%s@%s\033[0m:\033[94m%s\033[0m# ", 
                       current_user->username, system_state.hostname, current_dir);
            } else {
                printf("\033[92m%s@%s\033[0m:\033[94m%s\033[0m$ ", 
                       current_user->username, system_state.hostname, current_dir);
            }
        } else {
            printf("\033[93msystem\033[0m:\033[94m%s\033[0m> ", current_dir);
        }
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) > 0) {
            handle_command_advanced(input);
        }
    }
}

int main(void) {
    // Set UTF-8 console
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // Initialize system
    init_system();
    
    // Print banner
    print_banner();
    
    printf("\033[97mWelcome to CardinalOS Enterprise Edition\033[0m\n");
    printf("Type '\033[93mhelp\033[0m' for available commands\n");
    printf("Type '\033[93mdesktop\033[0m' to launch GUI mode\n");
    printf("Type '\033[93miso-generate\033[0m' to create bootable ISO\n\n");
    
    audit_log("BOOT", "System started successfully");
    
    // Start shell
    shell_run();
    
    return 0;
}
