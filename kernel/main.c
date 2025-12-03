/*
 * CardinalOS - Attack-Oriented Operating System Kernel
 * Main kernel entry point and core initialization
 */

#include "kernel.h"
#include "c2/c2_core.h"
#include "net/network.h"
#include "fs/vfs.h"
#include "mm/memory.h"
#include "shell/shell.h"

// Kernel version
#define KERNEL_VERSION "1.0.0"
#define KERNEL_NAME "CardinalOS"

// VGA text mode
#define VGA_MEMORY 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25

static uint16_t* vga_buffer = (uint16_t*)VGA_MEMORY;
static int cursor_x = 0;
static int cursor_y = 0;

// Terminal colors
#define COLOR_BLACK 0
#define COLOR_BLUE 1
#define COLOR_GREEN 2
#define COLOR_CYAN 3
#define COLOR_RED 4
#define COLOR_MAGENTA 5
#define COLOR_BROWN 6
#define COLOR_LIGHT_GREY 7
#define COLOR_DARK_GREY 8
#define COLOR_LIGHT_BLUE 9
#define COLOR_LIGHT_GREEN 10
#define COLOR_LIGHT_CYAN 11
#define COLOR_LIGHT_RED 12
#define COLOR_LIGHT_MAGENTA 13
#define COLOR_YELLOW 14
#define COLOR_WHITE 15

static uint8_t terminal_color = (COLOR_GREEN << 4) | COLOR_BLACK;

void kernel_clear_screen(void) {
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = (terminal_color << 8) | ' ';
    }
    cursor_x = 0;
    cursor_y = 0;
}

void kernel_putchar(char c) {
    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else if (c == '\r') {
        cursor_x = 0;
    } else if (c == '\t') {
        cursor_x = (cursor_x + 4) & ~(4 - 1);
    } else {
        vga_buffer[cursor_y * VGA_WIDTH + cursor_x] = (terminal_color << 8) | c;
        cursor_x++;
    }

    if (cursor_x >= VGA_WIDTH) {
        cursor_x = 0;
        cursor_y++;
    }

    if (cursor_y >= VGA_HEIGHT) {
        // Scroll
        for (int i = 0; i < VGA_WIDTH * (VGA_HEIGHT - 1); i++) {
            vga_buffer[i] = vga_buffer[i + VGA_WIDTH];
        }
        for (int i = 0; i < VGA_WIDTH; i++) {
            vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + i] = (terminal_color << 8) | ' ';
        }
        cursor_y = VGA_HEIGHT - 1;
    }
}

void kernel_print(const char* str) {
    while (*str) {
        kernel_putchar(*str++);
    }
}

void kernel_print_color(const char* str, uint8_t color) {
    uint8_t old_color = terminal_color;
    terminal_color = color;
    kernel_print(str);
    terminal_color = old_color;
}

void kernel_printf(const char* format, ...) {
    // Simple printf implementation
    while (*format) {
        if (*format == '%') {
            format++;
            if (*format == 's') {
                // String
                format++;
            } else if (*format == 'd') {
                // Decimal
                format++;
            } else if (*format == 'x') {
                // Hex
                format++;
            }
        } else {
            kernel_putchar(*format++);
        }
    }
}

void print_banner(void) {
    terminal_color = (COLOR_RED << 4) | COLOR_BLACK;
    kernel_clear_screen();
    
    kernel_print("\n");
    kernel_print("   ██████╗ █████╗ ██████╗ ██████╗ ██╗███╗   ██╗ █████╗ ██╗      ██████╗ ███████╗\n");
    kernel_print("  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗██║     ██╔═══██╗██╔════╝\n");
    kernel_print("  ██║     ███████║██████╔╝██║  ██║██║██╔██╗ ██║███████║██║     ██║   ██║███████╗\n");
    kernel_print("  ██║     ██╔══██║██╔══██╗██║  ██║██║██║╚██╗██║██╔══██║██║     ██║   ██║╚════██║\n");
    kernel_print("  ╚██████╗██║  ██║██║  ██║██████╔╝██║██║ ╚████║██║  ██║███████╗╚██████╔╝███████║\n");
    kernel_print("   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝\n");
    kernel_print("\n");
    
    terminal_color = (COLOR_WHITE << 4) | COLOR_BLACK;
    kernel_print("              === Attack-Oriented Operating System ===\n");
    kernel_print("                      Version ");
    kernel_print(KERNEL_VERSION);
    kernel_print("\n\n");
}

void kernel_init_subsystems(void) {
    terminal_color = (COLOR_CYAN << 4) | COLOR_BLACK;
    
    kernel_print("[*] Initializing memory management...\n");
    memory_init();
    
    kernel_print("[*] Initializing interrupt handlers...\n");
    interrupts_init();
    
    kernel_print("[*] Initializing PCI devices...\n");
    pci_init();
    
    kernel_print("[*] Initializing network stack...\n");
    network_init();
    
    kernel_print("[*] Initializing file systems...\n");
    vfs_init();
    fs_ntfs_init();
    fs_exfat_init();
    fs_ext4_init();
    fs_apfs_init();
    
    kernel_print("[*] Initializing C2 core...\n");
    c2_core_init();
    
    kernel_print("[*] Starting C2 services...\n");
    c2_server_start();
    
    terminal_color = (COLOR_LIGHT_GREEN << 4) | COLOR_BLACK;
    kernel_print("\n[+] All systems initialized successfully!\n\n");
}

// Main kernel entry point (called from bootloader)
void kernel_main(void) {
    // Print boot banner
    print_banner();
    
    // Initialize all subsystems
    kernel_init_subsystems();
    
    // Print system info
    terminal_color = (COLOR_YELLOW << 4) | COLOR_BLACK;
    kernel_print("System Information:\n");
    kernel_print("  - Architecture: x86_64\n");
    kernel_print("  - Memory: ");
    kernel_printf("%d MB\n", memory_get_total() / (1024 * 1024));
    kernel_print("  - File Systems: NTFS, ExFAT, Ext4, APFS\n");
    kernel_print("  - Network: TCP/IP stack enabled\n");
    kernel_print("  - C2 Server: Active on port 4444\n");
    kernel_print("\n");
    
    // Start interactive shell
    terminal_color = (COLOR_WHITE << 4) | COLOR_BLACK;
    kernel_print("Starting CardinalOS shell...\n\n");
    
    shell_init();
    shell_run();
    
    // Should never reach here
    kernel_print("\n[!] Kernel panic: Shell exited unexpectedly\n");
    while (1) {
        __asm__ volatile ("hlt");
    }
}

// Kernel panic handler
void kernel_panic(const char* message) {
    terminal_color = (COLOR_WHITE << 4) | COLOR_RED;
    kernel_print("\n\n!!! KERNEL PANIC !!!\n");
    kernel_print(message);
    kernel_print("\n\nSystem halted.\n");
    
    while (1) {
        __asm__ volatile ("hlt");
    }
}
