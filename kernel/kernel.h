/*
 * CardinalOS Kernel Header
 * Core kernel definitions and function prototypes
 */

#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Kernel configuration
#define KERNEL_STACK_SIZE 0x4000
#define PAGE_SIZE 4096

// Basic types
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef char i8;
typedef short i16;
typedef int i32;
typedef long long i64;

// Terminal functions
void kernel_clear_screen(void);
void kernel_putchar(char c);
void kernel_print(const char* str);
void kernel_print_color(const char* str, uint8_t color);
void kernel_printf(const char* format, ...);

// System functions
void kernel_panic(const char* message);
void kernel_main(void);

// Memory management
void memory_init(void);
uint64_t memory_get_total(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* memset(void* dest, int val, size_t count);
void* memcpy(void* dest, const void* src, size_t count);
int memcmp(const void* s1, const void* s2, size_t n);

// String functions
size_t strlen(const char* str);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* strcat(char* dest, const char* src);

// Interrupt handling
void interrupts_init(void);
void interrupts_enable(void);
void interrupts_disable(void);

// PCI
void pci_init(void);

// Port I/O
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile ("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ volatile ("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// CPU control
static inline void cpu_halt(void) {
    __asm__ volatile ("hlt");
}

static inline void cpu_cli(void) {
    __asm__ volatile ("cli");
}

static inline void cpu_sti(void) {
    __asm__ volatile ("sti");
}

#endif // KERNEL_H
