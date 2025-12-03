/*
 * Windows EXE Wrapper for CardinalOS
 * Launches QEMU with CardinalOS image
 */

#include <windows.h>
#include <stdio.h>

#ifndef IMG_FILE
#define IMG_FILE "build/cardinalos.img"
#endif

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf("    CardinalOS - Attack Platform Launcher\n");
    printf("===========================================\n\n");
    
    printf("[*] Checking for QEMU...\n");
    
    // Check if QEMU is installed
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    // Build QEMU command
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
        "qemu-system-x86_64.exe -drive format=raw,file=%s -m 128M -serial stdio",
        IMG_FILE);
    
    printf("[*] Launching CardinalOS in QEMU...\n");
    printf("[*] Command: %s\n\n", cmd);
    
    // Start QEMU
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[!] Error: Failed to start QEMU\n");
        printf("[!] Make sure QEMU is installed and in PATH\n");
        printf("[!] Download from: https://www.qemu.org/download/\n");
        return 1;
    }
    
    // Wait for QEMU to exit
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Close handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    printf("\n[*] CardinalOS session ended\n");
    return 0;
}
