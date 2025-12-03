/*
 * CardinalOS - Network Stack
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "../kernel.h"

// Network initialization
void network_init(void);
void pci_init(void);
void interrupts_init(void);

// Socket operations
int socket_create(int domain, int type, int protocol);
int socket_bind(int sockfd, uint32_t addr, uint16_t port);
int socket_listen(int sockfd, int backlog);
int socket_accept(int sockfd);
int socket_connect(int sockfd, uint32_t addr, uint16_t port);
int socket_send(int sockfd, const void* buf, size_t len);
int socket_recv(int sockfd, void* buf, size_t len);
int socket_close(int sockfd);

#endif // NETWORK_H
