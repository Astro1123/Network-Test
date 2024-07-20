#ifndef __RAW_H__
#define __RAW_H__

#include <netpacket/packet.h>   // struct sockaddr_ll
#include "common.h"

/* Constants */
#define ETH_HEADER_SIZE 14

/* Structs */
typedef struct {
    int fd;
    int ifidx;
    struct sockaddr_ll sa;
} raw_socket_t;

typedef struct {
    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    unsigned short type;
    char payload[BUF_SIZE - ETH_HEADER_SIZE];
    size_t payload_len;
} eth_header_t;

/* Functions */
int create_sock(const char *ifname, raw_socket_t *sock);
int eth_send(raw_socket_t sock, eth_header_t header);
int eth_recv(raw_socket_t sock, eth_header_t *header);
int parse_eth_header(char *buf, size_t size, eth_header_t *header);
int build_eth_header(eth_header_t *header, const char *dst_mac,
                     unsigned short type);

void set_blocking(int num);
void set_timeout(int sec);
int get_blocking(void);
int get_timeout(void);

#endif /* __RAW_H__ */