#ifndef __UDP_H__
#define __UDP_H__

#include "common.h"
#include "ip.h"

/* Constants */
#define IP_PROTO_UDP 17
#define UDP_HEADER_SIZE 8

/* Structs */
typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
    unsigned char  payload[BUF_SIZE - ETH_HEADER_SIZE - IPV4_HEADER_SIZE - UDP_HEADER_SIZE];
    size_t         payload_len;
    ip_header_t    ip_header;
} udp_header_t;

int parse_udp_header(udp_header_t *udp_header,
                     unsigned char *payload, size_t len);

int recv_udp(raw_socket_t sock, udp_header_t *udp_header,
             const char *recv_ip_addr, const unsigned short recv_port);

int send_udp_ipv4(raw_socket_t sock, udp_header_t *udp_header,
                  const char *payload, size_t len,
                  const int src_port, const int dst_port,
                  const char *dst_mac, const char *dst_ip);

void set_udp_timeout(int timeout);
void set_calc_udp_checksum(int num);
int get_calc_udp_checksum(void);
int get_udp_timeout(void);

#endif /* __UDP_H__ */