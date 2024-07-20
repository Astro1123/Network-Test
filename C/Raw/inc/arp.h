#ifndef __ARP_H__
#define __ARP_H__

#include "common.h"
#include "raw.h"

#define ETH_TYPE_ARP 0x0806
#define PTYPE_IPV4 0x0800
#define PTYPE_IPV6 0x86dd
#define HTYPE 0x0001
#define HA_LEN MAC_ADDR_SIZE
#define PA_LEN IPV4_ADDR_SIZE
#define ARP_REQ 1
#define ARP_RPY 2

typedef struct {
    unsigned short htype;
    unsigned short ptype;
    unsigned char  hlen;
    unsigned char  plen;
    unsigned short oper;
    mac_addr_t     sha;
    ipv4_addr_t    spa;
    mac_addr_t     tha;
    ipv4_addr_t    tpa;
    eth_header_t   eth_header;
} arp_packet_t;

int execute_arp(raw_socket_t sock, arp_packet_t *arp_packet, 
                const char *dst_ip);

int send_arp(raw_socket_t sock, arp_packet_t *arp_packet, 
             const char *dst_ip);

int recv_arp(raw_socket_t sock, arp_packet_t *arp_packet, 
             const char *dst_ip);

int recv_arp_oper(raw_socket_t sock, arp_packet_t *arp_packet, int oper);
int send_garp(raw_socket_t sock, arp_packet_t *arp_packet);
int send_arp_probe(raw_socket_t sock, arp_packet_t *arp_packet, 
                   const char *dst_ip);

void set_timeout_arp(int timeout);
int get_timeout_arp(void);

#endif /* __ARP_H__ */
