#ifndef __IP_H__
#define __IP_H__

#include "common.h"
#include "raw.h"

/* Constants */
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86dd
#define IPV4_HEADER_SIZE 20

/* Structs */
typedef struct {
    unsigned char  version;
    unsigned char  ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned char  flags;
    unsigned int   fragment_offset;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    ipv4_addr_t    src_ip;
    ipv4_addr_t    dst_ip;
    unsigned char  payload[BUF_SIZE - ETH_HEADER_SIZE - IPV4_HEADER_SIZE];
    size_t         payload_len;
    eth_header_t   eth_header;
} ip_header_t;

int parse_ipv4_header(ip_header_t *ip_header,
                      char *payload, size_t len);
int recv_ip(raw_socket_t sock, ip_header_t *ip_header,
            const char *recv_ip_addr);
int send_ipv4(raw_socket_t sock, ip_header_t *ip_header,
              const char *payload, size_t len,
              const char *dst_mac, const char *dst_ip,
              unsigned short protocol);

int build_ipv4_header(ip_header_t *ip_header, 
                      const char *dst_mac, const char *dst_ip_str,
                      unsigned short protocol);

void set_ttl(unsigned char new_ttl);
void set_offset(unsigned int new_offset);
void set_flags(unsigned char new_flags);
void set_tos(unsigned char new_tos);
void set_id(unsigned short new_id);
unsigned char get_ttl(void);
unsigned int get_offset(void);
unsigned char get_flags(void);
unsigned char get_tos(void);
unsigned short get_id(void);

#endif /* __IP_H__ */