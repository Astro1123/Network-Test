#ifndef __ICMP_H__
#define __ICMP_H__

#include "common.h"
#include "ip.h"

#define IP_PROTO_ICMP 0x01

#define ICMP_TYPE_ECHO_RPY 0x00
#define ICMP_TYPE_UNREACHABLE 0x03
#define ICMP_TYPE_REDIRECT 0x05
#define ICMP_TYPE_ECHO_REQ 0x08
#define ICMP_TYPE_ROUTER_ADV 0x09
#define ICMP_TYPE_ROUTER_SEL 0x0A
#define ICMP_TYPE_TIME_EXCEEDED 0x0B
#define ICMP_TYPE_PARAM_PROBLEM 0x0C
#define ICMP_TYPE_TIME_STAMP 0x0D
#define ICMP_TYPE_TIME_STAMP_RPY 0x0E

#define ICMP_CODE_ECHO 0x00
#define ICMP_CODE_UNREACHABLE_PORT 0x03

#define ICMP_HEADER_SIZE 4

#define TRACEROUTE_PROTO_ICMP 0
#define TRACEROUTE_PROTO_UDP  1


typedef struct {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    union {
        struct {
            unsigned short id;
            unsigned short sequence;
        } echo;
    } rest;
    unsigned char  payload[BUF_SIZE - ETH_HEADER_SIZE - IPV4_HEADER_SIZE - ICMP_HEADER_SIZE];
    size_t         payload_len;
    ip_header_t    ip_header;
} icmp_header_t;


int execute_traceroute(raw_socket_t sock, const char *dst_mac,
                       const char *dst_ip, int proto);
int execute_ping(raw_socket_t sock, const char *dst_mac, const char *dst_ip);
int send_icmp_ipv4(raw_socket_t sock, icmp_header_t *icmp_header,
                   const char *payload, size_t len,
                   const int type, const int code,
                   const char *dst_mac, const char *dst_ip);

int recv_icmp(raw_socket_t sock, icmp_header_t *icmp_header,
              const char *recv_ip_addr);

void set_timeout_icmp(int timeout);
int get_timeout_icmp(void);
void set_icmp_echo_id(unsigned short id);
unsigned short get_icmp_echo_id(void);
void set_icmp_echo_sequence(unsigned short sequence);
unsigned short get_icmp_echo_sequence(void);
void set_ping_count(unsigned int count);
unsigned int get_ping_count(void);

#endif /* __ARP_H__ */
