#include <string.h>
#include <stdio.h>

#include "udp.h"

int calc_udp_checksum = 1;

static int build_ip_payload(udp_header_t *udp_header, const char *dst_ip_str);

int parse_udp_header(udp_header_t *udp_header,
                     unsigned char *payload, size_t len) {
    unsigned char *payload_p = payload;

    if (len < UDP_HEADER_SIZE) {
        return FAILURE;
    }
    udp_header->src_port = *payload_p;
    udp_header->src_port <<= 8;
    payload_p++;
    udp_header->src_port |= *payload_p;
    payload_p++;

    udp_header->dst_port = *payload_p;
    udp_header->dst_port <<= 8;
    payload_p++;
    udp_header->dst_port |= *payload_p;
    payload_p++;

    udp_header->length = *payload_p;
    udp_header->length <<= 8;
    payload_p++;
    udp_header->length |= *payload_p;
    payload_p++;

    udp_header->checksum = *payload_p;
    udp_header->checksum <<= 8;
    payload_p++;
    udp_header->checksum |= *payload_p;
    payload_p++;

    udp_header->payload_len = len - UDP_HEADER_SIZE;
    memcpy(udp_header->payload, payload_p, udp_header->payload_len);
    return SUCCESS;
}

int recv_udp(raw_socket_t sock, udp_header_t *udp_header,
             const char *recv_ip_addr, const unsigned short recv_port) {
    int ret;

    while (1) {
        memset(udp_header, 0, sizeof(udp_header_t));
        ret = recv_ip(sock, &(udp_header->ip_header), recv_ip_addr);
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        if (udp_header->ip_header.protocol != IP_PROTO_UDP) {
            continue;
        }
        ret = parse_udp_header(udp_header, udp_header->ip_header.payload, 
                               udp_header->ip_header.payload_len);
        if (ret < 0) {
            return ret;
        }
        if (udp_header->dst_port == recv_port) {
            break;
        }
    }
    return ret;
}

int send_udp_ipv4(raw_socket_t sock, udp_header_t *udp_header,
                  const char *payload, size_t len,
                  const int src_port, const int dst_port,
                  const char *dst_mac, const char *dst_ip) {
    int ret;
    char ip_payload[BUF_SIZE - ETH_HEADER_SIZE - IPV4_HEADER_SIZE];
    char ip_payload_len;
    
    memset(udp_header, 0, sizeof(udp_header_t));
    udp_header->payload_len = len;
    memcpy(udp_header->payload, payload, len);
    udp_header->length = len + UDP_HEADER_SIZE;

    udp_header->src_port = (unsigned short)src_port;
    udp_header->dst_port = (unsigned short)dst_port;

    ret = build_ip_payload(udp_header, dst_ip);
    if (ret < 0) {
        return ret;
    }

    ip_payload_len = udp_header->ip_header.payload_len;
    memcpy(ip_payload, udp_header->ip_header.payload, ip_payload_len);

    /*
    for (unsigned int i = 0; i < ip_payload_len; i++) {
        printf("%02x ", ip_payload[i]);
    }
    printf("\n");
    */
    ret = send_ipv4(sock, &(udp_header->ip_header), 
                    ip_payload, ip_payload_len, 
                    dst_mac, dst_ip, IP_PROTO_UDP);
    if (ret < 0) {
        return ret;
    }
    return ret;
}

static int build_ip_payload(udp_header_t *udp_header, const char *dst_ip_str) {
    unsigned int sum = 0;
    unsigned short high;
    unsigned short low;
    unsigned int len;
    unsigned int i;
    int idx = 0;
    unsigned short word;
    unsigned char byte;
    int ret;
    char *payload_p;
    ipv4_addr_t dst_ip;

    byte = ((udp_header->src_port >> 8) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    byte = ((udp_header->src_port) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    sum += udp_header->src_port;

    byte = ((udp_header->dst_port >> 8) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    byte = ((udp_header->dst_port) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    sum += udp_header->dst_port;

    byte = ((udp_header->length >> 8) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    byte = ((udp_header->length) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    sum += udp_header->length;
    
    i = 0;
    payload_p = (char *)udp_header->payload;
    len = udp_header->payload_len;
    while (i < len) {
        word = ((*payload_p) << 8) & 0xff00;
        i++;
        payload_p++;
        if (i < len) {
            word |= (*payload_p) & 0x00ff;
            i++;
            payload_p++;
        }
        sum += word;
    }

    word  = if_paddr.addr[0];
    word <<= 8;
    word |= if_paddr.addr[1];
    sum += word;

    word  = if_paddr.addr[2];
    word <<= 8;
    word |= if_paddr.addr[3];
    sum += word;

    ret = str_to_ip(dst_ip_str, strlen(dst_ip_str)+1, &dst_ip);
    if (ret < 0) {
        return ret;
    }

    word  = dst_ip.addr[0];
    word <<= 8;
    word |= dst_ip.addr[1];
    sum += word;

    word  = dst_ip.addr[2];
    word <<= 8;
    word |= dst_ip.addr[3];
    sum += word;

    sum += IP_PROTO_UDP;
    sum += udp_header->payload_len + UDP_HEADER_SIZE;

    if (calc_udp_checksum == 0) {
        udp_header->checksum = 0x0000;
    } else {
        high = ((sum >> 16) & 0x0000ffff);
        low  = (sum & 0x0000ffff);
        udp_header->checksum = ( (high + low) ^ 0xffff );
        if (udp_header->checksum == 0x0000) {
            udp_header->checksum = 0xffff;
        }
    }

    byte = ((udp_header->checksum >> 8) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;
    byte = ((udp_header->checksum) & 0x00ff);
    udp_header->ip_header.payload[idx++] = byte;

    udp_header->ip_header.payload_len = udp_header->payload_len + idx;
    memcpy(&(udp_header->ip_header.payload[idx]), 
           udp_header->payload, udp_header->payload_len);
    return SUCCESS;
}

void set_calc_udp_checksum(int num) {
    calc_udp_checksum = num;
}

int get_calc_udp_checksum(void) {
    return calc_udp_checksum;
}
