#include <string.h>
#include <stdio.h>

#include "ip.h"

unsigned char  tos = 0;
unsigned short identification = 0xca9f;//0x1234;
unsigned char  flags = 2;
unsigned int   fragment_offset = 0;
unsigned char  ttl = 64;//ttl = 128;

int build_eth_payload(ip_header_t *ip_header);

int parse_ipv4_header(ip_header_t *ip_header,
                      char *payload, size_t len) {
    char *payload_p = payload;
    
    if (len < 20) {
        return FAILURE;
    }
    ip_header->version = (*payload_p >> 4) & 0x0f;
    ip_header->ihl = *payload_p & 0x0f;
    payload_p++;

    ip_header->tos = *payload_p;
    payload_p++;

    ip_header->total_length  = *payload_p;
    ip_header->total_length <<= 8;
    payload_p++;
    ip_header->total_length |= *payload_p;
    payload_p++;

    ip_header->identification  = *payload_p;
    ip_header->identification <<= 8;
    payload_p++;
    ip_header->identification |= *payload_p;
    payload_p++;

    ip_header->flags = (*payload_p >> 5) & 0x07;
    ip_header->fragment_offset = *payload_p & 0x1f;
    ip_header->fragment_offset <<= 8;
    payload_p++;
    ip_header->fragment_offset |= *payload_p;
    payload_p++;

    ip_header->ttl = *payload_p;
    payload_p++;

    ip_header->protocol = *payload_p;
    payload_p++;

    ip_header->checksum  = *payload_p;
    ip_header->checksum <<= 8;
    payload_p++;
    ip_header->checksum |= *payload_p;
    payload_p++;

    ip_header->src_ip.addr[0] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->src_ip.addr[1] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->src_ip.addr[2] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->src_ip.addr[3] = (unsigned char)*payload_p;
    payload_p++;

    ip_header->dst_ip.addr[0] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->dst_ip.addr[1] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->dst_ip.addr[2] = (unsigned char)*payload_p;
    payload_p++;
    ip_header->dst_ip.addr[3] = (unsigned char)*payload_p;
    payload_p++;

    if (ip_header->ihl > 5) {
        payload_p += (ip_header->ihl - 5) * 4;
    }
    ip_header->payload_len = ip_header->total_length - ip_header->ihl * 4;
    memcpy(ip_header->payload, payload_p, ip_header->payload_len);
    return SUCCESS;
}

int recv_ip(raw_socket_t sock, ip_header_t *ip_header,
            const char *recv_ip_addr) {
    int ret;
    unsigned char head;
    
    while (1) {
        memset(ip_header, 0, sizeof(ip_header_t));
        ret = eth_recv(sock, &(ip_header->eth_header));
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        head = ip_header->eth_header.payload[0];
        if (ip_header->eth_header.type == ETH_TYPE_IPV4 && ((head >> 4) & 0x0f) == 4) {
            ret = parse_ipv4_header(ip_header, ip_header->eth_header.payload, 
                                    ip_header->eth_header.payload_len);
            if (ret < 0) {
                return ret;
            }
            if (recv_ip_addr == NULL) {
                break;
            }
            if (comp_ip(ip_header->dst_ip, recv_ip_addr)) {
                break;
            }
        }
    }
    return ret;
}

int send_ipv4(raw_socket_t sock, ip_header_t *ip_header,
              const char *payload, size_t len,
              const char *dst_mac, const char *dst_ip,
              unsigned short protocol) {
    int ret;
    unsigned int i;

    memset(ip_header, 0, sizeof(ip_header_t));
    ip_header->payload_len = len;
    ret = build_ipv4_header(ip_header, dst_mac, dst_ip, protocol);
    for (i = 0; i < len; i++) {
        ip_header->payload[i] = payload[i];
    }
    ret = build_eth_payload(ip_header);
    if (ret < 0) {
        return ret;
    }
    /*
    for (i = 0; i < ip_header->eth_header.payload_len; i++) {
        printf("%02x ", ip_header->eth_header.payload[i]);
    }
    printf("\n");
    */
    ret = eth_send(sock, ip_header->eth_header);
    if (ret < 0) {
        return ret;
    }
    return SUCCESS;
}

int build_ipv4_header(ip_header_t *ip_header, 
                      const char *dst_mac, const char *dst_ip_str,
                      unsigned short protocol) {
    ipv4_addr_t dst_ip;
    int ret;

    ret = build_eth_header(&(ip_header->eth_header), dst_mac, ETH_TYPE_IPV4);
    if (ret < 0) {
        return ret;
    }
    ip_header->protocol = protocol;
    
    ip_header->src_ip = if_paddr;

    ret = str_to_ip(dst_ip_str, strlen(dst_ip_str)+1, &dst_ip);
    if (ret < 0) {
        return ret;
    }
    ip_header->dst_ip = dst_ip;

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = tos;
    ip_header->total_length = ip_header->payload_len + 20;
    ip_header->identification = identification;
    ip_header->flags = flags;
    ip_header->fragment_offset = fragment_offset;
    ip_header->ttl = ttl;
    ip_header->protocol = protocol;

    return SUCCESS;
}

int build_eth_payload(ip_header_t *ip_header) {
	unsigned int sum = 0;
    unsigned short low;
    unsigned short high;
    int idx = 0;
    unsigned short word;
    unsigned char byte;

    byte = 0;
    byte |= ((ip_header->version << 4) & 0x00f0);
    byte |= ((ip_header->ihl) & 0x000f);
    ip_header->eth_header.payload[idx++] = byte;
    word  = ((byte << 8) & 0xff00);
    word |= ((ip_header->tos) & 0x00ff);
    ip_header->eth_header.payload[idx++] = ip_header->tos;
    sum += word;

    byte = ((ip_header->total_length >> 8) & 0x00ff);
    ip_header->eth_header.payload[idx++] = byte;
    byte = ((ip_header->total_length) & 0x00ff);
    ip_header->eth_header.payload[idx++] = byte;
    sum += ip_header->total_length;

    byte = ((ip_header->identification >> 8) & 0x00ff);
    ip_header->eth_header.payload[idx++] = byte;
    byte = ((ip_header->identification) & 0x00ff);
    ip_header->eth_header.payload[idx++] = byte;
    sum += ip_header->identification;

    byte = 0;
    byte |= ((ip_header->flags << 5) & 0x00e0);
    byte |= ((ip_header->fragment_offset >> 8) & 0x001f);
    ip_header->eth_header.payload[idx++] = byte;
    word  = ((byte << 8) & 0xff00);
    byte  = ((ip_header->fragment_offset) & 0x00ff);
    word |= byte;
    ip_header->eth_header.payload[idx++] = byte;
    sum += word;

    word = 0;
    word |= ((ip_header->ttl << 8) & 0xff00);
    ip_header->eth_header.payload[idx++] = ip_header->ttl;
    word |= ((ip_header->protocol) & 0x00ff);
    ip_header->eth_header.payload[idx++] = ip_header->protocol;
    sum += word;

    word  = (ip_header->src_ip.addr[0] << 8) & 0x0000ff00;
    word |= (ip_header->src_ip.addr[1]) & 0x000000ff;
    sum += word;
    word  = (ip_header->src_ip.addr[2] << 8) & 0x0000ff00;
    word |= (ip_header->src_ip.addr[3]) & 0x000000ff;
    sum += word;
    word  = (ip_header->dst_ip.addr[0] << 8) & 0x0000ff00;
    word |= (ip_header->dst_ip.addr[1]) & 0x000000ff;
    sum += word;
    word  = (ip_header->dst_ip.addr[2] << 8) & 0x0000ff00;
    word |= (ip_header->dst_ip.addr[3]) & 0x000000ff;
    sum += word;

    high = (unsigned short)((sum >> 16) & 0x0000ffff);
    low  = (unsigned short)(sum & 0x0000ffff);
	ip_header->checksum = ( (high + low) ^ 0xffff );
    byte = (ip_header->checksum >> 8) & 0x00ff;
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->checksum & 0x00ff;
    ip_header->eth_header.payload[idx++] = byte;
    
    byte = ip_header->src_ip.addr[0];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->src_ip.addr[1];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->src_ip.addr[2];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->src_ip.addr[3];
    ip_header->eth_header.payload[idx++] = byte;
    
    byte = ip_header->dst_ip.addr[0];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->dst_ip.addr[1];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->dst_ip.addr[2];
    ip_header->eth_header.payload[idx++] = byte;
    byte = ip_header->dst_ip.addr[3];
    ip_header->eth_header.payload[idx++] = byte;

    ip_header->eth_header.payload_len = ip_header->payload_len + idx;
    memcpy(&(ip_header->eth_header.payload[idx]), 
           ip_header->payload, ip_header->payload_len);
    return SUCCESS;
}

void set_ttl(unsigned char new_ttl) {
    ttl = new_ttl;
}

void set_offset(unsigned int new_offset) {
    fragment_offset = new_offset;
}

void set_flags(unsigned char new_flags) {
    flags = new_flags;
}

void set_tos(unsigned char new_tos) {
    tos = new_tos;
}

void set_id(unsigned short new_id) {
    identification = new_id;
}

unsigned char get_ttl(void) {
    return ttl;
}

unsigned int get_offset(void) {
    return fragment_offset;
}

unsigned char get_flags(void) {
    return flags;
}

unsigned char get_tos(void) {
    return tos;
}

unsigned short get_id(void) {
    return identification;
}
