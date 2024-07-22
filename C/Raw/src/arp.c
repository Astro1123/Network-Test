#include <string.h>         // memset(), strncpy()
#include <stdio.h>        // printf()

#include "arp.h"

int send_arppacket(raw_socket_t sock, arp_packet_t *arp_packet);
int parse_arp_rpy(arp_packet_t *arp_packet, 
                  const char *payload, size_t len);
int build_garp(arp_packet_t *arp_packet);
int build_arp_probe(arp_packet_t *arp_packet, const char *dst_ip);
int build_arp_req(arp_packet_t *arp_packet, const char *dst_ip);

int execute_arp(raw_socket_t sock, arp_packet_t *arp_packet, 
                const char *dst_ip) {
    int ret;

    ret = send_arp(sock, arp_packet, dst_ip);
    if (ret < 0) {
        return ret;
    }

    ret = recv_arp_rpy(sock, arp_packet, dst_ip);
    if (ret < 0) {
        return ret;
    }
    return SUCCESS;
}

int send_arp(raw_socket_t sock, arp_packet_t *arp_packet, 
             const char *dst_ip) {
    int ret;

    memset(arp_packet, 0, sizeof(arp_packet_t));
    ret = build_arp_req(arp_packet, dst_ip);
    if (ret < 0) {
        return ret;
    }
    return send_arppacket(sock, arp_packet);
}

int recv_arp_rpy(raw_socket_t sock, arp_packet_t *arp_packet,
                 const char *dst_ip) {
    int ret;
    
    while (1) {
        ret = recv_arp_oper(sock, arp_packet, ARP_RPY);
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        if (!comp_mac_mac(arp_packet->eth_header.dst_mac, if_haddr)) {
            continue;
        }
        if (!comp_ip(arp_packet->spa, dst_ip)) {
            continue;
        }
        if (!comp_mac_mac(arp_packet->tha, if_haddr)) {
            continue;
        }
        if (!comp_ip_ip(arp_packet->tpa, if_paddr)) {
            continue;
        }
        break;
    }
    return ret;
}

int recv_arp_proxy(raw_socket_t sock, arp_packet_t *arp_packet) {
    int ret;
    
    while (1) {
        ret = recv_arp_oper(sock, arp_packet, ARP_RPY);
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        if (!comp_mac_mac(arp_packet->eth_header.dst_mac, if_haddr)) {
            continue;
        }
        if (!comp_mac_mac(arp_packet->tha, if_haddr)) {
            continue;
        }
        if (!comp_ip_ip(arp_packet->tpa, if_paddr)) {
            continue;
        }
        break;
    }
    return ret;
}

int recv_arp(raw_socket_t sock, arp_packet_t *arp_packet) {
    int ret;
    
    while (1) {
        memset(arp_packet, 0, sizeof(arp_packet_t));
        ret = eth_recv(sock, &(arp_packet->eth_header));
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        ret = parse_arp_rpy(arp_packet, arp_packet->eth_header.payload, 
                            arp_packet->eth_header.payload_len);
        if (ret < 0) {
            return ret;
        }
        break;
    }
    return ret;
}

int recv_arp_oper(raw_socket_t sock, arp_packet_t *arp_packet, int oper) {
    int ret;
    
    while (1) {
        ret = recv_arp(sock, arp_packet);
        if (ret < 0) {
            return ret;
        }
        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
        if (arp_packet->oper == oper) {
            break;
        }
    }
    return ret;
}

int build_arp_req(arp_packet_t *arp_packet, const char *dst_ip) {
    mac_addr_t tha;
    ipv4_addr_t tpa;
    const char *dst_mac = "00:00:00:00:00:00";
    int ret;

    ret = str_to_mac(dst_mac, strlen(dst_mac)+1, &tha);
    if (ret < 0) {
        return ret;
    }
    ret = str_to_ip(dst_ip, strlen(dst_ip)+1, &tpa);
    if (ret < 0) {
        return ret;
    }
    arp_packet->htype = HTYPE;
    arp_packet->ptype = PTYPE_IPV4;
    arp_packet->hlen = HA_LEN;
    arp_packet->plen = PA_LEN;
    arp_packet->oper = ARP_REQ;
    arp_packet->sha = if_haddr;
    arp_packet->tha = tha;
    arp_packet->spa = if_paddr;
    arp_packet->tpa = tpa;

    return SUCCESS;
}

int build_garp(arp_packet_t *arp_packet) {
    mac_addr_t tha;
    const char *dst_mac = "00:00:00:00:00:00";
    int ret;

    ret = str_to_mac(dst_mac, strlen(dst_mac)+1, &tha);
    if (ret < 0) {
        return ret;
    }
    arp_packet->htype = HTYPE;
    arp_packet->ptype = PTYPE_IPV4;
    arp_packet->hlen = HA_LEN;
    arp_packet->plen = PA_LEN;
    arp_packet->oper = ARP_REQ;
    arp_packet->sha = if_haddr;
    arp_packet->tha = tha;
    arp_packet->spa = if_paddr;
    arp_packet->tpa = if_paddr;

    return SUCCESS;
}

int build_arp_probe(arp_packet_t *arp_packet, const char *dst_ip) {
    mac_addr_t tha;
    ipv4_addr_t tpa, spa;
    const char *dst_mac = "00:00:00:00:00:00";
    const char *src_ip = "0.0.0.0";
    int ret;

    ret = str_to_mac(dst_mac, strlen(dst_mac)+1, &tha);
    if (ret < 0) {
        return ret;
    }
    ret = str_to_ip(dst_ip, strlen(dst_ip)+1, &tpa);
    if (ret < 0) {
        return ret;
    }
    ret = str_to_ip(src_ip, strlen(src_ip)+1, &spa);
    if (ret < 0) {
        return ret;
    }
    arp_packet->htype = HTYPE;
    arp_packet->ptype = PTYPE_IPV4;
    arp_packet->hlen = HA_LEN;
    arp_packet->plen = PA_LEN;
    arp_packet->oper = ARP_REQ;
    arp_packet->sha = if_haddr;
    arp_packet->tha = tha;
    arp_packet->spa = spa;
    arp_packet->tpa = tpa;

    return SUCCESS;
}

int parse_arp_rpy(arp_packet_t *arp_packet, 
                  const char *payload, size_t len) {
    const unsigned int arp_len = 8 + HA_LEN * 2 + PA_LEN * 2;
    int i;

    if (len < arp_len) {
        return FAILURE;
    }
    if (arp_packet == NULL || payload == NULL) {
        return FAILURE;
    }
    arp_packet->htype = *payload;
    payload++;
    arp_packet->htype <<= 8;
    arp_packet->htype |= *payload;
    payload++;

    arp_packet->ptype = *payload;
    payload++;
    arp_packet->ptype <<= 8;
    arp_packet->ptype |= *payload;
    payload++;

    arp_packet->hlen = *payload;
    payload++;

    arp_packet->plen = *payload;
    payload++;

    arp_packet->oper = *payload;
    payload++;
    arp_packet->oper <<= 8;
    arp_packet->oper |= *payload;
    payload++;

    for (i = 0; i < HA_LEN; i++) {
        arp_packet->sha.addr[i] = *payload;
        payload++;
    }

    for (i = 0; i < PA_LEN; i++) {
        arp_packet->spa.addr[i] = *payload;
        payload++;
    }

    for (i = 0; i < HA_LEN; i++) {
        arp_packet->tha.addr[i] = *payload;
        payload++;
    }

    for (i = 0; i < PA_LEN; i++) {
        arp_packet->tpa.addr[i] = *payload;
        payload++;
    }
    return SUCCESS;
}

int send_arppacket(raw_socket_t sock, arp_packet_t *arp_packet) {
    int ret;
    unsigned int i;
    size_t len;
    char buf[BUF_SIZE - ETH_HEADER_SIZE];
    char *buf_p = buf;

    memset(buf, 0, sizeof(buf));
    *buf_p = (char)((arp_packet->htype >> 8) & 0x00ff);
    buf_p++;
    *buf_p = (char)((arp_packet->htype) & 0x00ff);
    buf_p++;
    *buf_p = (char)((arp_packet->ptype >> 8) & 0x00ff);
    buf_p++;
    *buf_p = (char)((arp_packet->ptype) & 0x00ff);
    buf_p++;
    *buf_p = arp_packet->hlen;
    buf_p++;
    *buf_p = arp_packet->plen;
    buf_p++;
    *buf_p = (char)((arp_packet->oper >> 8) & 0x00ff);
    buf_p++;
    *buf_p = (char)((arp_packet->oper) & 0x00ff);
    buf_p++;
    for (i = 0; i < HA_LEN; i++) {
        *buf_p = arp_packet->sha.addr[i];
        buf_p++;
    }
    for (i = 0; i < PA_LEN; i++) {
        *buf_p = arp_packet->spa.addr[i];
        buf_p++;
    }
    for (i = 0; i < HA_LEN; i++) {
        *buf_p = arp_packet->tha.addr[i];
        buf_p++;
    }
    for (i = 0; i < PA_LEN; i++) {
        *buf_p = arp_packet->tpa.addr[i];
        buf_p++;
    }
    ret = build_eth_header(&(arp_packet->eth_header), 
                           "ff:ff:ff:ff:ff:ff", ETH_TYPE_ARP);
    if (ret < 0) {
        return ret;
    }
    len = (size_t)(buf_p - buf);
    arp_packet->eth_header.payload_len = len;
    for (i = 0; i < len; i++) {
        arp_packet->eth_header.payload[i] = buf[i];
    }
    ret = eth_send(sock, arp_packet->eth_header);
    if (ret < 0) {
        return ret;
    }
    return SUCCESS;

}

int send_garp(raw_socket_t sock, arp_packet_t *arp_packet) {
    int ret;

    memset(arp_packet, 0, sizeof(arp_packet_t));
    ret = build_garp(arp_packet);
    if (ret < 0) {
        return ret;
    }
    return send_arppacket(sock, arp_packet);
}

int send_arp_probe(raw_socket_t sock, arp_packet_t *arp_packet, 
                   const char *dst_ip) {
    int ret;

    memset(arp_packet, 0, sizeof(arp_packet_t));
    ret = build_arp_probe(arp_packet, dst_ip);
    if (ret < 0) {
        return ret;
    }
    return send_arppacket(sock, arp_packet);
}
