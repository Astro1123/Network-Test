#include <string.h>         // memset()
#include <stdlib.h>         // strtol()
#include <stdio.h>          // printf()

#include "common.h"

int str_to_mac(const char *str, size_t size, mac_addr_t *mac) {
    unsigned int i, j;
    char buf[10];
    char *buf_p = buf;

    memset(buf, 0, sizeof(buf));
    j = 0;
    for (i = 0; i < size; i++) {
        if (str[i] == ':' || str[i] == '-') {
            mac->addr[j++] = (unsigned char)strtol(buf, NULL, 16);
            if (j >= MAC_ADDR_SIZE) {
                return FAILURE;
            }
            buf_p = buf;
            memset(buf, 0, sizeof(buf));
            i++;
        }
        *buf_p = str[i];
        buf_p++;
    }
    mac->addr[j++] = (unsigned char)strtol(buf, NULL, 16);
    return SUCCESS;
}

int str_to_ip(const char *str, size_t size, ipv4_addr_t *ip) {
    unsigned int i, j;
    char buf[10];
    char *buf_p = buf;

    memset(buf, 0, sizeof(buf));
    j = 0;
    for (i = 0; i < size; i++) {
        if (str[i] == '.') {
            ip->addr[j++] = (unsigned char)strtol(buf, NULL, 10);
            if (j >= IPV4_ADDR_SIZE) {
                break;
            }
            buf_p = buf;
            memset(buf, 0, sizeof(buf));
            i++;
        }
        *buf_p = str[i];
        buf_p++;
    }
    ip->addr[j++] = (unsigned char)strtol(buf, NULL, 10);
    return SUCCESS;
}

int comp_ip(ipv4_addr_t ip_1, const char *ip_2) {
    int i;
    ipv4_addr_t ip;

    str_to_ip(ip_2, strlen(ip_2)+1, &ip);
    for (i = 0; i < IPV4_ADDR_SIZE; i++) {
        if (ip_1.addr[i] != ip.addr[i]) {
            return COMP_FALSE;
        }
    }
    return COMP_TRUE;
}

int comp_mac(mac_addr_t mac_1, const char *mac_2) {
    int i;
    mac_addr_t mac;

    str_to_mac(mac_2, strlen(mac_2)+1, &mac);
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        if (mac_1.addr[i] != mac.addr[i]) {
            return COMP_FALSE;
        }
    }
    return COMP_TRUE;
}

int comp_mac_mac(mac_addr_t mac_1, mac_addr_t mac_2) {
    int i;

    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        if (mac_1.addr[i] != mac_2.addr[i]) {
            return COMP_FALSE;
        }
    }
    return COMP_TRUE;
}

int comp_ip_ip(ipv4_addr_t ip_1, ipv4_addr_t ip_2) {
    int i;

    for (i = 0; i < IPV4_ADDR_SIZE; i++) {
        if (ip_1.addr[i] != ip_2.addr[i]) {
            return COMP_FALSE;
        }
    }
    return COMP_TRUE;
}
