#include <stdio.h>          // printf()
#include <string.h>         // strlen(), strncpy(), memset()
#include <unistd.h>         // close()

#include "udp.h"
#include "arp.h"
#include "icmp.h"
#include "common.h"
#include "read_config.h"

int arp(void) {
    arp_packet_t arp_packet;
    raw_socket_t sock;
    read_data_t data;
    int ret;

    ret = read_config(CONFIG_FILE, &data);
    if (ret < 0) {
        return FAILURE;
    }

    //printf("%s\n", data.src_mac);
    //printf("%s\n", data.src_ip);
    //printf("%s\n", data.dst_ip);
    //printf("%s\n", data.interface);

    ret = create_sock(data.interface, &sock);
    if (ret < 0) {
        return FAILURE;
    }
    
    ret = execute_arp(sock, &arp_packet, data.dst_ip);
    if (ret < 0) {
        return FAILURE;
    }
    printf("%s", data.dst_ip);
    printf(" -> ");
    printf("%02x:", arp_packet.sha.addr[0]);
    printf("%02x:", arp_packet.sha.addr[1]);
    printf("%02x:", arp_packet.sha.addr[2]);
    printf("%02x:", arp_packet.sha.addr[3]);
    printf("%02x:", arp_packet.sha.addr[4]);
    printf("%02x\n", arp_packet.sha.addr[5]);

    close(sock.fd);
    printf("\n");
    return SUCCESS;
}

int udp_recv(void) {
    udp_header_t udp_header;
    raw_socket_t sock;
    read_data_t data;
    int ret;

    ret = read_config(CONFIG_FILE, &data);
    if (ret < 0) {
        return FAILURE;
    }

    ret = create_sock(data.interface, &sock);
    if (ret < 0) {
        return FAILURE;
    }
    ret = recv_udp(sock, &udp_header, NULL, 50000);
    if (ret < 0) {
        return FAILURE;
    }

    close(sock.fd);
    printf("%s\n", udp_header.payload);
    printf("\n");
    return SUCCESS;
}

int udp_send(void) {
    udp_header_t udp_header;
    raw_socket_t sock;
    read_data_t data;
    int ret;
    char message[256] = "Test";

    ret = read_config(CONFIG_FILE, &data);
    if (ret < 0) {
        return FAILURE;
    }

    ret = create_sock(data.interface, &sock);
    if (ret < 0) {
        return FAILURE;
    }
    ret = send_udp_ipv4(sock, &udp_header, 
                        message, 4,
                        data.src_port, data.dst_port, 
                        data.dst_mac, data.dst_ip);
    if (ret < 0) {
        return FAILURE;
    }

    close(sock.fd);
    printf("\n");
    return SUCCESS;
}

int ping(void) {
    raw_socket_t sock;
    read_data_t data;
    int ret;

    ret = read_config(CONFIG_FILE, &data);
    if (ret < 0) {
        return FAILURE;
    }

    ret = create_sock(data.interface, &sock);
    if (ret < 0) {
        return FAILURE;
    }
    ret = execute_ping(sock, NULL, data.dst_ip);
    if (ret < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

int traceroute(int mode, int proto) {
    raw_socket_t sock;
    read_data_t data;
    int ret;
    char mac_str[18];

    ret = read_config(CONFIG_FILE, &data);
    if (ret < 0) {
        return FAILURE;
    }

    ret = create_sock(data.interface, &sock);
    if (ret < 0) {
        return FAILURE;
    }

    if (mode == 1) {
        arp_packet_t arp_packet;
        char *ip = data.dst_ip;
        char *strp = strrchr(ip, '.');
        if (strp == NULL) {
            return FAILURE;
        }
        strp++;
        *strp = '1';
        strp++;
        *strp = '\0';

        ret = execute_arp(sock, &arp_packet, ip);
        if (ret < 0) {
            return FAILURE;
        }
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_packet.sha.addr[0], arp_packet.sha.addr[1], 
                 arp_packet.sha.addr[2], arp_packet.sha.addr[3], 
                 arp_packet.sha.addr[4], arp_packet.sha.addr[5]);
    }

    ret = execute_traceroute(sock, mac_str, "8.8.8.8", proto);
    if (ret < 0) {
        return FAILURE;
    }
    return SUCCESS;
}

int main(void) {
    int ret;

    ret = arp();
    if (ret < 0) {
        return FAILURE;
    }
/*
    ret = ping();
    if (ret < 0) {
        return FAILURE;
    }
*/
/*
    ret = udp_send();
    if (ret < 0) {
        return FAILURE;
    }
*/
/*
    ret = udp_recv();
    if (ret < 0) {
        return FAILURE;
    }
*/
/*
    ret = traceroute(1, TRACEROUTE_PROTO_UDP);
    if (ret < 0) {
        return FAILURE;
    }
*/
    return SUCCESS;
}
