#include <string.h>         // memset(), strncpy()
#include <stdlib.h>         // rand()
#include <time.h>           // time(), clock_gettime()
#include <stdio.h>          // printf()
#include <unistd.h>         // usleep()

#include "icmp.h"
#include "udp.h"
#include "arp.h"

#define NANO_SEC 1000000000
#define MICRO_SEC 1000000
#define MILLI_SEC 1000

static int build_ip_payload(icmp_header_t *icmp_header);
int build_icmp_echo_header(icmp_header_t *icmp_header, unsigned short id, 
                           unsigned short sequence);

int ping_main(raw_socket_t sock, icmp_header_t *icmp_header, 
              const char *recv_ip, const char *mac, const char *dst_ip, 
              unsigned short id, unsigned short sequence);

int icmp_timeout_sec = 10;

unsigned short icmp_echo_id = 0;
unsigned short icmp_echo_sequence = 0;
unsigned int   ping_count = 3;

unsigned short get_random(void) {
    double num;

    num = (double)(rand() / (1.0 + RAND_MAX) * 65536);
    //printf("%f\n", num);
    return (unsigned short)num;
}

int execute_traceroute(raw_socket_t sock, const char *dst_mac,
                       const char *dst_ip, int proto) {
    int ret = 0;
    unsigned int i, j, k;
    unsigned short id = 0;
    time_t s_time, c_time;
    struct timespec st, rt;
    long diff_sec, diff_nsec;
    double diff_time;
    icmp_header_t icmp_header;
    unsigned short udp_send_port = 33434;
    char recv_ip[16];
    char send_ip[16];

    snprintf(recv_ip, sizeof(recv_ip), "%d.%d.%d.%d",
             if_paddr.addr[0], if_paddr.addr[1], 
             if_paddr.addr[2], if_paddr.addr[3]);

    snprintf(send_ip, sizeof(send_ip), "%d.%d.%d.1",
             if_paddr.addr[0], if_paddr.addr[1], 
             if_paddr.addr[2]);

    id = get_random();
    set_icmp_echo_id(id);
    for (i = 1; i <= 30; i++) {
        ipv4_addr_t addr[3];
        int finish = 0;
        ipv4_addr_t addr_set[3] = {0};
        unsigned int cnt[3] = {0};
        double recv_time[3] = {0};
        double recv_time_list[3][3] = {0};
        unsigned int set_idx = 0;

        for (j = 0; j < 3; j++) {
            for (k = 0; k < IPV4_ADDR_SIZE; k++) {
                addr[j].addr[k] = 0;
            }
        }

        set_ttl(i);
        for (j = 0; j < 3; j++) {
            clock_gettime(CLOCK_REALTIME, &st);
            s_time = st.tv_sec;
            if (proto == TRACEROUTE_PROTO_ICMP) {
                ret = send_icmp_ipv4(sock, &icmp_header, NULL, 0, ICMP_TYPE_ECHO_REQ, 
                                     ICMP_CODE_ECHO, dst_mac, dst_ip);
                id++;
                set_icmp_echo_id(id);
            } else {
                udp_header_t udp_header;

                ret = send_udp_ipv4(sock, &udp_header, "", 0,
                                    50000, udp_send_port, dst_mac, dst_ip);
                udp_send_port++;
            }
            if (ret < 0) {
                return FAILURE;
            }
            while (1) {
                int isrecv = 0;
                ret = recv_icmp(sock, &icmp_header, recv_ip);
                if (ret < 0) {
                    return FAILURE;
                }
                clock_gettime(CLOCK_REALTIME, &rt);
                c_time = rt.tv_sec;
                //c_time = time(NULL);
                if (c_time - s_time > icmp_timeout_sec) {
                    printf("Timeout.\n");
                    break;
                }
                switch (icmp_header.type) {
                    case ICMP_TYPE_TIME_EXCEEDED:
                        isrecv = 1;
                        break;
                    case ICMP_TYPE_ECHO_RPY:
                        if (proto == TRACEROUTE_PROTO_ICMP) {
                            isrecv = 1;
                        }
                        break;
                    case ICMP_TYPE_UNREACHABLE:
                        if (proto == TRACEROUTE_PROTO_UDP) {
                            if (icmp_header.code == ICMP_CODE_UNREACHABLE_PORT) {
                                isrecv = 1;
                            }
                        }
                        break;
                    default:
                        break;
                    if (isrecv) {
                        break;
                    }
                }
                diff_sec = (long)(c_time - s_time);
                diff_nsec = (long)(rt.tv_nsec - st.tv_nsec);
                diff_time = diff_sec+((double)diff_nsec / NANO_SEC);
                recv_time[j] = diff_time * MILLI_SEC;
                memcpy(addr[j].addr, icmp_header.ip_header.src_ip.addr, IPV4_ADDR_SIZE);
                break;
            }
        }
        
        for (j = 0; j < 3; j++) {
            int find = 0;

            for (k = 0; k < set_idx; k++) {
                if (comp_ip_ip(addr_set[k], addr[j])) {
                    recv_time_list[k][cnt[k]] = recv_time[j];
                    cnt[k]++;
                    find = 1;
                    break;
                }
            }
            if (!find) {
                memcpy(addr_set[set_idx].addr, addr[j].addr, IPV4_ADDR_SIZE);
                cnt[set_idx] = 1;
                recv_time_list[set_idx][0] = recv_time[j];
                set_idx++;
            }
        }
        for (j = 0; j < set_idx; j++) {
            char ip_str[16];
            int result;
            size_t str_length = 0;
            char time_str[256];

            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", 
                     addr_set[j].addr[0], addr_set[j].addr[1],
                     addr_set[j].addr[2], addr_set[j].addr[3]);
                            char *str_p;

            memset(time_str, 0, sizeof(time_str));
            str_p = time_str;
            for (k = 0; k < cnt[j]; k++) {
                result = snprintf(str_p, sizeof(time_str) - str_length, 
                                  " %8.3f ms", recv_time_list[j][k]);
                if (result > 0) {
                    str_length += result;
                    if (str_length >= sizeof(time_str) - 1) {
                        break;
                    }
                    str_p += result;
                } else {
                    return FAILURE;
                }
            }
            if (j == 0) {
                printf("%2d: %-16s\ttime:%s\n", 
                       i, ip_str, time_str);
            } else {
                printf("    %-16s\ttime:%s\n", 
                       ip_str, time_str);
            }
            if (comp_ip(addr[j], dst_ip)) {
                finish = 1;
            }
        }
        if (finish) {
            break;
        }
    }

    return SUCCESS;
}

int execute_ping(raw_socket_t sock, const char *dst_mac, const char *dst_ip) {
    icmp_header_t icmp_header;
    int ret;
    char mac_str[18];
    char *mac;
    unsigned short id = 0;
    unsigned short sequence = 0;
    char recv_ip[16];
    unsigned int i;

    srand((unsigned int)time(NULL));

    snprintf(recv_ip, sizeof(recv_ip), "%d.%d.%d.%d",
             if_paddr.addr[0], if_paddr.addr[1], 
             if_paddr.addr[2], if_paddr.addr[3]);

    if (dst_mac == NULL) {
        arp_packet_t arp_packet;

        ret = execute_arp(sock, &arp_packet, dst_ip);
        if (ret < 0) {
            return FAILURE;
        }
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_packet.sha.addr[0], arp_packet.sha.addr[1], 
                 arp_packet.sha.addr[2], arp_packet.sha.addr[3], 
                 arp_packet.sha.addr[4], arp_packet.sha.addr[5]);
        mac = mac_str;
    } else {
        mac = (char *)dst_mac;
    }

    id = get_random();
    set_icmp_echo_id(id);

    printf("Send ping to %s.\n", dst_ip);
    if (ping_count > 0) {
        for (i = 0; i < ping_count; i++) {
            set_icmp_echo_sequence(sequence);
            ret = ping_main(sock, &icmp_header, recv_ip, mac, 
                            dst_ip, id, sequence);
            if (ret < 0) {
                return FAILURE;
            }
            sequence++;
            usleep(MICRO_SEC);
        }
    } else {
        while (1) {
            set_icmp_echo_sequence(sequence);
            ret = ping_main(sock, &icmp_header, recv_ip, mac, 
                            dst_ip, id, sequence);
            if (ret < 0) {
                return FAILURE;
            }
            sequence++;
            usleep(MICRO_SEC);
        }
    }
    return SUCCESS;
}

int ping_main(raw_socket_t sock, icmp_header_t *icmp_header, 
              const char *recv_ip, const char *mac, const char *dst_ip, 
              unsigned short id, unsigned short sequence) {
    time_t s_time, c_time;
    struct timespec st, rt;
    long diff_sec, diff_nsec;
    double diff_time;
    int ret;

    clock_gettime(CLOCK_REALTIME, &st);
    s_time = st.tv_sec;
    //s_time = time(NULL);
    ret = send_icmp_ipv4(sock, icmp_header, NULL, 0, ICMP_TYPE_ECHO_REQ, 
                         ICMP_CODE_ECHO, mac, dst_ip);
    if (ret < 0) {
        return FAILURE;
    }
    while (1) {
        ret = recv_icmp(sock, icmp_header, recv_ip);
        if (ret < 0) {
            return FAILURE;
        }
        clock_gettime(CLOCK_REALTIME, &rt);
        c_time = rt.tv_sec;
        //c_time = time(NULL);
        if (c_time - s_time > icmp_timeout_sec) {
            printf("Timeout.\n");
            break;
        }
        if (icmp_header->type != ICMP_TYPE_ECHO_RPY) {
            continue;
        }
        if (icmp_header->rest.echo.id != id) {
            continue;
        }
        if (icmp_header->rest.echo.sequence != sequence) {
            continue;
        }
        if (!comp_ip(icmp_header->ip_header.src_ip, dst_ip)) {
            continue;
        }
        diff_sec = (long)(c_time - s_time);
        diff_nsec = (long)(rt.tv_nsec - st.tv_nsec);
        diff_time = diff_sec+((double)diff_nsec / NANO_SEC);
        printf("Received. sequence: %d, time: %.3f ms\n", 
               sequence, diff_time * MILLI_SEC);
        break;
    }
    return SUCCESS;
}

int parse_icmp_header(icmp_header_t *icmp_header,
                      unsigned char *payload, size_t len) {
    unsigned char *payload_p = payload;
    int idx = 0;

    if (len < ICMP_HEADER_SIZE) {
        return FAILURE;
    }
    icmp_header->type = *payload_p;
    payload_p++;
    icmp_header->code = *payload_p;
    payload_p++;

    icmp_header->checksum = *payload_p;
    icmp_header->checksum <<= 8;
    payload_p++;
    icmp_header->checksum |= *payload_p;
    payload_p++;

    switch (icmp_header->type) {
        case ICMP_TYPE_ECHO_RPY:
        case ICMP_TYPE_ECHO_REQ:
            if (len < ICMP_HEADER_SIZE + 4) {
                return FAILURE;
            }
            icmp_header->rest.echo.id = *payload_p;
            icmp_header->rest.echo.id <<= 8;
            payload_p++;
            icmp_header->rest.echo.id |= *payload_p;
            payload_p++;
            
            icmp_header->rest.echo.sequence = *payload_p;
            icmp_header->rest.echo.sequence <<= 8;
            payload_p++;
            icmp_header->rest.echo.sequence |= *payload_p;
            payload_p++;
            break;
        default:
            break;
    }
    icmp_header->payload_len = 0;
    while (payload_p - payload < (long)len) {
        icmp_header->payload[idx++] = *payload_p;
        payload_p++;
        icmp_header->payload_len++;
    }
    return SUCCESS;
}

int recv_icmp(raw_socket_t sock, icmp_header_t *icmp_header,
              const char *recv_ip_addr) {
    int ret;
    time_t s_time, c_time;

    time(&s_time);
    while (1) {
        memset(icmp_header, 0, sizeof(icmp_header_t));
        ret = recv_ip(sock, &(icmp_header->ip_header), recv_ip_addr);
        if (ret < 0) {
            return FAILURE;
        }
        time(&c_time);
        if (blocking == 0 && c_time - s_time >= icmp_timeout_sec) {
            printf("Timeout.\n");
            return FAILURE;
        }
        if (icmp_header->ip_header.protocol != IP_PROTO_ICMP) {
            continue;
        }
        ret = parse_icmp_header(icmp_header, icmp_header->ip_header.payload, 
                                icmp_header->ip_header.payload_len);
        break;
    }
    return ret;
}

int send_icmp_ipv4(raw_socket_t sock, icmp_header_t *icmp_header,
                   const char *payload, size_t len,
                   const int type, const int code,
                   const char *dst_mac, const char *dst_ip) {
    int ret;
    char ip_payload[BUF_SIZE - ETH_HEADER_SIZE - IPV4_HEADER_SIZE];
    char ip_payload_len;
    
    memset(icmp_header, 0, sizeof(icmp_header_t));

    icmp_header->type = type;
    icmp_header->code = code;
    switch (type) {
        case ICMP_TYPE_ECHO_RPY:
        case ICMP_TYPE_ECHO_REQ:
            ret = build_icmp_echo_header(icmp_header, icmp_echo_id,
                                         icmp_echo_sequence);
            if (ret < 0) {
                return FAILURE;
            }
            break;
    }
    icmp_header->payload_len = len;
    if (len > 0) {
        memcpy(icmp_header->payload, payload, len);
    }

    ret = build_ip_payload(icmp_header);
    if (ret < 0) {
        return FAILURE;
    }

    ip_payload_len = icmp_header->ip_header.payload_len;
    memcpy(ip_payload, icmp_header->ip_header.payload, ip_payload_len);

    /*
    for (unsigned int i = 0; i < ip_payload_len; i++) {
        printf("%02x ", ip_payload[i]);
    }
    printf("\n");
    */
    ret = send_ipv4(sock, &(icmp_header->ip_header), 
                    ip_payload, ip_payload_len, 
                    dst_mac, dst_ip, IP_PROTO_ICMP);
    if (ret < 0) {
        return FAILURE;
    }
    return ret;
}

int build_icmp_echo_header(icmp_header_t *icmp_header, unsigned short id, 
                           unsigned short sequence) {
    icmp_header->rest.echo.id = id;
    icmp_header->rest.echo.sequence = sequence;
    return SUCCESS;
}

static int build_ip_payload(icmp_header_t *icmp_header) {
    unsigned int sum = 0;
    unsigned short high;
    unsigned short low;
    unsigned int len;
    unsigned int i;
    int idx = 0;
    int idx_2;
    unsigned short word;
    unsigned char byte;
    char *payload_p;

    byte = icmp_header->type;
    icmp_header->ip_header.payload[idx++] = byte;
    word = (byte << 8) & 0xff00;
    byte = icmp_header->code;
    icmp_header->ip_header.payload[idx++] = byte;
    word |= byte;
    sum += word;
    
    idx_2 = idx + 2;
    switch (icmp_header->type) {
        case ICMP_TYPE_ECHO_RPY:
        case ICMP_TYPE_ECHO_REQ:
            byte = (icmp_header->rest.echo.id >> 8) & 0x00ff;
            icmp_header->ip_header.payload[idx_2++] = byte;
            byte = icmp_header->rest.echo.id & 0x00ff;
            icmp_header->ip_header.payload[idx_2++] = byte;
            sum += icmp_header->rest.echo.id;

            byte = (icmp_header->rest.echo.sequence >> 8) & 0x00ff;
            icmp_header->ip_header.payload[idx_2++] = byte;
            byte = icmp_header->rest.echo.sequence & 0x00ff;
            icmp_header->ip_header.payload[idx_2++] = byte;
            sum += icmp_header->rest.echo.sequence;
            break;
        default:
            break;
    }

    i = 0;
    payload_p = (char *)icmp_header->payload;
    len = icmp_header->payload_len;
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
    high = ((sum >> 16) & 0x0000ffff);
    low  = (sum & 0x0000ffff);
    icmp_header->checksum = ( (high + low) ^ 0xffff );

    byte = ((icmp_header->checksum >> 8) & 0x00ff);
    icmp_header->ip_header.payload[idx++] = byte;
    byte = ((icmp_header->checksum) & 0x00ff);
    icmp_header->ip_header.payload[idx++] = byte;

    idx = idx_2;
    icmp_header->ip_header.payload_len = icmp_header->payload_len + idx;
    memcpy(&(icmp_header->ip_header.payload[idx]), 
           icmp_header->payload, icmp_header->payload_len);
    return SUCCESS;
}

void set_timeout_icmp(int timeout) {
    icmp_timeout_sec = timeout;
}

int get_timeout_icmp(void) {
    return icmp_timeout_sec;
}

void set_icmp_echo_id(unsigned short id) {
    icmp_echo_id = id;
}

unsigned short get_icmp_echo_id(void) {
    return icmp_echo_id;
}

void set_icmp_echo_sequence(unsigned short sequence) {
    icmp_echo_sequence = sequence;
}

unsigned short get_icmp_echo_sequence(void) {
    return icmp_echo_sequence;
}

void set_ping_count(unsigned int count) {
    ping_count = count;
}

unsigned int get_ping_count(void) {
    return ping_count;
}
