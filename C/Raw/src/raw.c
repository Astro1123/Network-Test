#include <stdio.h>              // perror(), NULL
#include <string.h>             // memset()
#include <sys/types.h>          // socket(), bind(), setsockopt()
#include <sys/socket.h>         // socket(), bind(), setsockopt()
#include <arpa/inet.h>          // htons()
#include <net/ethernet.h>       // L2 protocols
#include <net/if.h>             // struct ifreq
#include <unistd.h>             // close(), alerm()
#include <sys/ioctl.h>          // ioctl(), SIOCGIFINDEX, SIOCGIFHWADDR
#include <sys/select.h>         // select()
#include <errno.h>              // errno
#include <stdint.h>             // uint32_t

//#define PROMISCUOUS

#include "raw.h"

mac_addr_t  if_haddr = {0};
ipv4_addr_t if_paddr = {0};

int raw_send(raw_socket_t sock, const char *buf, size_t len);
int raw_recv(raw_socket_t sock, char *buf, size_t size);
int get_haddr(raw_socket_t *sock, const char *ifname);
int get_paddr(raw_socket_t *sock, const char *ifname);

int raw_send(raw_socket_t sock, const char *buf, size_t len) {
    int ret;

    /*
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    //*/
    ret = sendto(sock.fd, buf, len, 0, (struct sockaddr *)&(sock.sa), sizeof(sock.sa));
    if (ret < 0) {
        perror("sendto");
        close(sock.fd);
        return FAILURE;
    }
    return ret;
}

int raw_recv(raw_socket_t sock, char *buf, size_t size) {
    int ret;
    struct sockaddr_ll rll;
    socklen_t rll_size;
    struct timeval timeout_sel;
    fd_set fds, readfds;

    memset(&rll, 0, sizeof(rll));
    rll_size = sizeof(rll);

    FD_ZERO(&readfds);
    FD_SET(sock.fd, &readfds);
    
    if (!timer_set_flag) {
        set_timer();
    }

    while (1) {
        memcpy(&fds, &readfds, sizeof(fd_set));

        timeout_sel.tv_sec = 0;
        timeout_sel.tv_usec = 0;
        ret = select(sock.fd + 1, &fds , NULL, NULL, &timeout_sel);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            return FAILURE;
        }
        if (FD_ISSET(sock.fd, &fds)) {
            memset(buf, 0, size);
            ret = recvfrom(sock.fd, buf, size, 0, 
                           (struct sockaddr *)&rll, &rll_size);
            if (ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("recvfrom");
                close(sock.fd);
                return FAILURE;
            }
            break;
        }

        if (blocking != 0) {
            continue;
        }

        if (timeout_flag && !blocking) {
            return ERR_TIMEOUT;
        }
    }
    return ret;
}

int eth_send(raw_socket_t sock, eth_header_t header) {
    char buf[BUF_SIZE];
    char *buf_p = buf;
    unsigned int i;

    memset(buf, 0, sizeof(buf));
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        *buf_p = header.dst_mac.addr[i];
        buf_p++;
    }
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        *buf_p = header.src_mac.addr[i];
        buf_p++;
    }
    *buf_p = (char)((header.type >> 8) & 0x00ff);
    buf_p++;
    *buf_p = (char)(header.type & 0x00ff);
    buf_p++;
    for (i = 0; i < header.payload_len; i++) {
        *buf_p = header.payload[i];
        buf_p++;
    }
    memcpy( sock.sa.sll_addr, (char *)header.src_mac.addr, ETHER_ADDR_LEN );
    return raw_send(sock, buf, (size_t)(buf_p - buf));
}

int eth_recv(raw_socket_t sock, eth_header_t *header) {
    char buf[BUF_SIZE];
    int ret;

    memset(buf, 0, sizeof(buf));
    ret = raw_recv(sock, buf, sizeof(buf));
    if (ret < 0) {
        return ret;
    }
    memset(header, 0, sizeof(eth_header_t));
    return parse_eth_header(buf, ret, header);
}

int create_sock(const char *ifname, raw_socket_t *sock) {
    int ret;
    struct ifreq ifr;
#ifdef PROMISCUOUS
    struct packet_mreq mreq;
#endif

    if (sock == NULL) {
        return FAILURE;
    }
    // socket
    sock->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock->fd < 0) {
        perror("socket");
        return FAILURE;
    }

    // interface
    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock->fd, SIOCGIFINDEX, &ifr) < 0 ) {
        perror("ioctl SIOCGIFINDEX");
        close(sock->fd);
        return FAILURE;
    }

    // bind
    sock->ifidx = ifr.ifr_ifindex;
    sock->sa.sll_family = AF_PACKET;
    sock->sa.sll_protocol = htons(ETH_P_ALL);
    sock->sa.sll_ifindex = ifr.ifr_ifindex;
    sock->sa.sll_halen = MAC_ADDR_SIZE;
    ret = bind(sock->fd, (struct sockaddr *)&(sock->sa), sizeof(sock->sa));
    if (ret < 0) {
        perror("bind");
        close(sock->fd);
        return FAILURE;
    }

    // Promiscuous mode (Linux)
#ifdef PROMISCUOUS
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_alen = 0;
    mreq.mr_address[0] ='\0';
    ret = setsockopt(sock->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq));
    if (ret < 0) {
        perror("setsockopt");
        close(sock->fd);
        return FAILURE;
    }
#endif
    ret = get_haddr(sock, ifname);
    if (ret < 0) {
        close(sock->fd);
        return FAILURE;
    }
    ret = get_paddr(sock, ifname);
    if (ret < 0) {
        close(sock->fd);
        return FAILURE;
    }

    return SUCCESS;
}

int get_haddr(raw_socket_t *sock, const char *ifname) {
    struct ifreq ifr;
    int i;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(sock->fd, SIOCGIFHWADDR, &ifr);
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        if_haddr.addr[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];
    }
    return SUCCESS;
}

int get_paddr(raw_socket_t *sock, const char *ifname) {
    struct ifreq ifr;
    uint32_t addr;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(sock->fd, SIOCGIFADDR, &ifr);
    addr = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
    if_paddr.addr[3] = (unsigned char)((addr >> 24) & 0x000000ff);
    if_paddr.addr[2] = (unsigned char)((addr >> 16) & 0x000000ff);
    if_paddr.addr[1] = (unsigned char)((addr >>  8) & 0x000000ff);
    if_paddr.addr[0] = (unsigned char)((addr      ) & 0x000000ff);
    return SUCCESS;
}

int parse_eth_header(char *buf, size_t size, eth_header_t *header) {
    int i;
    unsigned short type;

    if (buf == NULL || header == NULL) {
        return FAILURE;
    }
    if (size < ETH_HEADER_SIZE) {
        return FAILURE;
    }
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        header->dst_mac.addr[i] = *buf;
        buf++;
    }
    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        header->src_mac.addr[i] = *buf;
        buf++;
    }
    type = *buf;
    buf++;
    type <<= 8;
    type |= *buf;
    buf++;
    header->type = type;
    header->payload_len = size - ETH_HEADER_SIZE;
    memcpy(header->payload, buf, header->payload_len);
    return SUCCESS;
}

int build_eth_header(eth_header_t *header, const char *dst_mac,
                     unsigned short type) {
    mac_addr_t dst;
    int ret;

    ret = str_to_mac(dst_mac, strlen(dst_mac)+1, &dst);
    if (ret < 0) {
        return ret;
    }
    header->dst_mac = dst;
    header->src_mac = if_haddr;
    header->type = type;
    return SUCCESS;
}
