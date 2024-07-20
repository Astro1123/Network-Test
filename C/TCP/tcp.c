#include <stdio.h>          // perror()
#include <string.h>         // memset()
#include <sys/types.h>      // socket(), bind(), inet_addr()
#include <sys/socket.h>     // socket(), bind(), inet_addr(), struct sockaddr, AF_INET
#include <netinet/in.h>     // inet_addr(), struct sockaddr_in
#include <arpa/inet.h>      // inet_addr(), htons()
#include <unistd.h>         // close()
#include <sys/select.h>     // select()
#include <time.h>               // time()

#include "tcp.h"

int blocking = 0;
int timeout_sec = 10;

int tcp_send(int sock, const char *buf, size_t len, int port, const char *ip) {
    int ret;
    struct sockaddr_in server;
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_port = htons(port);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    ret = send(sock, buf, len, 0);
    if (ret < 0) {
        perror("send");
        close(sock);
        return FAILURE;
    }
    return ret;
}

int tcp_recv(int sock, int port, char *buf, size_t size) {
    int ret;
    struct sockaddr_in addr, client;
    struct timeval timeout_sel;
    fd_set fds, readfds;
    time_t c_time, s_time;
    int csock;
    socklen_t len;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind");
        close(sock);
        return FAILURE;
    }

    ret = listen(sock, 10);
    if (ret < 0) {
        perror("listen");
        close(sock);
        return FAILURE;
    }

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    time(&s_time);

    while (1) {
        memcpy(&fds, &readfds, sizeof(fd_set));

        timeout_sel.tv_sec = 0;
        timeout_sel.tv_usec = 0;

        ret = select(sock + 1, &fds , NULL, NULL, &timeout_sel);
        if (ret < 0) {
            perror("select");
            return FAILURE;
        }

        if (FD_ISSET(sock, &fds)) {
            csock = accept(sock, (struct sockaddr *)&client, &len);
            if (csock < 0) {
                perror("accept");
                close(sock);
                return FAILURE;
            }
            memset(buf, 0, size);
            ret = recv(csock, buf, size, 0);
            if (ret < 0) {
                perror("recv");
                close(csock);
                close(sock);
                return FAILURE;
            }
            close(csock);
            break;
        }

        if (blocking != 0) {
            continue;
        }
        
        time(&c_time);
        if (c_time - s_time >= timeout_sec) {
            printf("Timeout.\n");
            return FAILURE;
        }
    }
    return ret;
}

int create_sock(void) {
    int sock;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return FAILURE;
    }
    return sock;
}

void set_blocking(int num) {
    blocking = num;
}

void set_timeout(int sec) {
    timeout_sec = sec;
}

int get_blocking(void) {
    return blocking;
}

int get_timeout(void) {
    return timeout_sec;
}
