#include <stdio.h>          // printf()
#include <string.h>         // strlen(), strncpy(), memset()
#include <unistd.h>         // close()

#include "tcp.h"

int main(void) {
    int sock;
    int ret;
    char buf[BUF_SIZE];
    read_data_t data;

    read_config("config.conf", &data);

    sock = create_sock();
    if (sock < 0) {
        return FAILURE;
    }

    ret = tcp_recv(sock, data.recv_port, buf, sizeof(buf));
    if (ret < 0) {
        return FAILURE;
    }

/*
    memset(buf, 0, sizeof(buf));
    strncpy(buf, "Test", 4);
    ret = tcp_send(sock, buf, strlen(buf), data.send_port, data.send_ip);
    if (ret < 0) {
        return FAILURE;
    }
*/

    close(sock);
    return SUCCESS;
}
