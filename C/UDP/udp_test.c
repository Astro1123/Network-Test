#include <stdio.h>          // printf()
#include <string.h>         // strlen(), strncpy(), memset()
#include <unistd.h>         // close()

#include "udp.h"

int main(void) {
    int sock;
    int ret;
    char buf[BUF_SIZE];
    read_data_t data;

    read_config("config.conf", &data);

    sock = create_sock(data.recv_port);
    if (sock < 0) {
        return FAILURE;
    }

    ret = udp_recv(sock, buf, sizeof(buf));
    if (ret < 0) {
        return FAILURE;
    }

/*
    memset(buf, 0, sizeof(buf));
    strncpy(buf, "Test", 4);
    ret = udp_send(sock, buf, strlen(buf), data.send_port, data.send_ip);
    if (ret < 0) {
        return FAILURE;
    }
*/

    close(sock);
    return SUCCESS;
}
