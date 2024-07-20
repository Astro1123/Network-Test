#ifndef __UDP_H__
#define __UDP_H__

#include "read_config.h"

/* Constants */
#define BUF_SIZE    1514

#define FAILURE     -1
#define SUCCESS      0

/* Functions */
int create_sock(int port);
int udp_send(int sock, const char *buf, size_t len, int port, const char *ip);
int udp_recv(int sock, char *buf, size_t size);

void set_blocking(int num);
void set_timeout(int sec);
int get_blocking(void);
int get_timeout(void);

#endif /* __UDP_H__ */