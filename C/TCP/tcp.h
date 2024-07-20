#ifndef __TCP_H__
#define __TCP_H__

#include "read_config.h"

/* Constants */
#define BUF_SIZE    1514

#define FAILURE     -1
#define SUCCESS      0

/* Functions */
int create_sock(void);
int tcp_send(int sock, const char *buf, size_t len, int port, const char *ip);
int tcp_recv(int sock, int port, char *buf, size_t size);

void set_blocking(int num);
void set_timeout(int sec);
int get_blocking(void);
int get_timeout(void);

#endif /* __TCP_H__ */