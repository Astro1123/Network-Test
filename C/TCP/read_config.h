#ifndef __READ_CONFIG_H__
#define __READ_CONFIG_H__

typedef struct {
    int recv_port;
    int send_port;
    char send_ip[16];
} read_data_t;

int read_config(char *file_name, read_data_t *data);

#endif /* __READ_CONFIG_H__ */