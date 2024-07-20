#ifndef __READ_CONFIG_H__
#define __READ_CONFIG_H__

typedef struct {
    char dst_ip[16];
    int src_port;
    int dst_port;
    char dst_mac[18];
    char interface[256];
} read_data_t;

int read_config(char *file_name, read_data_t *data);

#endif /* __READ_CONFIG_H__ */