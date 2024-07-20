#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "read_config.h"

#define MAX_LINE_LENGTH 256

int read_config(char *file_name, read_data_t *data) {
    FILE *fp;
    char str[MAX_LINE_LENGTH + 1];
    char *str_p;

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        return -1;
    }
    memset(data->dst_ip, 0, sizeof(data->dst_ip));

    while (fgets(str, MAX_LINE_LENGTH, fp) != NULL) {
        if (str[strlen(str) - 1] == '\n') {
            str[strlen(str) - 1] = '\0';
        } else {
            while (getc(fp) != '\n');
        }
        if (strncmp(str, "SRC_PORT", 8) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                data->src_port = strtol(str_p, NULL, 0);
            }
            //printf("SRC_PORT: %d\n", data->src_port);
        } else if (strncmp(str, "DST_IP", 6) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                strncpy(data->dst_ip, str_p, sizeof(data->dst_ip));
            }
            //printf("DST_IP: %s\n", data->dst_ip);
        } else if (strncmp(str, "DST_MAC", 7) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                strncpy(data->dst_mac, str_p, sizeof(data->dst_mac));
            }
            //printf("DST_MAC: %s\n", data->dst_mac);
        } else if (strncmp(str, "DST_PORT", 8) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                data->dst_port = strtol(str_p, NULL, 0);
            }
            //printf("DST_PORT: %d\n", data->dst_port);
        } else if (strncmp(str, "INTERFACE", 9) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                strncpy(data->interface, str_p, sizeof(data->interface));
            }
            //printf("INTERFACE: %s\n", data->interface);
        }
    }
    fclose(fp);
    return 0;
}
