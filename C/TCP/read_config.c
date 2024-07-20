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
    data->recv_port = -1;
    data->send_port = -1;
    memset(data->send_ip, 0, sizeof(data->send_ip));

    while (fgets(str, MAX_LINE_LENGTH, fp) != NULL) {
        if (str[strlen(str) - 1] == '\n') {
            str[strlen(str) - 1] = '\0';
        } else {
            while (getc(fp) != '\n');
        }
        if (strncmp(str, "SEND_PORT", 9) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                data->send_port = strtol(str_p, NULL, 10);
            }
            //printf("SEND_PORT: %d\n", data->send_port);
        } else if (strncmp(str, "SEND_IP", 7) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                strncpy(data->send_ip, str_p, sizeof(data->send_ip));
            }
            //printf("SEND_IP: %s\n", data->send_ip);
        } else if (strncmp(str, "RECV_PORT", 9) == 0) {
            str_p = strchr(str, '=');
            if (str_p != NULL) {
                str_p++;
                while (*str_p == ' ' || *str_p == '\t') {
                    str_p++;
                }
                data->recv_port = strtol(str_p, NULL, 10);
            }
            //printf("RECV_PORT: %d\n", data->recv_port);
        }
    }
    fclose(fp);
    return 0;
}
