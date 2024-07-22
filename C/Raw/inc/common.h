#ifndef __COMMON_H__
#define __COMMON_H__

#include <signal.h>

/* Constants */
#define ERR_TIMEOUT -2
#define FAILURE     -1
#define SUCCESS      0

#define COMP_TRUE    1
#define COMP_FALSE   0

#define BUF_SIZE    1514

#define MAC_ADDR_SIZE 6
#define IPV4_ADDR_SIZE 4

#define CONFIG_FILE "conf/config.conf"

/* Structs */
typedef struct {
    unsigned char addr[MAC_ADDR_SIZE];
} mac_addr_t;

typedef struct {
    unsigned char addr[IPV4_ADDR_SIZE];
} ipv4_addr_t;

extern mac_addr_t  if_haddr;
extern ipv4_addr_t if_paddr;
extern struct sigaction sa;
extern volatile int timeout_flag;
extern int timeout_sec;
extern int blocking;
extern int timer_set_flag;

/* Functions */
int str_to_mac(const char *str, size_t size, mac_addr_t *mac);
int str_to_ip(const char *str, size_t size, ipv4_addr_t *ip);
int comp_ip(ipv4_addr_t ip_1, const char *ip_2);
int comp_mac(mac_addr_t mac_1, const char *mac_2);
int comp_mac_mac(mac_addr_t mac_1, mac_addr_t mac_2);
int comp_ip_ip(ipv4_addr_t ip_1, ipv4_addr_t ip_2);

void set_timer(void);
void reset_timer(void);
void signal_handler(int signum);

void set_blocking(int num);
void set_timeout(int sec);
int get_blocking(void);
int get_timeout(void);

#endif /* __COMMON_H__ */