#ifndef __HEADER_RECV_PACKET__
#define __HEADER_RECV_PACKET__
#include "pcap.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

struct ipv4 {
    u_char *ip_header;
    uint32_t ip_header_length;
    u_char protocol;
    u_char *payload;
};

struct tcp {
    u_char *tcp_header;
    uint32_t tcp_header_length;
    u_char *payload;
};

/* */
int get_info_of_dev(const char *device);
int print_ip_header(char *device);
#endif
