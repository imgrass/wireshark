#ifndef __HEADER_RECV_PACKET__
#define __HEADER_RECV_PACKET__
#include "pcap.h"
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* Format: "aa:bb:cc:dd:ee:ff" */
#define LEN_STRING_MAC_ADDR (2 * 6 + 5 + 1)
/* Format: "255.255.255.255" */
#define LEN_STRING_IPV4_ADDR (3 * 4 + 3 + 1)
#define GET_BYTE_FROM_IPV4_BUFF(ipv4, n) \
    ((ipv4 & (0xFF << ((n - 1) * 8))) >> ((n - 1) * 8))
#define GET_ACTUAL_BYTES_OF_IPV4_HEADER_FROM_IHL(ihl) ((32 / 8) * ihl)


/*
struct packet_buff {
    u_char *lyr2_head;
    union { // ethernet
        // #define in <net/ethernet>
        struct ether_header ether;
    } layer2;

    u_char *lyr3_head;
    union { // ipv4, ipv6
        // #define in <linux/ip.h>
        struct iphdr ipv4;

        // #define in <linux/ipv6.h>
        struct ipv6hdr ipv6;
    } layer3;

    u_char *lyr4_head;
    union { // tcp, udp
        // #define in <linux/tcp.h>
        struct tcphdr tcp;

        // #define in <linux/udp.h>
        struct udphdr udp;
    } layer4;
};
*/


int get_info_of_dev(const char *device);
int print_ip_header(char *device);
#endif
