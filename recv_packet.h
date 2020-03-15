#ifndef __HEADER_RECV_PACKET__
#define __HEADER_RECV_PACKET__
#include "pcap.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


/* */
int get_info_of_dev(const char *device);
int print_ip_header(char *device);
#endif
