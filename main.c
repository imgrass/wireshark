//#include "./libpcap/include/pcap.h"
#include "pcap.h"
#include "recv_packet.h"
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char **argv) {
    char *device = NULL;
    unsigned int len = 0;

    if(argc != 2) {
        printf("need a device name\n");
        exit(1);
    }

    len = strlen(argv[1]) + 1;
    device = (char *)calloc(1, len);
    strncpy(device, argv[1], len);

    printf("==Show info of device: %s\n", device);
    get_info_of_dev(device);
    print_ip_header(device);
    return 0;
}
