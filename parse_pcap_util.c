#include "parse_pcap_util.h"


int parse_ipv4_header(void *buf, unsigned int len_buf,
    struct ipv4_header *header) {
    if(len_buf < IPV4_HEADER_LENGTH) {
        printf("Exception: Length of pcap is less than the standard length \
                of IPv4 header (%d<%d)\n", len_buf, IPV4_HEADER_LENGTH);
        return -1;
    }
    return 0;
}
