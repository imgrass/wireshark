#ifndef __HEADER_PARSE_PCAP_UTIL__
#define __HEADER_PARSE_PCAP_UTIL__

typedef unsigned int offset_bit

struct ipv4 {
    char buf[32];

    void *version;
    offset_bit n_version
};

#endif
