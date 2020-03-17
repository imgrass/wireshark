#ifndef __HEADER_PARSE_PCAP_UTIL__
#define __HEADER_PARSE_PCAP_UTIL__
/**
 * Refer to RFC791
 *      [https://tools.ietf.org/html/rfc791#section-3.1]

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>

#define IPV4_HEADER_LENGTH 32   // bytes
#define IPV4_OFFSET_VERSION 4   // bits
#define IPV4_OFFSET_IHL 4
#define IPV4_OFFSET_TYPE_OF_SERVICE 8
#define IPV4_OFFSET_TOTAL_LENGTH 16
#define IPV4_OFFSET_IDENTIFICATION 16
#define IPV4_OFFSET_FLAGS 3
#define IPV4_OFFSET_FRAGMENT_OFFSET 13
#define IPV4_OFFSET_TIME_TO_LIVE 8
#define IPV4_OFFSET_PROTOCOL 8
#define IPV4_OFFSET_HEADER_CHECKSUM 16
#define IPV4_OFFSET_SOURCE_ADDRESS 32
#define IPV4_OFFSET_DESTINATION_ADDRESS 32
#define IPV4_OFFSET_OPTIONS     //"variable"
#define IPV4_OFFSET_PADDING     //"variable"

struct ipv4_header {
    uint8_t version;
    // void ihl;
    // void *type_of_service;
    uint16_t total_length;
    // void *identification;
    // void *flags;
    // void *fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    // void *header_checksum;
    in_addr_t source_address;
    in_addr_t destination_address;
    // void *options;
    // void *padding;
};

int parse_ipv4_header(void *buf, unsigned int len_buf,
    struct ipv4_header *header);
#endif
