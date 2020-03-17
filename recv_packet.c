#include "recv_packet.h"

static int parse_mac_from_eth_header(struct ether_header *eth_header, char *src_mac,
        char *dst_mac) {
    int i = 0;
    u_char *ptr = NULL;

    i = ETHER_ADDR_LEN;
    ptr = eth_header->ether_shost;
    do {
        sprintf(src_mac, "%s%s%02x", src_mac, (i == ETHER_ADDR_LEN)?"":":",
                *ptr++);
    } while(--i>0);
    //sprintf(src_mac, "%s\0", src_mac);

    i = ETHER_ADDR_LEN;
    ptr = eth_header->ether_dhost;
    do {
        sprintf(dst_mac, "%s%s%02x", dst_mac, (i == ETHER_ADDR_LEN)?"":":",
                *ptr++);
    } while(--i>0);
    //sprintf(dst_mac, "%s\0", dst_mac);

    return 0;
}

static int parse_type_from_eth_header(struct ether_header *eth_header,
        char *ether_type, size_t max_len) {
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        strncpy(ether_type, "IP", max_len);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        strncpy(ether_type, "ARP", max_len);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        strncpy(ether_type, "Reverse ARP", max_len);
    } else {
        strncpy(ether_type, "Other", max_len);
    }
    return 0;
}

static void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
        const u_char *packet_body) {
    printf("\n...\n");
    struct ether_header *eth_header = NULL;
    char ether_type[16] = {0};
    char src_mac[32] = {0};
    char dst_mac[32] = {0};

    eth_header = (struct ether_header *) packet_body;
    parse_mac_from_eth_header(eth_header, src_mac, dst_mac);
    parse_type_from_eth_header(eth_header, ether_type, 16);

    printf("<type:%s> from MAC<%s> ==> MAC<%s>\n", ether_type, src_mac, dst_mac);
}

static int parse_ip(const u_char *ip_header, struct ipv4 *str_ipv4) {
    str_ipv4->ip_header = ip_header;
    str_ipv4->ip_header_length = ((*str_ipv4->ip_header) & 0x0F) * 4;
    str_ipv4->protocol = *(str_ipv4->ip_header + 9);
    str_ipv4->payload = str_ipv4->ip_header + str_ipv4->ip_header_length;
    return 0;
}

static int parse_tcp(const u_char *tcp_header, struct tcp *str_tcp) {
    str_tcp->tcp_header = tcp_header;
    str_tcp->tcp_header_length = (((*(str_tcp->tcp_header + 12)) & 0xF0) >> 4) * 4;
    str_tcp->payload = str_tcp->tcp_header + str_tcp->tcp_header_length;
    return 0;
}

static void filter_tcp_handler(u_char *args, const struct pcap_pkthdr *packet_header,
        const u_char *packet_body) {
    struct ether_header *eth_header = NULL;

    char ether_type[16] = {0};
    char src_mac[32] = {0};
    char dst_mac[32] = {0};

    struct ipv4 str_ipv4 = {0};
    struct tcp str_tcp = {0};

    eth_header = (struct ether_header *) packet_body;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        //printf("\n... Only Ip pass ...\n");
        ;
    }
    parse_mac_from_eth_header(eth_header, src_mac, dst_mac);

    parse_ip(packet_body+14, &str_ipv4);
    parse_tcp(str_ipv4.payload, &str_tcp);

    int len_payload = packet_header->caplen - 14 - str_ipv4.ip_header_length -
        str_tcp.tcp_header_length;

    printf("..ip from %s ==> %s, ip_header_length:%u, tcp_header_length:%u, "
           "with len of payload is %d\n",
           src_mac, dst_mac, str_ipv4.ip_header_length,
           str_tcp.tcp_header_length, len_payload);

    if (len_payload > 0) {
        u_char * pt = str_tcp.payload;
        int byte_count = 0;
        printf("    ");
        while (byte_count++ < len_payload) {
            printf("%c", *pt);
            pt++;
        }
        printf("\n");
    }
}

int get_info_of_dev(const char *device) {
    char ip[64];
    char subnet_mask[64];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    struct in_addr address; /* Used for both ip & subnet */

    /* Get device info */
    lookup_return_code = pcap_lookupnet(device, &ip_raw, &subnet_mask_raw,
                                        error_buffer);
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* If you call inet_ntoa() more than once
    you will overwrite the buffer. If we only stored
    the pointer to the string returned by inet_ntoa(),
    and then we call it again later for the subnet mask,
    our first pointer (ip address) will actually have
    the contents of the subnet mask. That is why we are
    using a string copy to grab the contents while it is fresh.
    The pointer returned by inet_ntoa() is always the same.

    This is from the man:
    The inet_ntoa() function converts the Internet host address in,
    given in network byte order, to a string in IPv4 dotted-decimal
    notation. The string is returned in a statically allocated
    buffer, which subsequent calls will overwrite. 
    */

    /* Get ip in human readable form */
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return 1;
    }

    /* Get subnet mask in human readable form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP address[%lu]: %s\n", strlen(ip), ip);
    printf("Subnet mask[%lu]: %s\n", strlen(subnet_mask), subnet_mask);

    return 0;
}

int print_ip_header(char *device) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    //const u_char *packet = NULL;
    //struct pcap_pkthdr packet_header;
    int packet_count_limit = 3;
    int timeout_limit = 10000;

    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit,
                            err_buf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, err_buf);
        return 2;
    }
    printf("BUFSIZ is %u\n", BUFSIZ);
    printf("Catch packet on dev:%s\n", device);

    u_char *args = (u_char *)"eouylei";
    pcap_loop(handle, 20, filter_tcp_handler, args);
    return 0;
}
