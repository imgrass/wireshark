#include "recv_packet.h"

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
    const u_char *packet = NULL;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000;

    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit,
                            err_buf);
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    }
    printf("Catch packet on dev:%s\n", device);
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    return 0;
}
