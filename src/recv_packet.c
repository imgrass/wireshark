#include "recv_packet.h"


static int ether_addr_to_str(u_int8_t *ether_addr, char *str_mac_addr) {
    int i = 0;
    while (i<ETHER_ADDR_LEN) {
        sprintf(str_mac_addr, "%s%s%02x", str_mac_addr,
                (i==0)?"":":", *(ether_addr+i));
        i++;
    }
    return 0;
}


static int ipv4_addr_uchar_to_str(u_int32_t ipv4_addr, char *str_ipv4_addr) {
    int i = 4;
    do {
        sprintf(str_ipv4_addr, "%s%s%u", str_ipv4_addr,
                (i==4)?"":".", GET_BYTE_FROM_IPV4_BUFF(ipv4_addr, i));
    } while(--i>0);
    return 0;
}


static u_char *parse_ip(u_char *header_layer3) {
    char src_addr[LEN_STRING_IPV4_ADDR] = {0};
    char dst_addr[LEN_STRING_IPV4_ADDR] = {0};
    /* #define in <linux/ip.h> */
    struct iphdr *ipv4_header = (struct iphdr *)header_layer3;

    /* parse ip address.*/
    ipv4_addr_uchar_to_str(ntohl(ipv4_header->saddr), src_addr);
    ipv4_addr_uchar_to_str(ntohl(ipv4_header->daddr), dst_addr);
    printf("IPv4 %s ==> %s, ", src_addr, dst_addr);

    printf("<ihl:%u>, <total_length:%u>, <protocol:%u>, <ttl:%u>",
           (unsigned int)ipv4_header->ihl,
           (unsigned int)ntohs(ipv4_header->tot_len),
           (unsigned int)ipv4_header->protocol,
           (unsigned int)ipv4_header->ttl);
    return header_layer3+
        GET_ACTUAL_BYTES_OF_IPV4_HEADER_FROM_IHL(ipv4_header->ihl);
}


static void filter_http_handler(u_char *args, const struct pcap_pkthdr *packet_header,
        const u_char *packet_body) {
    int i = 0;
    char src_mac[LEN_STRING_MAC_ADDR] = {0};
    char dst_mac[LEN_STRING_MAC_ADDR] = {0};
    /* #define in <net/ethernet.h> */
    struct ether_header *eth_header = NULL;
    u_char *header_layer3 = NULL;
    u_char *header_layer4 = NULL;

    // only handle these Layer3 protocol.
    u_int16_t ether_type = 0;
    u_int16_t interesting_ether_type[] = {
        ETHERTYPE_IP,
        ETHERTYPE_IPV6,
        ETHERTYPE_VLAN
    };
    int len_interesting_ehter_type = sizeof(interesting_ether_type)/
        sizeof(u_int16_t);

    // only support these Layer4 protocol.
    
    eth_header = (struct ether_header *)packet_body;
    ether_type = ntohs(eth_header->ether_type);
    for (i=0; i<len_interesting_ehter_type; i++) {
        if (ether_type==interesting_ether_type[i]) {
            break;
        }
    }
    if (i==len_interesting_ehter_type) {
        return;
    }

    /* parse mac address from ether header */
    ether_addr_to_str(eth_header->ether_shost, src_mac);
    ether_addr_to_str(eth_header->ether_dhost, dst_mac);
    printf(".. MAC %s ==> %s\n", src_mac, dst_mac);

    header_layer3 = packet_body + sizeof(struct ether_header);
    switch (ether_type) {
        case ETHERTYPE_IP:
            printf("   ");
            header_layer4 = parse_ip(header_layer3);
            break;
        case ETHERTYPE_IPV6:
            break;
        case ETHERTYPE_VLAN:
            break;
    };
    printf("\n");

    /*

    int len_payload = packet_header->caplen - 14 - str_ipv4.ip_header_length -
        str_tcp.tcp_header_length;


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
    */
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
    pcap_loop(handle, 20, filter_http_handler, args);
    return 0;
}
