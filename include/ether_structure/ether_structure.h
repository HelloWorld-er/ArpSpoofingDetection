//
// Created by Yimin Liu on 12/4/2025.
//



#ifndef ARP_PARSING_SUPPORT_H
#define ARP_PARSING_SUPPORT_H

#ifndef _LIBCPP_CSTDINT
#include <cstdint>
#endif

#endif //ARP_PARSING_SUPPORT_H

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#define ARPHRD_ETHER    1
#define ARPHRD_IEEE802  6
#define ARPHRD_FRELAY   15
#define ARPHRD_IEEE1394 24
#define ARPHRD_IEEE1394_EUI64 27

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define RARPOP_REQUEST 3
#define RARPOP_REPLY  4
#define INARPOP_REQUEST 8
#define INARPOP_REPLY  9

#define ETHER_ADDR_LEN 6

typedef struct ethernet_header {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
} ethernet_header_t;

typedef struct ether_arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t opcode;
    uint8_t sender_mac[ETHER_ADDR_LEN];
    uint8_t sender_ip[4];
    uint8_t target_mac[ETHER_ADDR_LEN];
    uint8_t target_ip[4];
} arp_header_t;
