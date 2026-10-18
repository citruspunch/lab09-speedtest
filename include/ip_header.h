#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;   /* Version (4 bits) + Internet Header Length (4 bits) */
    uint8_t  tos;           /* Type of Service / DSCP + ECN */
    uint16_t total_length;  /* Total length of IP packet */
    uint16_t id;            /* Identification */
    uint16_t flags_fo;      /* Flags (3 bits) + Fragment Offset (13 bits) */
    uint8_t  ttl;           /* Time to Live */
    uint8_t  protocol;      /* Upper layer protocol (IPPROTO_TCP = 6) */
    uint16_t checksum;      /* Header Checksum */
    uint32_t src_addr;      /* Source IP address (network byte order) */
    uint32_t dst_addr;      /* Destination IP address (network byte order) */
} ip_header_t;
#pragma pack(pop)

/**
 * Builds an IPv4 header.
 * Handles the BSD/Darwin vs Linux difference for total_length under IP_HDRINCL.
 */
void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                      uint16_t payload_len);

#endif /* IP_HEADER_H */
