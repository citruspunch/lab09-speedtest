#include "checksum.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_length;
} pseudo_header_t;
#pragma pack(pop)

uint16_t calculate_checksum(uint16_t *buffer, int size) {
    unsigned long sum = 0;

    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(uint8_t *)buffer;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t calculate_tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                 uint8_t *tcp_segment, int tcp_segment_len) {
    int total_len = (int)sizeof(pseudo_header_t) + tcp_segment_len;

    uint8_t *pseudo_packet = (uint8_t *)malloc(total_len);
    if (!pseudo_packet) {
        return 0;
    }

    pseudo_header_t *psh = (pseudo_header_t *)pseudo_packet;
    psh->src_addr    = src_addr;
    psh->dst_addr    = dst_addr;
    psh->zero        = 0;
    psh->protocol    = IPPROTO_TCP;
    psh->tcp_length  = htons((uint16_t)tcp_segment_len);

    memcpy(pseudo_packet + sizeof(pseudo_header_t), tcp_segment, tcp_segment_len);

    uint16_t result = calculate_checksum((uint16_t *)pseudo_packet, total_len);

    free(pseudo_packet);
    return result;
}
