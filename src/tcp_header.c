#include "tcp_header.h"

#include <string.h>
#include <arpa/inet.h>

void build_tcp_header(tcp_header_t *tcph, uint16_t src_port, uint16_t dst_port,
                       uint32_t seq_num, uint32_t ack_num, uint8_t flags,
                       uint16_t window) {
    memset(tcph, 0, sizeof(tcp_header_t));

    tcph->src_port             = htons(src_port);
    tcph->dst_port             = htons(dst_port);
    tcph->seq_num              = htonl(seq_num);
    tcph->ack_num              = htonl(ack_num);
    tcph->data_offset_reserved = (5 << 4); /* 5 * 32-bit words = 20 bytes (no TCP options) */
    tcph->flags                = flags;
    tcph->window               = htons(window);
    tcph->checksum             = 0;         /* Calculated later with pseudo-header */
    tcph->urgent_ptr           = 0;
}
