#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <stdint.h>

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;             /* Source port */
    uint16_t dst_port;             /* Destination port */
    uint32_t seq_num;              /* Sequence number */
    uint32_t ack_num;              /* Acknowledgment number */
    uint8_t  data_offset_reserved; /* Data offset (4 bits) + Reserved (4 bits) */
    uint8_t  flags;                /* Control flags (SYN, ACK, PSH, FIN, etc.) */
    uint16_t window;               /* Receive window size */
    uint16_t checksum;             /* Segment checksum */
    uint16_t urgent_ptr;           /* Urgent pointer */
} tcp_header_t;
#pragma pack(pop)

/**
 * Builds a standard 20-byte TCP header (without options).
 */
void build_tcp_header(tcp_header_t *tcph, uint16_t src_port, uint16_t dst_port,
                       uint32_t seq_num, uint32_t ack_num, uint8_t flags,
                       uint16_t window);

#endif /* TCP_HEADER_H */
