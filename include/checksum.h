#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/**
 * Calculates the standard 16-bit one's complement Internet checksum.
 * Used for IPv4 headers and ICMP packets.
 */
uint16_t calculate_checksum(uint16_t *buffer, int size);

/**
 * Calculates the TCP checksum using IPv4 pseudo-header and TCP segment.
 */
uint16_t calculate_tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                 uint8_t *tcp_segment, int tcp_segment_len);

#endif /* CHECKSUM_H */
