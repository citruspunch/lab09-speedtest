#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stddef.h>
#include <stdint.h>

/**
 * Creates and initializes raw socket mechanism.
 * On macOS: creates AF_INET SOCK_RAW socket for transmission and libpcap handle for reception.
 * On Linux: creates AF_INET SOCK_RAW socket with IP_HDRINCL for both sending and receiving.
 * Returns file descriptor >= 0 on success, -1 on error.
 */
int create_raw_socket(const char *capture_interface);

/**
 * Sends a raw packet (IPv4 header + payload) to dst_ip.
 * Returns bytes sent or -1 on error.
 */
int send_packet(int sockfd, uint8_t *packet, size_t packet_len, const char *dst_ip);

/**
 * Receives an IPv4 packet matching the socket/pcap stream within timeout_ms.
 * Buffer is populated with the IP packet (starting from IP header).
 * Returns length of received IP packet, or -1 on timeout/error.
 */
int receive_packet(int sockfd, uint8_t *buffer, size_t buffer_len, int timeout_ms);

/**
 * Cleans up socket descriptor and packet capture handles.
 */
void close_raw_socket(int sockfd);

#endif /* RAW_SOCKET_H */
