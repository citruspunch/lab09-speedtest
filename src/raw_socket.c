#include "raw_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __APPLE__
/* ---------------------------------------------------------------------- */
/* macOS / Darwin / BSD implementation: Raw send socket + libpcap receive */
/* ---------------------------------------------------------------------- */

#include <pcap/pcap.h>

static pcap_t *g_pcap_handle = NULL;
static int g_pcap_link_offset = 0; /* bytes to skip before IP header */

int create_raw_socket(const char *capture_interface) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("[raw_socket] Error creating raw socket (sudo/root required)");
        return -1;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[raw_socket] Error setting IP_HDRINCL");
        close(sockfd);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = (capture_interface != NULL) ? capture_interface : "lo0";

    g_pcap_handle = pcap_open_live(iface, 65535, 0, 1, errbuf);
    if (g_pcap_handle == NULL) {
        fprintf(stderr, "[raw_socket] Error opening pcap on '%s': %s\n", iface, errbuf);
        close(sockfd);
        return -1;
    }

    if (pcap_setnonblock(g_pcap_handle, 1, errbuf) < 0) {
        fprintf(stderr, "[raw_socket] Warning: pcap_setnonblock failed: %s\n", errbuf);
    }

    struct bpf_program filter;
    if (pcap_compile(g_pcap_handle, &filter, "tcp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_pcap_handle, &filter);
        pcap_freecode(&filter);
    }

    switch (pcap_datalink(g_pcap_handle)) {
        case DLT_NULL:
        case 108: /* DLT_LOOP */
            g_pcap_link_offset = 4;
            break;
        case DLT_EN10MB:
            g_pcap_link_offset = 14;
            break;
        default:
            g_pcap_link_offset = 0;
            break;
    }

    return sockfd;
}

int receive_packet(int sockfd, uint8_t *buffer, size_t buffer_len, int timeout_ms) {
    (void)sockfd;

    if (g_pcap_handle == NULL) {
        return -1;
    }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        struct pcap_pkthdr *header;
        const u_char *data;
        int rc = pcap_next_ex(g_pcap_handle, &header, &data);

        if (rc == 1) {
            if ((int)header->caplen > g_pcap_link_offset) {
                int ip_len = (int)header->caplen - g_pcap_link_offset;
                if (ip_len > (int)buffer_len) ip_len = (int)buffer_len;
                memcpy(buffer, data + g_pcap_link_offset, ip_len);
                return ip_len;
            }
        } else if (rc < 0) {
            return -1;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                          (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= timeout_ms) {
            return -1;
        }
        usleep(500); /* 0.5 ms sleep to reduce CPU usage while preserving low latency */
    }
}

void close_raw_socket(int sockfd) {
    if (g_pcap_handle != NULL) {
        pcap_close(g_pcap_handle);
        g_pcap_handle = NULL;
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
}

#else
/* ---------------------------------------------------------------------- */
/* Linux implementation: Raw socket for sending and receiving             */
/* ---------------------------------------------------------------------- */

#include <sys/time.h>

int create_raw_socket(const char *capture_interface) {
    (void)capture_interface;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("[raw_socket] Error creating raw socket (root required)");
        return -1;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[raw_socket] Error setting IP_HDRINCL");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int receive_packet(int sockfd, uint8_t *buffer, size_t buffer_len, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    ssize_t received = recvfrom(sockfd, buffer, buffer_len, 0,
                                 (struct sockaddr *)&src, &src_len);
    if (received < 0) {
        return -1;
    }
    return (int)received;
}

void close_raw_socket(int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
    }
}

#endif /* __APPLE__ */

int send_packet(int sockfd, uint8_t *packet, size_t packet_len, const char *dst_ip) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dst_ip);

    ssize_t sent = sendto(sockfd, packet, packet_len, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("[raw_socket] Error in sendto");
        return -1;
    }
    return (int)sent;
}
