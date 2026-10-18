#ifndef SPEEDTEST_H
#define SPEEDTEST_H

#include <stdint.h>
#include <stddef.h>
#include "tcp_header.h"

#define MAX_PACKET_SIZE 4096
#define NUM_FILE_TRANSFERS 10
#define DEFAULT_FILE_PATH "assets/1kb-image"

typedef struct {
    int sockfd;
    char local_ip[64];
    char server_ip[64];
    uint16_t local_port;
    uint16_t server_port;
    uint32_t seq;
    uint32_t ack;
    const char *capture_iface;
} tcp_session_t;

typedef struct {
    /* Stage 1: ICMP Ping Latency */
    double ping_latency_ms;

    /* Stage 2: Initial Handshake RTT (SYN -> SYN-ACK) */
    double handshake_rtt_ms;

    /* Transfer measurements for all 10 iterations */
    int num_transfers;
    double transfer_rtts_ms[NUM_FILE_TRANSFERS];
    double avg_transfer_rtt_ms;
    double min_transfer_rtt_ms;
    double max_transfer_rtt_ms;

    /* Timing totals */
    double total_cycle_time_ms;   /* RTT_initial + avg_transfer_rtt */
    double total_elapsed_ms;      /* Total wall-clock time for the 10 transfers */

    /* Data transferred */
    size_t file_size_bytes;       /* Size of single transfer (typically 1024 bytes) */
    size_t total_bytes_sent;

    /* Speeds */
    double speed_formula_kbps;    /* (windowSize * 8) / (2 * avg_rtt_sec) */
    double speed_actual_kbps;     /* (10 * file_size * 8) / (total_elapsed_sec) */
} speedtest_results_t;

typedef struct {
    const char *local_ip;
    const char *server_ip;
    uint16_t server_port;
    const char *file_path;
    const char *interface;
    int ping_count;
    int verbose;
} speedtest_config_t;

int tcp_session_open(tcp_session_t *s, const char *local_ip, const char *server_ip,
                     uint16_t server_port, const char *capture_interface);

int tcp_session_handshake(tcp_session_t *s, int timeout_sec, double *out_handshake_rtt_ms);

int tcp_session_upload_files(tcp_session_t *s, const uint8_t *file_data, size_t file_len,
                             int num_transfers, speedtest_results_t *results, int timeout_sec);

void tcp_session_close(tcp_session_t *s, int timeout_sec);

void tcp_session_abort(tcp_session_t *s);

#endif /* SPEEDTEST_H */
