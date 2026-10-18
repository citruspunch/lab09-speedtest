#include "speedtest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ip_header.h"
#include "tcp_header.h"
#include "checksum.h"
#include "raw_socket.h"
#include "logger.h"
#include "ping.h"

static int build_packet(uint8_t *packet, const tcp_session_t *s, uint8_t flags,
                        const uint8_t *data, size_t data_len)
{
    ip_header_t *iph = (ip_header_t *)packet;
    tcp_header_t *tcph = (tcp_header_t *)(packet + sizeof(ip_header_t));
    uint8_t *payload = packet + sizeof(ip_header_t) + sizeof(tcp_header_t);

    if (data && data_len > 0) {
        memcpy(payload, data, data_len);
    }

    uint16_t tcp_len = (uint16_t)(sizeof(tcp_header_t) + data_len);

    build_tcp_header(tcph, s->local_port, s->server_port, s->seq, s->ack, flags, 65535);
    build_ip_header(iph, s->local_ip, s->server_ip, tcp_len);

    iph->checksum = calculate_checksum((uint16_t *)iph, sizeof(ip_header_t));
    tcph->checksum = calculate_tcp_checksum(iph->src_addr, iph->dst_addr, (uint8_t *)tcph, tcp_len);

    return (int)(sizeof(ip_header_t) + tcp_len);
}

static int wait_for_packet(tcp_session_t *s, uint8_t flags_mask, uint8_t flags_value,
                           tcp_header_t *out_tcph, uint8_t *out_payload,
                           int max_payload, int *out_payload_len, int timeout_ms)
{
    static uint8_t buffer[MAX_PACKET_SIZE];
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {
        int len = receive_packet(s->sockfd, buffer, sizeof(buffer), 50);
        if (len >= (int)(sizeof(ip_header_t) + sizeof(tcp_header_t))) {
            ip_header_t *iph = (ip_header_t *)buffer;
            if (iph->protocol == IPPROTO_TCP) {
                int ip_len = (iph->ihl_version & 0x0F) * 4;
                if (len >= ip_len + (int)sizeof(tcp_header_t)) {
                    tcp_header_t *tcph = (tcp_header_t *)(buffer + ip_len);
                    struct in_addr addr = {.s_addr = iph->src_addr};

                    if (strcmp(inet_ntoa(addr), s->server_ip) == 0 &&
                        ntohs(tcph->src_port) == s->server_port &&
                        ntohs(tcph->dst_port) == s->local_port)
                    {
                        if ((tcph->flags & flags_mask) == flags_value) {
                            if (out_tcph) {
                                memcpy(out_tcph, tcph, sizeof(*out_tcph));
                            }

                            int tcp_hdr_len = ((tcph->data_offset_reserved >> 4) & 0x0F) * 4;
                            int payload_offset = ip_len + tcp_hdr_len;
                            int payload_len = len - payload_offset;
                            if (payload_len < 0) payload_len = 0;

                            if (out_payload && max_payload > 0) {
                                int copy_len = (payload_len < max_payload) ? payload_len : max_payload;
                                memcpy(out_payload, buffer + payload_offset, copy_len);
                                if (out_payload_len) *out_payload_len = copy_len;
                            } else if (out_payload_len) {
                                *out_payload_len = payload_len;
                            }
                            return 0;
                        }
                    }
                }
            }
        }

        gettimeofday(&now, NULL);
        double elapsed_ms = (now.tv_sec - start.tv_sec) * 1000.0 +
                            (now.tv_usec - start.tv_usec) / 1000.0;
        if (elapsed_ms >= timeout_ms) {
            break;
        }
    }

    return -1;
}

static int send_control(tcp_session_t *s, uint8_t flags) {
    uint8_t packet[MAX_PACKET_SIZE];
    int len = build_packet(packet, s, flags, NULL, 0);
    return send_packet(s->sockfd, packet, len, s->server_ip);
}

int tcp_session_open(tcp_session_t *s, const char *local_ip, const char *server_ip,
                     uint16_t server_port, const char *capture_interface)
{
    memset(s, 0, sizeof(*s));
    strncpy(s->local_ip, local_ip, sizeof(s->local_ip) - 1);
    strncpy(s->server_ip, server_ip, sizeof(s->server_ip) - 1);
    s->server_port = server_port;
    s->capture_iface = capture_interface;

    /* Ephemeral port in range 40000 - 49999 */
    s->local_port = (uint16_t)(40000 + (rand() % 10000));
    s->seq = (uint32_t)rand();

    LOG_INFO("Endpoint configuration: Client %s:%u -> Server %s:%u",
             s->local_ip, s->local_port, s->server_ip, s->server_port);

    s->sockfd = create_raw_socket(capture_interface);
    if (s->sockfd < 0) {
        LOG_ERROR("Failed to create RAW socket (sudo/root required)");
        return -1;
    }

    return 0;
}

int tcp_session_handshake(tcp_session_t *s, int timeout_sec, double *out_handshake_rtt_ms)
{
    uint8_t packet[MAX_PACKET_SIZE];
    tcp_header_t recv_tcph;
    int recv_payload_len = 0;

    logger_section("STAGE 2: TCP 3-WAY HANDSHAKE (RAW SOCKET)");

    uint32_t syn_seq = s->seq;
    int len = build_packet(packet, s, TCP_SYN, NULL, 0);

    struct timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    if (send_packet(s->sockfd, packet, len, s->server_ip) < 0) {
        LOG_ERROR("sendto failed for SYN");
        return -1;
    }
    logger_segment(1, TCP_SYN, syn_seq, 0, NULL, 0, 0);

    /* Wait for SYN+ACK */
    if (wait_for_packet(s, TCP_SYN | TCP_ACK, TCP_SYN | TCP_ACK,
                        &recv_tcph, NULL, 0, &recv_payload_len, timeout_sec * 1000) != 0)
    {
        LOG_ERROR("SYN+ACK timeout from %s:%u", s->server_ip, s->server_port);
        return -1;
    }

    gettimeofday(&t_end, NULL);
    double rtt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
                    (t_end.tv_usec - t_start.tv_usec) / 1000.0;
    if (out_handshake_rtt_ms) *out_handshake_rtt_ms = rtt_ms;

    uint32_t server_seq = ntohl(recv_tcph.seq_num);
    uint32_t server_ack = ntohl(recv_tcph.ack_num);
    logger_segment(0, recv_tcph.flags, server_seq, server_ack, NULL, 0, 1);

    LOG_INFO("Initial Handshake RTT: %.3f ms (SYN -> SYN+ACK)", rtt_ms);

    /* Advance client sequence number and record server sequence + 1 */
    s->seq++;
    s->ack = server_seq + 1;

    uint32_t ack_seq = s->seq;
    uint32_t ack_ack = s->ack;
    if (send_control(s, TCP_ACK) < 0) {
        LOG_ERROR("sendto failed for handshake ACK");
        return -1;
    }
    logger_segment(1, TCP_ACK, ack_seq, ack_ack, NULL, 0, 1);

    LOG_INFO("TCP Connection established successfully");
    return 0;
}

int tcp_session_upload_files(tcp_session_t *s, const uint8_t *file_data, size_t file_len,
                             int num_transfers, speedtest_results_t *results, int timeout_sec)
{
    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t resp_buf[256];
    tcp_header_t recv_tcph;
    int resp_len = 0;

    logger_section("STAGE 2: 10x 1KB FILE TRANSMISSION OVER RAW TCP");
    LOG_INFO("Transmitting 1 KB payload %d times over the established connection...", num_transfers);

    results->num_transfers = num_transfers;
    results->file_size_bytes = file_len;
    results->total_bytes_sent = 0;
    results->min_transfer_rtt_ms = 999999.0;
    results->max_transfer_rtt_ms = 0.0;
    double rtt_sum = 0.0;

    struct timeval wall_start, wall_end;
    gettimeofday(&wall_start, NULL);

    for (int i = 0; i < num_transfers; i++) {
        uint32_t data_seq = s->seq;
        uint32_t data_ack = s->ack;

        int packet_len = build_packet(packet, s, TCP_PSH | TCP_ACK, file_data, file_len);

        struct timeval t_tx, t_rx;
        gettimeofday(&t_tx, NULL);

        if (send_packet(s->sockfd, packet, packet_len, s->server_ip) < 0) {
            LOG_ERROR("Failed to send file transfer #%d", i + 1);
            return -1;
        }
        logger_segment(1, TCP_PSH | TCP_ACK, data_seq, data_ack, file_data, file_len, 1);

        /* Advance sequence number by bytes sent */
        s->seq += (uint32_t)file_len;
        results->total_bytes_sent += file_len;

        /* Wait for server ACK or server ACK + response */
        resp_len = 0;
        int rc = wait_for_packet(s, TCP_ACK, TCP_ACK, &recv_tcph,
                                 resp_buf, sizeof(resp_buf) - 1, &resp_len, timeout_sec * 1000);
        gettimeofday(&t_rx, NULL);

        if (rc != 0) {
            LOG_ERROR("Timeout waiting for ACK on transfer #%d", i + 1);
            return -1;
        }

        double transfer_rtt = (t_rx.tv_sec - t_tx.tv_sec) * 1000.0 +
                              (t_rx.tv_usec - t_tx.tv_usec) / 1000.0;
        results->transfer_rtts_ms[i] = transfer_rtt;
        rtt_sum += transfer_rtt;
        if (transfer_rtt < results->min_transfer_rtt_ms) results->min_transfer_rtt_ms = transfer_rtt;
        if (transfer_rtt > results->max_transfer_rtt_ms) results->max_transfer_rtt_ms = transfer_rtt;

        uint32_t srv_seq = ntohl(recv_tcph.seq_num);
        uint32_t srv_ack = ntohl(recv_tcph.ack_num);

        logger_segment(0, recv_tcph.flags, srv_seq, srv_ack,
                       (resp_len > 0) ? resp_buf : NULL, resp_len, 1);

        LOG_INFO("-> File Transfer %2d/%d: RTT = %7.3f ms | SEQ=%u ACK=%u",
                 i + 1, num_transfers, transfer_rtt, data_seq, srv_ack);

        /* If server returned payload, update ack and send ACK back */
        if (resp_len > 0) {
            s->ack += (uint32_t)resp_len;
            send_control(s, TCP_ACK);
            logger_segment(1, TCP_ACK, s->seq, s->ack, NULL, 0, 1);
        }

        /* Brief inter-packet pause to prevent packet coalescence on loopback */
        usleep(10000); /* 10 ms */
    }

    gettimeofday(&wall_end, NULL);
    results->total_elapsed_ms = (wall_end.tv_sec - wall_start.tv_sec) * 1000.0 +
                                (wall_end.tv_usec - wall_start.tv_usec) / 1000.0;
    results->avg_transfer_rtt_ms = rtt_sum / num_transfers;

    return 0;
}

void tcp_session_close(tcp_session_t *s, int timeout_sec)
{
    tcp_header_t recv_tcph;
    uint8_t payload[256];
    int payload_len = 0;

    logger_section("TCP CONNECTION TEARDOWN");

    uint32_t fin_seq = s->seq;
    uint32_t fin_ack = s->ack;
    send_control(s, TCP_FIN | TCP_ACK);
    logger_segment(1, TCP_FIN | TCP_ACK, fin_seq, fin_ack, NULL, 0, 1);
    s->seq++;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    int got_fin = 0;

    while (1) {
        payload_len = 0;
        if (wait_for_packet(s, TCP_ACK, TCP_ACK, &recv_tcph, payload, sizeof(payload) - 1, &payload_len, 1000) == 0) {
            uint32_t s_seq = ntohl(recv_tcph.seq_num);
            uint32_t s_ack = ntohl(recv_tcph.ack_num);
            logger_segment(0, recv_tcph.flags, s_seq, s_ack, (payload_len > 0) ? payload : NULL, payload_len, 1);

            if (payload_len > 0) {
                s->ack = s_seq + (uint32_t)payload_len;
            }
            if (recv_tcph.flags & TCP_FIN) {
                s->ack = s_seq + ((payload_len > 0) ? (uint32_t)payload_len : 0) + 1;
                send_control(s, TCP_ACK);
                logger_segment(1, TCP_ACK, s->seq, s->ack, NULL, 0, 1);
                got_fin = 1;
                break;
            }
        }

        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000000.0;
        if (elapsed >= timeout_sec) break;
    }

    if (!got_fin) {
        LOG_WARN("Timeout waiting for server FIN");
    }

    usleep(15000); /* 15 ms to allow final ACK to flush onto wire */
    close_raw_socket(s->sockfd);
    s->sockfd = -1;
    logger_section("CONNECTION CLOSED");
}

void tcp_session_abort(tcp_session_t *s) {
    if (s->sockfd >= 0) {
        close_raw_socket(s->sockfd);
        s->sockfd = -1;
    }
}

static uint8_t *load_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, sz, f);
    fclose(f);

    if (read_bytes != (size_t)sz) {
        free(buf);
        return NULL;
    }

    *out_size = read_bytes;
    return buf;
}

static void print_results(const speedtest_results_t *r) {
    int c = logger_use_color();
    const char *b_cyan   = c ? ANSI_BOLD_CYAN    : "";
    const char *b_yellow = c ? ANSI_BOLD_YELLOW  : "";
    const char *b_green  = c ? ANSI_BOLD_GREEN   : "";
    const char *b_mag    = c ? ANSI_BOLD_MAGENTA : "";
    const char *b_blue   = c ? ANSI_BOLD_BLUE    : "";
    const char *b_white  = c ? ANSI_BOLD_WHITE   : "";
    const char *dim      = c ? ANSI_DIM          : "";
    const char *reset    = c ? ANSI_RESET        : "";

    printf("\n");
    printf("%s======================================================================%s\n", b_cyan, reset);
    printf("%s                    SPEEDTEST PERFORMANCE SUMMARY                     %s\n", b_cyan, reset);
    printf("%s======================================================================%s\n", b_cyan, reset);
    printf(" %s[STAGE 1] Latency Measurement (ICMP Ping)%s\n", b_yellow, reset);
    printf("   * Measured Ping Latency:             %s%8.3f ms%s\n", b_white, r->ping_latency_ms, reset);
    printf("%s----------------------------------------------------------------------%s\n", dim, reset);
    printf(" %s[STAGE 2] TCP RAW Connection & Transmission%s\n", b_yellow, reset);
    printf("   * Initial TCP Handshake RTT:         %s%8.3f ms%s  %s(SYN -> SYN+ACK)%s\n",
           b_white, r->handshake_rtt_ms, reset, dim, reset);
    printf("   * Payload per Transfer:              %s%8zu bytes%s %s(1 KB)%s\n",
           b_white, r->file_size_bytes, reset, dim, reset);
    printf("   * Transfers Completed:               %s%8d transfers%s\n",
           b_white, r->num_transfers, reset);
    printf("   * Total Bytes Transmitted:           %s%8zu bytes%s\n",
           b_white, r->total_bytes_sent, reset);
    printf("   * Transfer RTT (Min):                %s%8.3f ms%s\n", b_white, r->min_transfer_rtt_ms, reset);
    printf("   * Transfer RTT (Average):            %s%8.3f ms%s\n", b_white, r->avg_transfer_rtt_ms, reset);
    printf("   * Transfer RTT (Max):                %s%8.3f ms%s\n", b_white, r->max_transfer_rtt_ms, reset);
    printf("   * Total Wall-Clock Elapsed Time:     %s%8.3f ms%s\n", b_white, r->total_elapsed_ms, reset);
    printf("%s----------------------------------------------------------------------%s\n", dim, reset);
    printf(" %s[STAGE 3] Speed Calculations & Throughput Variants%s\n", b_yellow, reset);
    printf("   * Formula: Total Time = RTT + (RTT + transmit time)\n");
    printf("     Total Cycle Time:                  %s%8.3f ms%s  %s(Initial RTT + Avg Transfer RTT)%s\n",
           b_white, r->total_cycle_time_ms, reset, dim, reset);
    printf("     Assumed Cycle (2 * Avg RTT):       %s%8.3f ms%s\n",
           b_white, 2.0 * r->avg_transfer_rtt_ms, reset);
    printf("\n");

    /* Lab prompt formula: Speed = windowSize / ~RTT */
    double rtt_sec = r->avg_transfer_rtt_ms / 1000.0;
    double speed_2rtt_1000_kbps = (1000.0 * 8.0) / (2.0 * rtt_sec * 1000.0);
    double speed_2rtt_1024_kbps = (1024.0 * 8.0) / (2.0 * rtt_sec * 1000.0);
    double speed_1rtt_1000_kbps = (1000.0 * 8.0) / (1.0 * rtt_sec * 1000.0);
    double speed_1rtt_1024_kbps = (1024.0 * 8.0) / (1.0 * rtt_sec * 1000.0);

    printf(" %s[VARIANTE A] Modelo con Costo de Conexion por Envio (2 x RTT):%s\n", b_mag, reset);
    printf("   * Supuesto: Cada envio asume RTT_handshake + (RTT + T_trans) ~= 2 * RTT\n");
    printf("     - Con 1000 Bytes: (1000 * 8) / (2 * %.6f s) = %s%10.2f kbps (%6.2f Mbps)%s\n",
           rtt_sec, b_green, speed_2rtt_1000_kbps, speed_2rtt_1000_kbps / 1000.0, reset);
    printf("     - Con 1024 Bytes: (1024 * 8) / (2 * %.6f s) = %s%10.2f kbps (%6.2f Mbps)%s\n",
           rtt_sec, b_green, speed_2rtt_1024_kbps, speed_2rtt_1024_kbps / 1000.0, reset);
    printf("\n");

    printf(" %s[VARIANTE B] Conexion Persistente / Misma Conexion TCP (Modelo 1 x RTT):%s\n", b_cyan, reset);
    printf("   * Supuesto: Handshake unico inicial; cada envio es RTT + T_trans ~= 1 * RTT (T_trans ~= 0)\n");
    printf("     - Con 1000 Bytes: (1000 * 8) / (1 * %.6f s) = %s%10.2f kbps (%6.2f Mbps)%s\n",
           rtt_sec, b_green, speed_1rtt_1000_kbps, speed_1rtt_1000_kbps / 1000.0, reset);
    printf("     - Con 1024 Bytes: (1024 * 8) / (1 * %.6f s) = %s%10.2f kbps (%6.2f Mbps)%s\n",
           rtt_sec, b_green, speed_1rtt_1024_kbps, speed_1rtt_1024_kbps / 1000.0, reset);
    printf("\n");

    printf(" %s[VARIANTE C] Rendimiento Efectivo Empirico (Throughput Real Wall-Clock):%s\n", b_blue, reset);
    printf("   * Supuesto: Medicion real del tiempo total transcurrido para los 10 archivos\n");
    printf("     - Throughput:     (%zu * 8) / (%.6f s) = %s%10.2f kbps (%6.2f Mbps)%s\n",
           r->total_bytes_sent, r->total_elapsed_ms / 1000.0,
           b_green, r->speed_actual_kbps, r->speed_actual_kbps / 1000.0, reset);
    printf("%s======================================================================%s\n\n", b_cyan, reset);
}

static void print_usage(const char *prog) {
    printf("\nUsage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -s, --server IP        Target Server IP (default: 127.0.0.1)\n");
    printf("  -l, --local IP         Local IP (default: 127.0.0.1)\n");
    printf("  -p, --port PORT        Target Server TCP Port (default: 5001)\n");
    printf("  -f, --file PATH        Path to 1KB file to transmit (default: %s)\n", DEFAULT_FILE_PATH);
    printf("  -i, --interface IFACE  Capture interface (macOS: lo0, en0 | Linux: lo, eth0)\n");
    printf("  -c, --count N          Ping probe count for Stage 1 (default: 4)\n");
    printf("  -h, --help             Show this help message\n\n");
}

int main(int argc, char **argv) {
    speedtest_config_t cfg = {
        .local_ip = "127.0.0.1",
        .server_ip = "127.0.0.1",
        .server_port = 5001,
        .file_path = DEFAULT_FILE_PATH,
        .interface = NULL,
        .ping_count = 4,
        .verbose = 1,
    };

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--server")) {
            if (++i < argc) cfg.server_ip = argv[i];
        } else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--local")) {
            if (++i < argc) cfg.local_ip = argv[i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (++i < argc) cfg.server_port = (uint16_t)atoi(argv[i]);
        } else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
            if (++i < argc) cfg.file_path = argv[i];
        } else if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface")) {
            if (++i < argc) cfg.interface = argv[i];
        } else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--count")) {
            if (++i < argc) cfg.ping_count = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    srand((unsigned)time(NULL));
    logger_init(NULL, LOG_LEVEL_INFO);
    logger_banner("SPEEDTEST: RAW SOCKETS TCP BENCHMARK", "3 Stages: Latency, RAW TCP Handshake, 10x 1KB File Upload");

    /* ================================================================== */
    /* STAGE 1: Latency Measurement via Ping (Pure C)                     */
    /* ================================================================== */
    logger_section("STAGE 1: LATENCY MEASUREMENT (ICMP PING)");
    LOG_INFO("Pinging target %s (%d probes)...", cfg.server_ip, cfg.ping_count);

    ping_result_t ping_res;
    double ping_latency_ms = 0.0;
    if (measure_ping_latency(cfg.server_ip, cfg.ping_count, 1000, &ping_res) == 0) {
        ping_latency_ms = ping_res.avg_ms;
        LOG_INFO("Ping Success: Sent=%d, Received=%d, Min=%.3f ms, Avg=%.3f ms, Max=%.3f ms",
                 ping_res.sent, ping_res.received, ping_res.min_ms, ping_res.avg_ms, ping_res.max_ms);
    } else {
        LOG_WARN("ICMP Ping to %s timed out or was unreachable; using baseline estimate.", cfg.server_ip);
        ping_latency_ms = 0.5; /* fallback baseline */
    }

    /* Load 1 KB file */
    size_t file_len = 0;
    uint8_t *file_data = load_file(cfg.file_path, &file_len);
    if (!file_data) {
        LOG_ERROR("Failed to load 1 KB payload from '%s'", cfg.file_path);
        logger_close();
        return 1;
    }
    LOG_INFO("Loaded payload: %zu bytes from '%s'", file_len, cfg.file_path);

    /* ================================================================== */
    /* STAGE 2: TCP RAW Handshake and 10x 1KB File Upload                 */
    /* ================================================================== */
    tcp_session_t session;
    if (tcp_session_open(&session, cfg.local_ip, cfg.server_ip, cfg.server_port, cfg.interface) != 0) {
        free(file_data);
        logger_close();
        return 1;
    }

    double handshake_rtt_ms = 0.0;
    if (tcp_session_handshake(&session, 5, &handshake_rtt_ms) != 0) {
        LOG_ERROR("Handshake failed. Ensure speedtest_server is running on %s:%u",
                  cfg.server_ip, cfg.server_port);
        tcp_session_abort(&session);
        free(file_data);
        logger_close();
        return 1;
    }

    speedtest_results_t results;
    memset(&results, 0, sizeof(results));
    results.ping_latency_ms = ping_latency_ms;
    results.handshake_rtt_ms = handshake_rtt_ms;

    if (tcp_session_upload_files(&session, file_data, file_len, NUM_FILE_TRANSFERS, &results, 5) != 0) {
        LOG_ERROR("File upload failed");
        tcp_session_abort(&session);
        free(file_data);
        logger_close();
        return 1;
    }

    tcp_session_close(&session, 3);
    free(file_data);

    /* ================================================================== */
    /* STAGE 3: Performance & Speed Calculations                          */
    /* ================================================================== */
    results.total_cycle_time_ms = results.handshake_rtt_ms + results.avg_transfer_rtt_ms;

    double avg_rtt_sec = results.avg_transfer_rtt_ms / 1000.0;
    if (avg_rtt_sec > 0.0) {
        results.speed_formula_2rtt_kbps = (1000.0 * 8.0) / (2.0 * avg_rtt_sec * 1000.0);
        results.speed_formula_1rtt_kbps = (1000.0 * 8.0) / (1.0 * avg_rtt_sec * 1000.0);
    }

    double elapsed_sec = results.total_elapsed_ms / 1000.0;
    if (elapsed_sec > 0.0) {
        results.speed_actual_kbps = ((double)results.total_bytes_sent * 8.0) / (elapsed_sec * 1000.0);
    }

    print_results(&results);

    logger_close();
    return 0;
}
