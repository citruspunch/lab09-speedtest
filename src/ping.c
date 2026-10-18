#include "ping.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include "checksum.h"

#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    char     payload[32];
} icmp_echo_packet_t;
#pragma pack(pop)

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

static double ping_once_native(const char *target_ip, int seq, int timeout_ms) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sockfd < 0) {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (sockfd < 0) {
        return -1.0;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(target_ip);

    icmp_echo_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = ICMP_ECHO_REQUEST;
    pkt.code = 0;
    pkt.id = htons((uint16_t)(getpid() & 0xFFFF));
    pkt.sequence = htons((uint16_t)seq);
    snprintf(pkt.payload, sizeof(pkt.payload), "SPEEDTEST_LATENCY_%d", seq);
    pkt.checksum = calculate_checksum((uint16_t *)&pkt, sizeof(pkt));

    struct timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    ssize_t sent = sendto(sockfd, &pkt, sizeof(pkt), 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        close(sockfd);
        return -1.0;
    }

    uint8_t recv_buf[1024];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    ssize_t received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&src, &src_len);
    gettimeofday(&t_end, NULL);
    close(sockfd);

    if (received < 0) {
        return -1.0;
    }

    double rtt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
                    (t_end.tv_usec - t_start.tv_usec) / 1000.0;
    return rtt_ms;
}

static double ping_once_system(const char *target_ip) {
    char cmd[256];
#ifdef __APPLE__
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1000 %s 2>/dev/null", target_ip);
#else
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s 2>/dev/null", target_ip);
#endif

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1.0;

    char line[512];
    double rtt_ms = -1.0;
    while (fgets(line, sizeof(line), fp)) {
        char *time_str = strstr(line, "time=");
        if (time_str) {
            if (sscanf(time_str, "time=%lf", &rtt_ms) == 1) {
                break;
            }
        }
    }
    pclose(fp);
    return rtt_ms;
}

int measure_ping_latency(const char *target_ip, int count, int timeout_ms, ping_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->sent = count;
    result->min_ms = 999999.0;
    result->max_ms = 0.0;

    double samples[32];
    int valid_samples = 0;
    double sum = 0.0;

    for (int i = 0; i < count; i++) {
        double rtt = ping_once_native(target_ip, i + 1, timeout_ms);
        if (rtt < 0.0) {
            rtt = ping_once_system(target_ip);
        }

        if (rtt >= 0.0) {
            samples[valid_samples++] = rtt;
            sum += rtt;
            if (rtt < result->min_ms) result->min_ms = rtt;
            if (rtt > result->max_ms) result->max_ms = rtt;
        }

        if (i < count - 1) {
            usleep(50000); /* 50ms interval between pings */
        }
    }

    result->received = valid_samples;
    if (valid_samples > 0) {
        result->avg_ms = sum / valid_samples;
        result->success = 1;

        double var_sum = 0.0;
        for (int i = 0; i < valid_samples; i++) {
            double diff = samples[i] - result->avg_ms;
            var_sum += diff * diff;
        }
        result->mdev_ms = sqrt(var_sum / valid_samples);
        return 0;
    } else {
        result->min_ms = 0.0;
        result->avg_ms = 0.0;
        result->max_ms = 0.0;
        result->mdev_ms = 0.0;
        result->success = 0;
        return -1;
    }
}
