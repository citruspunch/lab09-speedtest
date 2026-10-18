#ifndef PING_H
#define PING_H

/**
 * Result of latency measurement (Stage 1).
 */
typedef struct {
    int sent;
    int received;
    double min_ms;
    double avg_ms;
    double max_ms;
    double mdev_ms;
    int success;
} ping_result_t;

/**
 * Measures ICMP ping latency in pure C to target_ip.
 * Sends 'count' ICMP echo requests and records round-trip timings.
 * Returns 0 on success (at least one reply), -1 on complete failure.
 */
int measure_ping_latency(const char *target_ip, int count, int timeout_ms, ping_result_t *result);

#endif /* PING_H */
